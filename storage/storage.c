/* octopos storage code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#ifndef ARCH_SEC_HW_STORAGE
#include <semaphore.h>
#include <tpm/tpm.h>
#else
#include "arch/sec_hw.h"
#include "arch/semaphore.h"
#endif
#include <tpm/hash.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/io.h>
#include <octopos/error.h>

#include "arch/mailbox_storage.h"
#include "arch/syscall.h"

#define STORAGE_KEY_SIZE	TPM_EXTEND_HASH_SIZE  /* bytes */

/* Need to make sure msgs are big enough so that we don't overflow
 * when processing incoming msgs and preparing outgoing ones.
 */
/* FIXME: find the smallest bound. 64 is conservative. */
#if MAILBOX_QUEUE_MSG_SIZE < 64
#error MAILBOX_QUEUE_MSG_SIZE is too small
#endif

#if MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE
#error data queue msg size must be equal to storage block size
#endif

#if STORAGE_KEY_SIZE != TPM_EXTEND_HASH_SIZE
#error storage key size must be equal to the TPM extend hash size
#endif


#ifndef ARCH_SEC_HW_STORAGE
#define fop_open fopen
#define fop_close fclose
#define fop_seek fseek
#define fop_read fread
#define fop_write fwrite
#endif /* ARCH_SEC_HW_STORAGE */

#define STORAGE_SET_ONE_RET(ret0)		\
	SERIALIZE_32(ret0, &buf[0])

#define STORAGE_SET_TWO_RETS(ret0, ret1)	\
	SERIALIZE_32(ret0, &buf[0])		\
	SERIALIZE_32(ret1, &buf[4])

/* FIXME: when calling this one, we need to allocate a ret_buf. Can we avoid that? */
#define STORAGE_SET_ONE_RET_DATA(ret0, data, size)		\
	*((uint32_t *) &buf[0]) = ret0;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 5;		\
	if (max_size < 256 && size <= ((int) max_size)) {	\
		buf[4] = (uint8_t) size;			\
		memcpy(&buf[5], data, size);			\
	} else {						\
		printf("Error: invalid max_size or size\n");	\
		buf[4] = 0;					\
	}

#define STORAGE_GET_ONE_ARG		\
	uint32_t arg0;			\
	arg0 = *((uint32_t *) &buf[1]); \

#define STORAGE_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	arg0 = *((uint32_t *) &buf[1]); \
	arg1 = *((uint32_t *) &buf[5]); \

#define STORAGE_GET_THREE_ARGS		\
	uint32_t arg0, arg1, arg2;	\
	arg0 = *((uint32_t *) &buf[1]); \
	arg1 = *((uint32_t *) &buf[5]); \
	arg2 = *((uint32_t *) &buf[9]);\

#define STORAGE_GET_ZERO_ARGS_DATA				\
	uint8_t data_size, *data;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 2;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data_size = buf[1];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data = &buf[2];						\

#define STORAGE_GET_ONE_ARG_DATA				\
	uint32_t arg0;						\
	uint8_t data_size, *data;				\
	arg0 = *((uint32_t *) &buf[1]);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 6;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data_size = buf[5];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data = &buf[6];						\

/* partition information */
struct partition {
	uint32_t size; /* in blocks */
	char data_name[256];
	char create_name[256];
	char keys_name[256];
	uint8_t is_created;
};

#define NUM_PARTITIONS		6

/* FIXME: determine partitions and their sizes dynamically. */
struct partition partitions[NUM_PARTITIONS];
/*
 * The following is assumed elsewhere and hence must be the case here.
 * Partition 0 is the boot partition.
 * Partition 1 is the root fs partition for the untrusted domain.
 */
#ifdef ARCH_SEC_HW
/* FIXME: for SEC_HW, partition size must be power of 2 */
uint32_t partition_sizes[NUM_PARTITIONS] = {STORAGE_BOOT_PARTITION_SIZE,
	STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE, 128, 128, 128, 128};
#else
uint32_t partition_sizes[NUM_PARTITIONS] = {STORAGE_BOOT_PARTITION_SIZE,
	STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE, 100, 100, 100, 100};
#endif
	
#ifdef ARCH_SEC_HW_STORAGE
uint32_t boot_image_sizes[NUM_PROCESSORS + 1] = 
	{0, OS_IMAGE_SIZE, KEYBOARD_IMAGE_SIZE, SERIALOUT_IMAGE_SIZE, 
		STORAGE_IMAGE_SIZE, 0, 0, RUNTIME1_IMAGE_SIZE, 0,
		UNTRUSTED_KERNEL_SIZE};
#endif

uint8_t bound_partition = 0xFF; /* 0xFF is an invalid partition number. */
uint8_t bound = 0;
uint8_t used = 0;
uint8_t authenticated = 0;

#ifdef ARCH_SEC_HW_STORAGE
uint8_t get_srec_line(uint8_t *line, uint8_t *buf);
u32 get_boot_image_address(int pid);
u32 get_boot_image_write_address(int pid);

/* FIXME: Translation log may be retired after we switch to PMOD SD */
typedef struct __attribute__((__packed__)) {
	u16 partition_id;
	u16 virt_page_id;
	u32 phy_page_id;
} translation_log_t;

/* Source:
 * https://stackoverflow.com/questions/38088732/explanation-to-aligned-malloc-implementation */
void* aligned_malloc(size_t required_bytes, size_t alignment)
{
    void* p1; // original block
    void** p2; // aligned block
    int offset = alignment - 1 + sizeof(void*);
    if ((p1 = (void*)malloc(required_bytes + offset)) == NULL)
    {
       return NULL;
    }
    p2 = (void**)(((size_t)(p1) + offset) & ~(alignment - 1));
    p2[-1] = p1;
    return p2;
}

void aligned_free(void *p)
{
    free(((void**)p)[-1]);
}

/* The next writable page number in each partition.
 * Note that page 0 is reserved as an empty page, so that
 * unmapped virtual pages will always read 0xFF.
 */
u32 partition_head[NUM_PARTITIONS];

u32 translation_log_head_offset = 0;

/* page_map translates a virtual page number to a
 * physical page number.
 */
/* FIXME: currently support up to 1000 virtual pages. */
#define PAGE_MAP_MAX_VIRT_PAGE 1000
u32 page_map[NUM_PARTITIONS][PAGE_MAP_MAX_VIRT_PAGE] = {0};

#define FLASH_PAGE_MAP_SECTOR_OFFSET 0
#define FLASH_PAGE_MAP_SECTOR_LENGTH 1
#define PARTITION_HEADER_SECTOR_OFFSET FLASH_PAGE_MAP_SECTOR_OFFSET + FLASH_PAGE_MAP_SECTOR_LENGTH
#define PARTITION_HEADER_SECTOR_LENGTH NUM_PARTITIONS
#define PARTITION_DATA_SECTOR_OFFSET PARTITION_HEADER_SECTOR_OFFSET + PARTITION_HEADER_SECTOR_LENGTH

#define MIN_PARTITION_SECTOR_SIZE 3

#define create_header_offset 0
#define lock_header_offset 15

// FIXME: Move to a header file
typedef struct{
	u32 SectSize;		/* Individual sector size or combined sector
				 * size in case of parallel config
				 */
	u32 NumSect;		/* Total no. of sectors in one/two
				 * flash devices
				 */
	u32 PageSize;		/* Individual page size or
				 * combined page size in case of parallel
				 * config
				 */
	u32 NumPage;		/* Total no. of pages in one/two flash
				 * devices
				 */
	u32 FlashDeviceSize;	/* This is the size of one flash device
				 * NOT the combination of both devices,
				 * if present
				 */
	u8 ManufacturerID;	/* Manufacturer ID - used to identify make */
	u8 DeviceIDMemSize;	/* Byte of device ID indicating the
				 * memory size
				 */
	u32 SectMask;		/* Mask to get sector start address */
	u8 NumDie;		/* No. of die forming a single flash */
} FlashInfo;

extern u32 FCTIndex;
extern u8 ReadCmd;
extern u8 WriteCmd;
extern u8 CmdBfr[8];
extern FlashInfo Flash_Config_Table[];

int FlashErase(u32 Address, u32 ByteCount,
		u8 *WriteBfrPtr);
int FlashWrite(u32 Address, u32 ByteCount, u8 Command,
				u8 *WriteBfrPtr);
int FlashRead(u32 Address, u32 ByteCount, u8 Command,
				u8 *WriteBfrPtr, u8 *ReadBfrPtr);

#define is_aligned_64(PTR) \
	(((uintptr_t)(const void *)(PTR)) % 64 == 0)

#define ERASE_HEADER	0x10
#define ERASE_DATA		0x01
#define ERASE_ALL		0x11

static u32 get_physical_partition_size(int partition_id)
{
	/* The partition size persent to user. */
	u32 norminal_size = partition_sizes[partition_id];

	/* Base size may be zero if less than sector size */
	u32 base_size = (int) norminal_size / Flash_Config_Table[FCTIndex].SectSize;

	if (base_size >=
			Flash_Config_Table[FCTIndex].NumSect -
			PARTITION_HEADER_SECTOR_LENGTH -
			FLASH_PAGE_MAP_SECTOR_LENGTH)
		SEC_HW_DEBUG_HANG();

	/* The minimal size required to implement erase, plus 2 times the base size*/
	return (MIN_PARTITION_SECTOR_SIZE + base_size * 2) *
			Flash_Config_Table[FCTIndex].SectSize;
}

static inline u32 get_translation_table_address()
{
	u32 address =
			FLASH_PAGE_MAP_SECTOR_OFFSET * Flash_Config_Table[FCTIndex].SectSize;

	return address;
}

static u32 get_partition_header_address(int partition_id)
{
	u32 address =
			PARTITION_HEADER_SECTOR_OFFSET * Flash_Config_Table[FCTIndex].SectSize +
			partition_id * Flash_Config_Table[FCTIndex].SectSize;

	return address;
}

static u32 get_partition_base_address(int partition_id)
{
	int i;
	u32 address =
			PARTITION_DATA_SECTOR_OFFSET * Flash_Config_Table[FCTIndex].SectSize;

	for (i = 0; i < partition_id; i++)
		address += get_physical_partition_size(i);

	return address;
}

static u32 get_partition_phy_page_address(int partition_id, int page_id)
{
	u32 address;
	u32 base_address = get_partition_base_address(partition_id);
	u32 phy_page = page_map[partition_id][page_id];

	address = base_address +
			phy_page * Flash_Config_Table[FCTIndex].PageSize;

	return address;
}

static int partition_erase(int partition_id, int part)
{
	struct partition *partition;
	u32 header_address, data_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	partition = &partitions[partition_id];
	header_address = get_partition_header_address(partition_id);
	data_address = get_partition_base_address(partition_id);

	if (part & ERASE_HEADER) {
		// FIXME: implement
//		status = FlashErase(header_address, header_size, CmdBfr);
		if (status != XST_SUCCESS) {
			SEC_HW_DEBUG_HANG();
			return ERR_FAULT;
		}
	}


	if (part & ERASE_DATA) {
		// FIXME: implement
		/* erase partition data */
//		status = FlashErase(data_address, partition->size, CmdBfr);
	}

	return 0;
}

static int partition_reset_key(int partition_id)
{
	u32 header_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	header_address = get_partition_header_address(partition_id);

	/* erase partition header */
	// FIXME: impl
//	status = FlashErase(header_address + lock_header_offset,
//						header_size - lock_header_offset,
//						CmdBfr);

	if (status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}	

	return 0;
}

static void write_translation_log(u8 partition_id, u32 virt_page_id, u32 phy_page_id)
{
	translation_log_t *entry = (translation_log_t*)
			malloc(sizeof(translation_log_t) + 5);
	u32 translation_log_head_address = get_translation_table_address();
	u32 status;

	entry->partition_id = partition_id;
	entry->virt_page_id = virt_page_id;
	entry->phy_page_id = phy_page_id;

	/* FIXME: handle large translation log */
	if (translation_log_head_offset + sizeof(translation_log_t) >
		Flash_Config_Table[FCTIndex].SectSize)
		SEC_HW_DEBUG_HANG();

	status = FlashWrite(translation_log_head_address + translation_log_head_offset,
			sizeof(translation_log_t), WriteCmd, (u8 *) entry);

	if (status != XST_SUCCESS)
		SEC_HW_DEBUG_HANG();

	translation_log_head_offset += sizeof(translation_log_t);
	free(entry);
}

void read_translation_log_and_initialize_mappings()
{
	translation_log_t *entry = (translation_log_t*)
			aligned_malloc(sizeof(translation_log_t) + 48, 64);
	u32 translation_log_head_address = get_translation_table_address();
	u32 translation_log_count = 0;
	u32 status;
	u32 partition_tail[NUM_PARTITIONS] = {0};
	_Bool need_write_back = FALSE;

	/* Set all partition head to 1. Page 0 is reserved for invalid pages (0xff) */
	for (int i = 0; i < NUM_PARTITIONS; i++)
		partition_head[i] = 1;

	for (;;) {
		status = FlashRead(translation_log_head_address +
							translation_log_count * sizeof(translation_log_t),
						sizeof(translation_log_t),
						ReadCmd, CmdBfr, (u8 *) entry);

		if (status != XST_SUCCESS)
			SEC_HW_DEBUG_HANG();

		/* Stop at 0xff because erased flash reads 0xff.
		 * It can be the end of log, or there is no log at all.
		 */
		/* After an unaligned write (if it's the last write), there will be
		 * a few 0x00 follow. That's why we check for the next value.
		 */
		if (*(u8 *) entry == 0xff) {
			break;
		}

		if (entry->partition_id >= NUM_PARTITIONS ||
				entry->virt_page_id >= PAGE_MAP_MAX_VIRT_PAGE)
			SEC_HW_DEBUG_HANG();

		page_map[entry->partition_id][entry->virt_page_id] = entry->phy_page_id;

		if (entry->virt_page_id > partition_tail[entry->partition_id])
			partition_tail[entry->partition_id] = entry->virt_page_id;

		if (partition_head[entry->partition_id] < entry->phy_page_id + 1)
			partition_head[entry->partition_id] = entry->phy_page_id + 1;

		translation_log_count++;
	}

	aligned_free(entry);

	/* Writing the compressed translation table back to flash */
	for (int i = 0; i < NUM_PARTITIONS; i++) {
		if (partition_tail[i] != 0)
			need_write_back = TRUE;
	}

	if (!need_write_back)
		return;

	FlashErase(translation_log_head_address, 1024, CmdBfr);

	for (int i = 0; i < NUM_PARTITIONS; i++) {
		/* virtual page 0 is reserved, so we skip */
		if (partition_tail[i] == 0)
			continue;

		for (int j = 0; j <= partition_tail[i]; j++)
			write_translation_log(i, j, page_map[i][j]);
	}
}

static int partition_read_header(int partition_id, u32 offset, u32 length, void *ptr)
{
	u32 header_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	if (offset + length > Flash_Config_Table[FCTIndex].SectSize) {
		SEC_HW_DEBUG_HANG();
		return ERR_INVALID;
	}

	if (!is_aligned_64(ptr)) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	header_address = get_partition_header_address(partition_id);

	/* read partition header */
	status = FlashRead(header_address + offset, 
					length,
					ReadCmd,
					CmdBfr, 
					(u8 *) ptr);
	if (status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}
	return length;
}

static int partition_read(int partition_id, int page_id, void *ptr)
{
	u32 data_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	/* Check if requested page id goes beyond allocated partition size */
	if (page_id >= partition_sizes[partition_id] / STORAGE_BLOCK_SIZE) {
		return ERR_PERMISSION;
	}

	if (!is_aligned_64(ptr)) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	data_address = get_partition_phy_page_address(partition_id, page_id);

	/* read partition */
	status = FlashRead(data_address,
					STORAGE_BLOCK_SIZE,
					ReadCmd, 
					CmdBfr, 
					(u8 *) ptr);

	if (status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	return STORAGE_BLOCK_SIZE;
}

static int partition_write_header(int partition_id, u32 offset, u32 length, void *ptr)
{
	u32 header_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	if (length > Flash_Config_Table[FCTIndex].PageSize)
		return ERR_INVALID;

	if (offset + length > Flash_Config_Table[FCTIndex].SectSize)
		return ERR_INVALID;

	// FIXME: dup buf is no longer needed
	uint8_t dup_buf[length + 5];
	memcpy(dup_buf, ptr, length);

	header_address = get_partition_header_address(partition_id);

	/* write partition header */
	status = FlashWrite(header_address + offset, length, WriteCmd, (u8 *) dup_buf);

	if (status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	return length;
}

static int partition_write(int partition_id, int page_id, void *ptr)
{
	u32 data_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	/* Check if requested page id goes beyond allocated partition size */
	if (page_id >= 
		partition_sizes[partition_id] / STORAGE_BLOCK_SIZE) {
		SEC_HW_DEBUG_HANG();
		return ERR_PERMISSION;
	}

	/* Update in-memory mapping */
	page_map[partition_id][page_id] = partition_head[partition_id];

	/* Append a translation log entry to flash */
	write_translation_log(partition_id, 
		page_id, partition_head[partition_id]);

	/* Update next writable physical address */
	partition_head[partition_id] += 1;

	/* Get physical address and write flash */
	data_address = 
		get_partition_phy_page_address(partition_id, page_id);
	status = FlashWrite(data_address, 
		STORAGE_BLOCK_SIZE, WriteCmd, (u8 *) ptr);

	if (status != XST_SUCCESS) {
		/* In case of a bad write, map the bad virt page to page zero.
		 * The partial written data will never be reachable. */
		page_map[partition_id][page_id] = 0;
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	/* FIXME: a small delay is needed for the write to finish. */
	for (int i=0; i < 1000; i++)
		asm("nop");

	return STORAGE_BLOCK_SIZE;
}

/* directly reads physical address. for reading boot images only */
int partition_read_physical(u32 data_address, u32 size, void *ptr)
{
	u32 status;

	if (!is_aligned_64(ptr)) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	/* read partition */
	status = FlashRead(data_address,
					size,
					ReadCmd,
					CmdBfr,
					(u8 *) ptr);

	if (status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	return size;
}

/* directly writes to physical address. for writing boot images only */
int partition_write_physical(u32 data_address, u32 size, void *ptr)
{
	u32 page_count, sector_count, page, sec;

	/* do not support mid-sector write */
	if (data_address % Flash_Config_Table[FCTIndex].SectSize != 0) {
		SEC_HW_DEBUG_HANG();
		return ERR_INVALID;
	}
 
	if (size % Flash_Config_Table[FCTIndex].PageSize != 0) {
		SEC_HW_DEBUG_HANG();
		return ERR_INVALID;
	}

	sector_count = size / Flash_Config_Table[FCTIndex].SectSize +
				(size % Flash_Config_Table[FCTIndex].SectSize != 0);

	/* we already align data_address with sector start address.
	 * erase size doesn't matter.
	 */
	for (sec = 0; sec < sector_count; sec++)
		FlashErase(data_address + 
			Flash_Config_Table[FCTIndex].SectSize * sec, 
			1024, CmdBfr);

	page_count = size / Flash_Config_Table[FCTIndex].PageSize;

	for (page = 0; page < page_count; page++) {
		FlashWrite(data_address + 
					page * Flash_Config_Table[FCTIndex].PageSize,
					Flash_Config_Table[FCTIndex].PageSize, 
					WriteCmd, 
					(u8 *) ptr + 
						page * Flash_Config_Table[FCTIndex].PageSize);
	}

	return size;
}

int load_boot_image_from_storage(int pid, void *ptr)
{
	u32 address;

	if (pid >= NUM_PROCESSORS) {
		return ERR_INVALID;
	}

	address = get_boot_image_address(pid);
	
	partition_read_physical(address, boot_image_sizes[pid], ptr);

	return 0;
}

int write_boot_image_to_storage(int pid, void *ptr)
{
	u32 address;

	address = get_boot_image_write_address(pid);

    switch(pid) {
        case P_UNTRUSTED_BOOT_P0:
            partition_write_physical(address, 
            	UNTRUSTED_KERNEL_P0_SIZE, ptr);
            break;

        case P_UNTRUSTED_BOOT_P1:
            partition_write_physical(address, 
            	UNTRUSTED_KERNEL_P1_SIZE, ptr);
            break;

        default:
            partition_write_physical(address, 
            	boot_image_sizes[pid], ptr);
            break;
    }

    SEC_HW_DEBUG_HANG();
	return 0;
}

#endif

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
void initialize_storage_space(void)
{	
	FILE *filep, *filep2;
	struct partition *partition;
	int suffix, i;

#ifdef ARCH_SEC_HW
	uint8_t tag[4 + 48] __attribute__ ((aligned(64)));

	/* OctopOS block size must be smaller than a physical page size */
	if (STORAGE_BLOCK_SIZE > Flash_Config_Table[FCTIndex].PageSize)
		SEC_HW_DEBUG_HANG();
#else
	uint32_t tag, size, j;
#endif

#ifdef ARCH_UMODE
	chdir("./storage");
#endif

	for (i = 0; i < NUM_PARTITIONS; i++) {
		suffix = i;
		partition = &partitions[i];
		partition->size = partition_sizes[i];

		memset(partition->data_name, 0x0, 256);
		sprintf(partition->data_name, "octopos_partition_%d_data",
			suffix);

		memset(partition->create_name, 0x0, 256);
		sprintf(partition->create_name, "octopos_partition_%d_create",
			suffix);

		memset(partition->keys_name, 0x0, 256);
		sprintf(partition->keys_name, "octopos_partition_%d_keys",
			suffix);

#ifndef ARCH_SEC_HW_STORAGE
		filep = fop_open(partition->data_name, "r");
		if (!filep) {
			uint8_t zero_block[STORAGE_BLOCK_SIZE];
			/* create empty file */
			filep2 = fop_open(partition->data_name, "w");
			/* populate with zeros (so that first read doesn't
			 * return an error
			 */
			memset(zero_block, 0x0, STORAGE_BLOCK_SIZE);
			fop_seek(filep2, 0, SEEK_SET);
			for (j = 0; j < partition->size; j++)
				fop_write(zero_block, sizeof(uint8_t),
					  STORAGE_BLOCK_SIZE, filep2);
			fop_close(filep2);
		} else {
			fop_close(filep);
		}


		/* Is partition created? */
		filep = fop_open(partition->create_name, "r");
		if (!filep) {
			/* create empty file */
			filep2 = fop_open(partition->create_name, "w");
			fop_close(filep2);
			/* Also wipe keys info (which should not have any valid
			 * key anyway).
			 */
			filep2 = fop_open(partition->keys_name, "w");
			fop_close(filep2);
			continue;
		}

		fop_seek(filep, 0, SEEK_SET);
		tag = 0;
		size = (uint32_t) fop_read(&tag, sizeof(uint8_t), 4, filep);
		fop_close(filep);
		if (size == 4 && tag == 1) {
			partition->is_created = 1;
		} else {
			/* create empty file */
			filep2 = fop_open(partition->create_name, "w");
			fop_close(filep2);
			/* Also wipe any key info. This should not normally
			 * happen.
			 */
			filep2 = fop_open(partition->keys_name, "w");
			fop_close(filep2);
			continue;
		}
#else
		uint32_t size = partition_read_header(i, create_header_offset, 4, tag);
		if (size == 4 && tag[0] == 1) {
			partition->is_created = true;
		} else {
			// FIXME discuss with Ardalan if erase is needed.
			// all unmapped pages won't be accessible.
//			partition_erase(i, ERASE_ALL);
			continue;
		}
#endif
	}

/* FIXME: installer should set boot partition is_created flag */
#ifdef ARCH_SEC_HW
	partitions[0].is_created = true;
#endif

}

static int set_partition_key(uint8_t *data, int partition_id)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep;
	uint32_t size;
	
	filep = fop_open(partitions[partition_id].keys_name, "w");
	if (!filep) {
		printf("Error: %s: couldn't open %s\n", __func__,
		       partitions[partition_id].keys_name);
		return ERR_FAULT;
	}

	fop_seek(filep, 0, SEEK_SET);
	size = (uint32_t) fop_write(data, sizeof(uint8_t), STORAGE_KEY_SIZE,
				    filep);
	fop_close(filep);
	if (size < STORAGE_KEY_SIZE) {
		/* make sure to delete what was written */
		filep = fop_open(partitions[partition_id].keys_name, "w");
		fop_close(filep);
		return ERR_FAULT;
	}
#else
	uint32_t size = partition_write_header(partition_id,
										lock_header_offset,
										STORAGE_KEY_SIZE,
										data);
	if (size < STORAGE_KEY_SIZE) {
		// FIXME: implement
//		partition_reset_key(partition_id);
		return ERR_FAULT;
	}
#endif

	return 0;
}

static int remove_partition_key(int partition_id)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep = fop_open(partitions[partition_id].keys_name, "w");
	if (!filep) {
		printf("Error: %s: couldn't open %s\n", __func__,
		       partitions[partition_id].keys_name);
		return ERR_FAULT;
	}

	fop_close(filep);
#else
	if (partitions[partition_id].is_created) {
		// FIXME: implement
//		partition_reset_key(partition_id);
	} else {
		return ERR_FAULT;
	}
#endif
	return 0;
}

static int authenticate_partition(int partition_id, uint8_t proc_id)
{
#ifdef ARCH_UMODE
	uint8_t key[STORAGE_KEY_SIZE];
	uint8_t tpm_pcr[STORAGE_KEY_SIZE];
	FILE *filep;
	uint32_t size;
	int ret;
	
	ret = tpm_processor_read_pcr(PROC_TO_PCR(proc_id), tpm_pcr);
	if (ret) {
		printf("Error: %s: couldn't read TPM PCR for proc %d.\n",
		       __func__, proc_id);
		return ERR_FAULT;
	}

	filep = fop_open(partitions[partition_id].keys_name, "r");
	if (!filep) {
		printf("Error: %s: couldn't open %s\n", __func__,
		       partitions[partition_id].keys_name);
		return ERR_FAULT;
	}

	/* We allow up to two keys and assume they're stored back to back
	 * in the lock file.
	 */
	fop_seek(filep, 0, SEEK_SET);
	size = (uint32_t) fop_read(key, sizeof(uint8_t), STORAGE_KEY_SIZE,
				   filep);

	if (size != STORAGE_KEY_SIZE) {
		printf("Error: %s: corrupted key data.\n", __func__);
		fop_close(filep);
		return ERR_FAULT;
	}

	ret = memcmp(key, tpm_pcr, STORAGE_KEY_SIZE);
	if (!ret) {
		fop_close(filep);
		return 0;
	}

	/* second key? */
	fop_seek(filep, STORAGE_KEY_SIZE, SEEK_SET);
	size = (uint32_t) fop_read(key, sizeof(uint8_t), STORAGE_KEY_SIZE,
				   filep);
	if (!size) {
		/* We don't have a second key. */
		fop_close(filep);
		return ERR_FOUND;
	} else if (size != STORAGE_KEY_SIZE) {
		printf("Error: %s: corrupted key data (2).\n", __func__);
		fop_close(filep);
		return ERR_FAULT;
	}

	/* We have a second key. */
	ret = memcmp(key, tpm_pcr, STORAGE_KEY_SIZE);
	if (!ret) {
		fop_close(filep);
		return 0;
	}

	fop_close(filep);
	return ERR_FOUND;
#else
	return 0;
#endif
}

static int wipe_partition(int partition_id)
{
#ifndef ARCH_SEC_HW_STORAGE
	uint8_t zero_block[STORAGE_BLOCK_SIZE];
	uint32_t i;

	FILE *filep = fop_open(partitions[partition_id].data_name, "w");
	if (!filep) {
		printf("Error: %s: couldn't open %s\n", __func__,
		       partitions[partition_id].data_name);
		return ERR_FAULT;
	}

	/* populate with zeros (so that first read next time doesn't return an
	 * error
	 */
	memset(zero_block, 0x0, STORAGE_BLOCK_SIZE);
	fop_seek(filep, 0, SEEK_SET);
	for (i = 0; i < partitions[partition_id].size; i++)
		fop_write(zero_block, sizeof(uint8_t), STORAGE_BLOCK_SIZE,
			  filep);

	fop_close(filep);
#else
	// FIXME: implement
//	partition_erase(partition_id, ERASE_DATA);
#endif
	return 0;
}

/*
 * Return error if bound, used, or authenticated is set.
 * Return error if invalid resource name
 * Bind the resource to the data queues.
 * Set the global var "bound"
 * This is irreversible until reset.
 */
static void storage_bind_resource(uint8_t *buf)
{
	uint32_t partition_id;

	if (bound || used || authenticated) {
		printf("Error: %s: the bind op is invalid if bound (%d), "
		       "used (%d), or authenticated (%d) is set.\n", __func__,
		       bound, used, authenticated);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	STORAGE_GET_ONE_ARG
	partition_id = arg0;

	if (partition_id >= NUM_PARTITIONS) {
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	bound_partition = partition_id;
	bound = 1;

	STORAGE_SET_ONE_RET(0)
}

/*
 * Bound or not?
 * Used or not?
 * If authentication is needed, is it authenticated?
 * If bound, resource name size and then resouce name.
 * If needed, is resource created/destroyed?
 * Other device specific info:
 *	network packet header
 * If global flag "used" not set, set it.
 * This is irreversible until reset.
 */
static void storage_query_state(uint8_t *buf)
{
	uint8_t state[5], partition_id;
	uint32_t state_size = 5;

	state[0] = bound;
	state[1] = used;
	used = 1;
	
	state[2] = authenticated;
	
	partition_id = bound_partition;

	state[3] = bound_partition;

	/* Technically, an unnecessary check. */
	if (partition_id >= NUM_PARTITIONS) {
		printf("Error: %s: invalid ID for the bound partition\n",
		       __func__);
		state[4] = 0;
	} else {
		state[4] = partitions[partition_id].is_created;
	}

	STORAGE_SET_ONE_RET_DATA(0, state, state_size)
}

/*
 * Return error if "bound" not set.
 * Return error if authentication is needed and not authenticated. 
 * Return error if bound resource not created (destroyed).
 * If global flag "used" not set, set it.
 * This is irreversible until reset.
 * Process incoming data on data queue (one or multiple).
 */
static void storage_send_data(uint8_t *buf)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep;
#endif
	uint8_t partition_id;
	uint32_t start_block, num_blocks, seek_off, size, i;
	uint8_t data_buf[STORAGE_BLOCK_SIZE];
	
	used = 1;

	if (!bound || !authenticated) {
		printf("Error: %s: the send_data op is invalid if bound (%d) "
		       "or authenticated (%d) is not set.\n", __func__,
		       bound, authenticated);
		STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
		return;
	}

	partition_id = bound_partition;

	/* Technically, an unnecessary check. */
	if (partition_id >= NUM_PARTITIONS) {
		printf("Error: %s: invalid ID for the bound partition\n",
		       __func__);
		STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
		return;
	}

	if (!partitions[partition_id].is_created) {
		printf("Error: %s: partition does not exist\n", __func__);
		STORAGE_SET_TWO_RETS(ERR_EXIST, 0)
		return;
	}

#ifndef ARCH_SEC_HW_STORAGE
	filep = fop_open(partitions[partition_id].data_name, "r+");
	if (!filep) {
		printf("Error: %s: couldn't open %s for write\n", __func__,
					partitions[partition_id].data_name);
		STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
		return;
	}
#endif

	STORAGE_GET_TWO_ARGS
	start_block = arg0;
	num_blocks = arg1;
	
	if (start_block + num_blocks > partitions[partition_id].size) {
		printf("Error: %s: invalid args\n", __func__);
		STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
#ifndef ARCH_SEC_HW_STORAGE
		fop_close(filep);
#endif
		return;
	}

#ifndef ARCH_SEC_HW_STORAGE
	seek_off = start_block * STORAGE_BLOCK_SIZE;
	fop_seek(filep, seek_off, SEEK_SET);
#endif
	size = 0;

	for (i = 0; i < num_blocks; i++) {
		read_data_from_queue(data_buf, Q_STORAGE_DATA_IN);
#ifndef ARCH_SEC_HW_STORAGE
		size += (uint32_t) fop_write(data_buf, sizeof(uint8_t),
					     STORAGE_BLOCK_SIZE, filep);
#else
		size += partition_write(partition_id,
								start_block + i,
								data_buf);
#endif
	}

	STORAGE_SET_TWO_RETS(0, size)
#ifndef ARCH_SEC_HW_STORAGE
	fop_close(filep);
#endif
}

/*
 * Return error if "bound" not set.
 * Return error if authentication is needed and not authenticated. 
 * Return error if bound resource not created (destroyed).
 * If global flag "used" not set, set it.
 * This is irreversible until reset.
 * Process incoming data on data queue (one or multiple).
 */
static void storage_receive_data(uint8_t *buf)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep;
#endif
	uint8_t partition_id;
	uint32_t start_block, num_blocks, seek_off, size, i;
	uint8_t data_buf[STORAGE_BLOCK_SIZE];

	used = 1;

	if (!bound || !authenticated) {
		printf("Error: %s: the receive_data op is invalid if bound (%d) "
		       "or authenticated (%d) is not set.\n", __func__,
		       bound, authenticated);
		STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
		return;
	}

	partition_id = bound_partition;
	
	/* Technically, an unnecessary check. */
	if (partition_id >= NUM_PARTITIONS) {
		printf("Error: %s: invalid ID for the bound partition\n",
		       __func__);
		STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
		return;
	}

	if (!partitions[partition_id].is_created) {
		printf("Error: %s: partition does not exist\n", __func__);
		STORAGE_SET_TWO_RETS(ERR_EXIST, 0)
		return;
	}

#ifndef ARCH_SEC_HW_STORAGE
	filep = fop_open(partitions[partition_id].data_name, "r");
	if (!filep) {
		printf("Error: %s: couldn't open %s for read\n", __func__,
					partitions[partition_id].data_name);
		STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
		return;
	}
#endif

	STORAGE_GET_TWO_ARGS
	start_block = arg0;
	num_blocks = arg1;

#ifdef ARCH_SEC_HW_STORAGE
	/* FIXME: use proper file read/write. */
	/* handle special boot image files */
	if (start_block >= BOOT_IMAGE_OFFSET * QSPI_SECTOR_SIZE) {
		/* FIXME: this is an ad hoc way to get the boot image address, by passing the
		 * address directly on argument.
		 */
		u32 address = start_block;
		uint8_t message_buf[STORAGE_BLOCK_SIZE + 48] 
			__attribute__ ((aligned(64)));

		for (u32 blk = 0; blk < num_blocks; blk++) {
			partition_read_physical(address + 
					blk * STORAGE_BLOCK_SIZE,
					STORAGE_BLOCK_SIZE, message_buf);
			write_data_to_queue(message_buf, Q_STORAGE_DATA_OUT);
		}

		STORAGE_SET_TWO_RETS(0, STORAGE_BLOCK_SIZE);
		return;
	}
#endif

	if (start_block + num_blocks > partitions[partition_id].size) {
		printf("Error: %s: invalid args\n", __func__);
		STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
#ifndef ARCH_SEC_HW_STORAGE
		fop_close(filep);
#endif
		return;
	}
	
#ifndef ARCH_SEC_HW_STORAGE
	seek_off = start_block * STORAGE_BLOCK_SIZE;
	fop_seek(filep, seek_off, SEEK_SET);
#endif
	size = 0;
	
	for (i = 0; i < num_blocks; i++) {
#ifndef ARCH_SEC_HW_STORAGE
		size += (uint32_t) fop_read(data_buf, sizeof(uint8_t),
					    STORAGE_BLOCK_SIZE, filep);
#else
		size += partition_read(partition_id, 
								start_block + i,
								data_buf);
#endif
		write_data_to_queue(data_buf, Q_STORAGE_DATA_OUT);
	}

	STORAGE_SET_TWO_RETS(0, size)
#ifndef ARCH_SEC_HW_STORAGE
	fop_close(filep);
#endif
}

/* 
 * Create a new resource
 * Not usable if any resource is bound
 * Non-persistent resources deleted upon reset.
 * Persistent ones need a method to be destroyed, e.g., an explicit calls or
 * a time-out.
 * Receives TPM measurements if resource needs authentication
 *
 * FIXME: our current implementation does not allow creating arbitrary-sized
 * partitions.
 *
 */
static void storage_create_resource(uint8_t *buf)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep, *filep2;
	uint32_t partition_id, tag, size;
#else
	uint8_t tag[4] __attribute__ ((aligned(64)));
	uint32_t partition_id, size;
#endif
	int ret;

	if (bound) {
		printf("Error: %s: some partition is bound to queue set\n",
		       __func__);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	STORAGE_GET_ONE_ARG_DATA
	if (data_size != STORAGE_KEY_SIZE) {
		printf("Error: %s: incorrect key (TPM hash) size\n", __func__);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	partition_id = arg0;

	if (partition_id >= NUM_PARTITIONS) {
		printf("Error: %s: invalid requested partition ID (%d)\n",
		       __func__, partition_id);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	ret = set_partition_key(data, partition_id);
	if (ret) {
		STORAGE_SET_ONE_RET(ERR_FAULT)
		return;
	}

#ifndef ARCH_SEC_HW_STORAGE
	filep = fop_open(partitions[partition_id].create_name, "w");
	if (!filep) {
		printf("Error: %s: Couldn't open %s.\n", __func__,
		       partitions[partition_id].create_name);
		STORAGE_SET_ONE_RET(ERR_FAULT)
		return;
	}

	fop_seek(filep, 0, SEEK_SET);
	tag = 1;
	size = (uint32_t) fop_write(&tag, sizeof(uint8_t), 4, filep);
	fop_close(filep);
#else
		tag[0] = 1;
		size = partition_write_header(partition_id,
									create_header_offset,
									4, tag);
#endif
	if (size != 4) {
		STORAGE_SET_ONE_RET(ERR_FAULT)
		if (size > 0) { /* partial write */
			/* wipe the file */
#ifndef ARCH_SEC_HW_STORAGE
			filep2 = fop_open(partitions[partition_id].create_name,
					  "w");
			fop_close(filep2);
#else
				/* FIXME: implement */
//				partition_erase(partition_id, ERASE_HEADER);
#endif
		}
		return;
	}

	partitions[partition_id].is_created = 1;

	STORAGE_SET_ONE_RET(0)
}

/* 
 * List available resources.
 * Not usable if resource bound.
 * If authentication is used, return keys (i.e., TPM measurements) for resources.
 * Can be implemented to return all data in one response or in separate queries.
 */
static void storage_query_all_resources(uint8_t *buf)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep;
#else
	uint8_t tag[4] __attribute__ ((aligned(64)));
#endif
	uint32_t size;
	uint32_t num_partitions;
	uint8_t partition_id;

/* FIXME: sec_hw doesn't support storage domain reboot. */
#ifndef ARCH_SEC_HW_STORAGE
	if (bound) {
		printf("Error: %s: the query_all_resources op cannot be used "
		       "when some partition is bound\n", __func__);
		char dummy;
		STORAGE_SET_ONE_RET_DATA(ERR_INVALID, &dummy, 0)
		return;
	}
#else
	if (bound) {
		/* if bound, simulate a reset */
		used = 0;
		bound = 0;
		authenticated = 0;
		bound_partition = 0xFF;
	}
#endif

	STORAGE_GET_TWO_ARGS

	if (arg0 == 0) {
		/* query the number of partitions */
		num_partitions = NUM_PARTITIONS;
		STORAGE_SET_ONE_RET_DATA(0, &num_partitions, 4)
	} else if (arg0 == 1) {
		/* query info of a specific partition
		 *
		 * data:
		 * 4 bytes for partition size
		 * 1 byte for is_created
		 * if is_created, STORAGE_KEY_SIZE bytes for the key
		 */
		uint8_t data[5 + STORAGE_KEY_SIZE];
		uint8_t key[STORAGE_KEY_SIZE];

		partition_id = arg1;

		if (partition_id >= NUM_PARTITIONS) {
			printf("Error: %s: invalid partition_id (%d)\n",
			       __func__, partition_id);
			char dummy;
			STORAGE_SET_ONE_RET_DATA(ERR_INVALID, &dummy, 0)
			return;
		}

		memcpy(data, &partitions[partition_id].size, 4);

		data[4] = partitions[partition_id].is_created;

		if (data[4]) {
#ifndef ARCH_SEC_HW_STORAGE
			filep = fop_open(partitions[partition_id].keys_name,
					 "r");
			if (!filep) {
				printf("Error: %s: couldn't open %s\n", __func__,
				       partitions[partition_id].keys_name);
				char dummy;
				STORAGE_SET_ONE_RET_DATA(ERR_FAULT, &dummy, 0)
				return;
			}

			fop_seek(filep, 0, SEEK_SET);
			size = (uint32_t) fop_read(key, sizeof(uint8_t),
						   STORAGE_KEY_SIZE, filep);
			fop_close(filep);
#endif

#ifdef ARCH_SEC_HW_STORAGE
			size = partition_read_header(partition_id,
					 lock_header_offset, STORAGE_KEY_SIZE, tag);
#endif
			if (size != STORAGE_KEY_SIZE) {
				printf("Error: %s: corrupted key data.\n",
				       __func__);
				char dummy;
				STORAGE_SET_ONE_RET_DATA(ERR_FAULT, &dummy, 0)
				return;
			}

			memcpy(&data[5], key, STORAGE_KEY_SIZE);
		}

		STORAGE_SET_ONE_RET_DATA(0, &data, 5 + STORAGE_KEY_SIZE)
	}
}

/*
 * Used when resource needs authentication.
 * Return error if "bound" not set.
 * Return error if "authenticated" already set.
 * Return error if bound resource not created (destroyed).
 * "authenticated" global variable will be set on success
 * If global flag "used" not set, set it.
 * This is irreversible until reset.
 * May require/receive signature for the TPM measurement
 *
 * @proc_id: ID of the requesting processor.
 */
static void storage_authenticate(uint8_t *buf, uint8_t proc_id)
{
	uint8_t partition_id;
	int ret;

	used = 1;

	if (!bound) {
		printf("Error: %s: no partition is bound to queue set\n",
		       __func__);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	if (authenticated) {
		printf("Error: %s: already authenticated.\n", __func__);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	partition_id = bound_partition;

	/* Technically, an unnecessary check. */
	if (bound_partition >= NUM_PARTITIONS) {
		printf("Error: %s: invalid ID for the bound partition\n",
		       __func__);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	if (!partitions[partition_id].is_created) {
		printf("Error: %s: partition does not exist\n", __func__);
		STORAGE_SET_ONE_RET(ERR_EXIST)
		return;
	}

	ret = authenticate_partition(partition_id, proc_id);
	if (ret) {
		printf("Error: %s: authentication failed\n",__func__);
		STORAGE_SET_ONE_RET(ERR_PERMISSION)
		return;
	}			

	authenticated = 1;

	STORAGE_SET_ONE_RET(0)
}

/*
 * Return error if "bound" not set.
 * Return error if "authenticated" not set.
 * "authenticated" global variable will be unset.
 * If global flag "used" not set, set it.
 * This is irreversible until rest.
 */
static void storage_deauthenticate(uint8_t *buf)
{
	used = 1;

	if (!bound || !authenticated) {
		printf("Error: %s: the deauthenticate op is invalid if bound "
		       "(%d) or authenticated (%d) is not set.\n", __func__,
		       bound, authenticated);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	authenticated = 0;	
		
	STORAGE_SET_ONE_RET(0)
}

/*
 * Return error if "bound" not set.
 * Return error if authentication is needed and not authenticated. 
 * Return error if bound resource not created (destroyed).
 * If global flag "used" not set, set it.
 * This is irreversible until reset.
 * Destroy resource(s).
 * After a resource is destroyed, it cannot be used.
 * Deauthenticate if needed.
 */ 
static void storage_destroy_resource(uint8_t *buf)
{
	uint8_t partition_id;
	int ret;
	FILE *filep;

	used = 1;

	if (!bound || !authenticated) {
		printf("Error: %s: the destroy_resource op is invalid if bound "
		       "(%d) or authenticated (%d) is not set.\n", __func__,
		       bound, authenticated);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	partition_id = bound_partition;

	if (partition_id >= NUM_PARTITIONS) {
		printf("Error: %s: invalid partition ID\n", __func__);
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}

	if (!partitions[partition_id].is_created) {
		printf("Error: %s: partition does not exist\n", __func__);
		STORAGE_SET_ONE_RET(ERR_EXIST)
		return;
	}

	authenticated = 0;
	
	ret = wipe_partition(partition_id);
	if (ret)
		printf("Error: %s: couldn't wipe the partition\n", __func__);

	ret = remove_partition_key(partition_id);
	if (ret)
		printf("Error: %s: couldn't remove partition key\n", __func__);

	partitions[partition_id].is_created = 0;

#ifndef ARCH_SEC_HW
	/* wipe the create file of the partition */
	filep = fop_open(partitions[partition_id].create_name, "w");
	fop_close(filep);
#endif

	STORAGE_SET_ONE_RET(0)
}

void process_request(uint8_t *buf, uint8_t proc_id)
{
	switch (buf[0]) {
	case IO_OP_QUERY_ALL_RESOURCES:
		storage_query_all_resources(buf);	
		break;

	case IO_OP_CREATE_RESOURCE:
		storage_create_resource(buf);
		break;

	case IO_OP_BIND_RESOURCE:
		storage_bind_resource(buf);		
		break;

	case IO_OP_QUERY_STATE:
		storage_query_state(buf);
		break;

	case IO_OP_AUTHENTICATE:
		storage_authenticate(buf, proc_id);
		break;

	case IO_OP_SEND_DATA:
		storage_send_data(buf);
		break;

	case IO_OP_RECEIVE_DATA:
		storage_receive_data(buf);
		break;

	case IO_OP_DEAUTHENTICATE:
		storage_deauthenticate(buf);
		break;

	case IO_OP_DESTROY_RESOURCE:
		storage_destroy_resource(buf);
		break;

	default:
		/*
		 * If global flag "used" not set, set it.
		 * This is irreversible until reset.
		 */
		printf("Error: %s: unknown op (%d)\n", __func__, buf[0]);
		used = 1;
		STORAGE_SET_ONE_RET(ERR_INVALID)
		break;
	}
}

#ifndef ARCH_SEC_HW_BOOT
int main(int argc, char **argv)
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: storage init\n", __func__);

#ifndef ARCH_SEC_HW
	enforce_running_process(P_STORAGE);
#endif

	init_storage();
	storage_event_loop();
	close_storage();
}
#endif
