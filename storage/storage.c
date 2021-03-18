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
#else
#include "arch/semaphore.h"
#endif
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/error.h>
#include <tpm/tpm.h>

#include "arch/mailbox_storage.h"
#include "arch/syscall.h"

#ifdef ARCH_SEC_HW_STORAGE
#include "arch/sec_hw.h"
#else /* ARCH_SEC_HW_STORAGE */

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
	char lock_name[256];
	bool is_created;
	bool is_locked;
};

#define NUM_PARTITIONS		6

/* FIXME: determine partitions and their sizes dynamically. */
struct partition partitions[NUM_PARTITIONS];
uint32_t partition_sizes[NUM_PARTITIONS] = {STORAGE_BOOT_PARTITION_SIZE,
	STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE, 128, 128, 128};

#ifdef ARCH_SEC_HW_STORAGE
uint32_t boot_image_sizes[NUM_PROCESSORS + 1] = 
	{0, OS_IMAGE_SIZE, 0, 0, STORAGE_IMAGE_SIZE, 0, 0, 0, 0 ,0 ,0};
#endif

bool is_queue_set_bound = false;
int bound_partition = -1;

uint8_t config_key[STORAGE_KEY_SIZE];
bool is_config_locked = false;

#ifdef ARCH_SEC_HW_STORAGE
uint8_t get_srec_line(uint8_t *line, uint8_t *buf);
u32 get_boot_image_address(int pid);

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
//	uint8_t zero_block[header_size] __attribute__ ((aligned(64)));

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
	translation_log_t *entry = malloc(sizeof(translation_log_t) + 5);
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
	translation_log_t *entry = aligned_malloc(sizeof(translation_log_t) + 48, 64);
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
//	SEC_HW_DEBUG_HANG();
	u32 header_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	if (length > Flash_Config_Table[FCTIndex].PageSize)
		return ERR_INVALID;

//	if (!is_aligned_64(ptr)) {
//		SEC_HW_DEBUG_HANG();
//		return ERR_FAULT;
//	}
	// FIXME: dup buf is no longer needed
	uint8_t dup_buf[length + 5];
	memcpy(dup_buf, ptr, length);

	if (offset + length > Flash_Config_Table[FCTIndex].SectSize)
		return ERR_INVALID;

	header_address = get_partition_header_address(partition_id);

	/* write partition header */
//	status = FlashErase(header_address + offset, length, CmdBfr);
	// FIXME check for status errors
	status = FlashWrite(header_address + offset, length, WriteCmd, (u8 *) dup_buf);
	//debug >>>
//	uint8_t bufw[128+5];
//	memset(bufw, 0x99, 32);
//	status = FlashWrite(1036, 32, WriteCmd, (u8 *) bufw);

//	uint8_t bufr[128 + 48] __attribute__ ((aligned(64)));
//	memset(bufr, 0x0, 128);
//	status = FlashRead(header_offset,
//					header_size,
//					ReadCmd,
//					CmdBfr,
//					bufr);

//	sleep(30);
	//debug <<<
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
	if (page_id >= partition_sizes[partition_id] / STORAGE_BLOCK_SIZE) {
		SEC_HW_DEBUG_HANG();
		return ERR_PERMISSION;
	}

	/* Update in-memory mapping */
	page_map[partition_id][page_id] = partition_head[partition_id];

	/* Append a translation log entry to flash */
	write_translation_log(partition_id, page_id, partition_head[partition_id]);

	/* Update next writable physical address */
	partition_head[partition_id] += 1;

	/* Get physical address and write flash */
	data_address = get_partition_phy_page_address(partition_id, page_id);
	status = FlashWrite(data_address, STORAGE_BLOCK_SIZE, WriteCmd, (u8 *) ptr);

	if (status != XST_SUCCESS) {
		/* In case of a bad write, map the bad virt page to page zero.
		 * The partial written data will never be reachable. */
		page_map[partition_id][page_id] = 0;
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	// FIXME: a small delay is needed for the write to finish.
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

	if (sector_count > MAX_ALLOWED_IMAGE_SIZE_IN_SECTOR) {
		SEC_HW_DEBUG_HANG();
		return ERR_INVALID;
	}

	/* we already align data_address with sector start address.
	 * erase size doesn't matter.
	 */
	for (sec = 0; sec < sector_count; sec++)
		FlashErase(data_address + Flash_Config_Table[FCTIndex].SectSize * sec, 1024, CmdBfr);

	page_count = size / Flash_Config_Table[FCTIndex].PageSize;

	for (page = 0; page < page_count; page++) {
		FlashWrite(data_address + page * Flash_Config_Table[FCTIndex].PageSize,
					Flash_Config_Table[FCTIndex].PageSize, 
					WriteCmd, 
					(u8 *) ptr + page * Flash_Config_Table[FCTIndex].PageSize);
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

	if (pid >= NUM_PROCESSORS) {
		return ERR_INVALID;
	}

	address = get_boot_image_address(pid);

	partition_write_physical(address, boot_image_sizes[pid], ptr);

	return 0;
}

#endif

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
void initialize_storage_space(void)
{
	uint8_t tag[4 + 48] __attribute__ ((aligned(64)));

#ifdef ARCH_SEC_HW
	/* OctopOS block size must be smaller than a physical page size */
	if (STORAGE_BLOCK_SIZE > Flash_Config_Table[FCTIndex].PageSize)
		SEC_HW_DEBUG_HANG();
#endif

#ifdef ARCH_UMODE
	chdir("./storage");
#endif
	for (int i = 0; i < NUM_PARTITIONS; i++) {
		struct partition *partition;
		int suffix = i;
		partition = &partitions[i];
		partition->size = partition_sizes[i];

		memset(partition->data_name, 0x0, 256);
		sprintf(partition->data_name, "octopos_partition_%d_data", suffix);

		memset(partition->create_name, 0x0, 256);
		sprintf(partition->create_name, "octopos_partition_%d_create", suffix);

		memset(partition->lock_name, 0x0, 256);
		sprintf(partition->lock_name, "octopos_partition_%d_lock", suffix);

#ifndef ARCH_SEC_HW_STORAGE
		FILE *filep = fop_open(partition->data_name, "r");
		if (!filep) {
			/* create empty file */
			FILE *filep2 = fop_open(partition->data_name, "w");
			/* populate with zeros (so that first read doesn't return an error */
			uint8_t zero_block[STORAGE_BLOCK_SIZE];
			memset(zero_block, 0x0, STORAGE_BLOCK_SIZE);
			fop_seek(filep2, 0, SEEK_SET);
			for (uint32_t j = 0; j < partition->size; j++)
				fop_write(zero_block, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep2);
			fop_close(filep2);
		} else {
			fop_close(filep);
		}

		/* Is partition created? */
		filep = fop_open(partition->create_name, "r");
		if (!filep) {
			/* create empty file */
			FILE *filep2 = fop_open(partition->create_name, "w");
			fop_close(filep2);
			/* Also wipe lock info (which should not have any valid key anyway. */
			filep2 = fop_open(partition->lock_name, "w");
			fop_close(filep2);
			partition->is_locked = false;
			continue;
		}

		fop_seek(filep, 0, SEEK_SET);
		uint32_t tag = 0;
		uint32_t size = (uint32_t) fop_read(&tag, sizeof(uint8_t), 4, filep);
		fop_close(filep);
		if (size == 4 && tag == 1) {
			partition->is_created = true;
		} else {
			/* create empty file */
			FILE *filep2 = fop_open(partition->create_name, "w");
			fop_close(filep2);
			/* Also wipe any key info. This should not normally happen. */
			filep2 = fop_open(partition->lock_name, "w");
			fop_close(filep2);
			partition->is_locked = false;
			continue;
		}

		/* lock partitions that have an active key */
		filep = fop_open(partition->lock_name, "r");
		if (!filep) {
			/* create empty file */
			FILE *filep2 = fop_open(partition->lock_name, "w");
			fop_close(filep2);
			partition->is_locked = false;
			continue;
		}

		uint8_t key[STORAGE_KEY_SIZE];
		fop_seek(filep, 0, SEEK_SET);
		size = (uint32_t) fop_read(key, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
		fop_close(filep);
		if (size == STORAGE_KEY_SIZE) {
			partition->is_locked = true;
		} else {
			/* wipe lock file */
			FILE *filep2 = fop_open(partition->lock_name, "w");
			fop_close(filep2);
			partition->is_locked = false;
		}
#else
		uint32_t size = partition_read_header(i, create_header_offset, 4, tag);
//		sleep(1);
		if (size == 4 && tag[0] == 1) {
			partition->is_created = true;
		} else {
			// FIXME discuss with Ardalan if erase is needed.
			// all unmapped pages won't be accessible.
//			partition_erase(i, ERASE_ALL);
			partition->is_locked = false;
			continue;
		}
#endif
	}

	/* set an initial config key */
	for (int i = 0; i < STORAGE_KEY_SIZE; i++)
		config_key[i] = i;

}

static int set_partition_key(uint8_t *data, int partition_id)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep = fop_open(partitions[partition_id].lock_name, "r+");
	if (!filep) {
		printf("%s: Error: couldn't open %s\n", __func__, partitions[partition_id].lock_name);
		return ERR_FAULT;
	}

	fop_seek(filep, 0, SEEK_SET);
	uint32_t size = (uint32_t) fop_write(data, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
	fop_close(filep);
	if (size < STORAGE_KEY_SIZE) {
		/* make sure to delete what was written */
		filep = fop_open(partitions[partition_id].lock_name, "w");
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

//	// debug >>>
//	// Pass
//	uint8_t key[STORAGE_KEY_SIZE + 48] __attribute__ ((aligned(64)));
//	size = partition_read_header(partition_id,
//								lock_header_offset,
//								STORAGE_KEY_SIZE,
//								key);
//	sleep(30);
//	// debug <<<
#endif

	return 0;
}

static int remove_partition_key(int partition_id)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep = fop_open(partitions[partition_id].lock_name, "w");
	if (!filep) {
		printf("%s: Error: couldn't open %s\n", __func__, partitions[partition_id].lock_name);
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

////DEBUG
int unlock_counter = 0;

static int unlock_partition(uint8_t *data, int partition_id)
{
#ifndef ARCH_SEC_HW_STORAGE
	uint8_t key[STORAGE_KEY_SIZE];
	FILE *filep = fop_open(partitions[partition_id].lock_name, "r");
	if (!filep) {
		printf("%s: Error: couldn't open %s\n", __func__, partitions[partition_id].lock_name);
		return ERR_FAULT;
	}

	fop_seek(filep, 0, SEEK_SET);
	uint32_t size = (uint32_t) fop_read(key, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
	fop_close(filep);
#else
	uint8_t key[STORAGE_KEY_SIZE + 48] __attribute__ ((aligned(64)));
	uint32_t size = partition_read_header(partition_id,
										lock_header_offset,
										STORAGE_KEY_SIZE,
										key);
#endif
	if (size != STORAGE_KEY_SIZE) {
		/* TODO: if the key file is corrupted, then we might need to unlock, otherwise, we'll lose the partition. */
		while(1) sleep(1);
		return ERR_FAULT;
	}
	// DEBUG
//	if (partition_id == 0) {
//		if (unlock_counter == 1)
//			sleep(30);
//		unlock_counter++;
//	}

	for (int i = 0; i < STORAGE_KEY_SIZE; i++) {
		if (key[i] != data[i]) {
			return ERR_INVALID;
		}
	}

	partitions[partition_id].is_locked = false;

	return 0;
}

static int wipe_partition(int partition_id)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep = fop_open(partitions[partition_id].data_name, "w");
	if (!filep) {
		printf("%s: Error: couldn't open %s\n", __func__, partitions[partition_id].data_name);
		return ERR_FAULT;
	}
	fop_close(filep);
#else
	// FIXME: implement
//	partition_erase(partition_id, ERASE_DATA);
#endif
	return 0;
}

void process_request(uint8_t *buf)
{
#ifndef ARCH_SEC_HW_STORAGE
	FILE *filep = NULL;
#endif

	/* write */
	if (buf[0] == STORAGE_OP_WRITE) {
		if (!is_queue_set_bound) {
			SEC_HW_DEBUG_HANG();
			printf("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
			SEC_HW_DEBUG_HANG();
			printf("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		if (partitions[partition_id].is_locked) {
			SEC_HW_DEBUG_HANG();
			printf("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

#ifndef ARCH_SEC_HW_STORAGE
		filep = fop_open(partitions[partition_id].data_name, "r+");
		if (!filep) {
			printf("%s: Error: couldn't open %s for write\n", __func__,
						partitions[partition_id].data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}
#endif

		STORAGE_GET_TWO_ARGS
		uint32_t start_block = arg0;
		uint32_t num_blocks = arg1;
		if (start_block + num_blocks > partitions[partition_id].size) {
			SEC_HW_DEBUG_HANG();
			printf("%s: Error: invalid args\n", __func__);
			STORAGE_SET_ONE_RET(0)
#ifndef ARCH_SEC_HW_STORAGE
			fop_close(filep);
#endif
			return;
		}
#ifndef ARCH_SEC_HW_STORAGE
		uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
		fop_seek(filep, seek_off, SEEK_SET);
#endif
		uint8_t data_buf[STORAGE_BLOCK_SIZE + 5];
		uint32_t size = 0;
		for (uint32_t i = 0; i < num_blocks; i++) {
			read_data_from_queue(data_buf, Q_STORAGE_DATA_IN);
#ifndef ARCH_SEC_HW_STORAGE
			size += (uint32_t) fop_write(data_buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
#else

			size += partition_write(partition_id,
									start_block + i,
									data_buf);
//			sleep(5);

//			uint8_t data_buf_rd_dbg[STORAGE_BLOCK_SIZE + 48] __attribute__ ((aligned(64)));
//			partition_read(partition_id, start_block + i, data_buf_rd_dbg);
//			sleep(5);
#endif
		}
		STORAGE_SET_ONE_RET(size);
#ifndef ARCH_SEC_HW_STORAGE
		fop_close(filep);
#endif
	} else if (buf[0] == STORAGE_OP_READ) { /* read */
		if (!is_queue_set_bound) {
			SEC_HW_DEBUG_HANG();
			printf("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
			SEC_HW_DEBUG_HANG();
			printf("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		if (partitions[partition_id].is_locked) {
			SEC_HW_DEBUG_HANG();
			printf("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

#ifndef ARCH_SEC_HW_STORAGE
		filep = fop_open(partitions[partition_id].data_name, "r");
		if (!filep) {
			printf("%s: Error: couldn't open %s for read\n", __func__,
						partitions[partition_id].data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}
#endif

		STORAGE_GET_TWO_ARGS
		uint32_t start_block = arg0;
		uint32_t num_blocks = arg1;
#ifdef ARCH_SEC_HW_STORAGE
		/* FIXME: use proper file read/write. */
		/* handle special boot image files */
		if (start_block >= BOOT_IMAGE_OFFSET * QSPI_SECTOR_SIZE) {
			/* FIXME: this is an ad hoc way to get the boot image address, by passing the
			 * address directly on argument.
			 */
			u32 address = start_block;
			// u32 message_count = boot_image_sizes[partition_id] / STORAGE_BLOCK_SIZE;
			uint8_t message_buf[STORAGE_BLOCK_SIZE + 48] __attribute__ ((aligned(64)));

			// for (u32 message = 0; message < message_count; message++) {
			partition_read_physical(address, STORAGE_BLOCK_SIZE, message_buf);
			write_data_to_queue(message_buf, Q_STORAGE_DATA_OUT);
			// }

			STORAGE_SET_ONE_RET(STORAGE_BLOCK_SIZE);
			return;
		}
#endif
		if (start_block + num_blocks > partitions[partition_id].size) {
			SEC_HW_DEBUG_HANG();
			printf("%s: Error: invalid args\n", __func__);
			STORAGE_SET_ONE_RET(0)
#ifndef ARCH_SEC_HW_STORAGE
			fop_close(filep);
#endif
			return;
		}
#ifndef ARCH_SEC_HW_STORAGE
		uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
		fop_seek(filep, seek_off, SEEK_SET);
#endif
		uint8_t data_buf[STORAGE_BLOCK_SIZE + 48] __attribute__ ((aligned(64)));
		uint32_t size = 0;
		for (uint32_t i = 0; i < num_blocks; i++) {
#ifndef ARCH_SEC_HW_STORAGE
			size += (uint32_t) fop_read(data_buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
#else
			size += partition_read(partition_id, 
									start_block + i,
									data_buf);
//			sleep(5);
#endif
			write_data_to_queue(data_buf, Q_STORAGE_DATA_OUT);
		}
		STORAGE_SET_ONE_RET(size);
#ifndef ARCH_SEC_HW_STORAGE
		fop_close(filep);
#endif
	} else if (buf[0] == STORAGE_OP_SET_KEY) {
		if (!is_queue_set_bound) {
			printf("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
			printf("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		if (partitions[partition_id].is_locked) {
			printf("%s: Error: can't set the key for a locked partition\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		STORAGE_GET_ZERO_ARGS_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			printf("%s: Error: incorrect key size\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		uint32_t ret = (uint32_t) set_partition_key(data, partition_id);
		STORAGE_SET_ONE_RET(ret)
	} else if (buf[0] == STORAGE_OP_UNLOCK) {
		STORAGE_GET_ZERO_ARGS_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			printf("%s: Error: incorrect key size (sent for unlocking)\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			while(1) sleep(1);
			return;
		}

		int partition_id = -1;

		for (int i = 0; i < NUM_PARTITIONS; i++) {
			int ret = unlock_partition(data, i);
			if (!ret) {
				partition_id = i;
				break;
			}			
		}

		if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
			STORAGE_SET_ONE_RET(ERR_EXIST)
			return;
		}

		if (partitions[partition_id].is_locked) {
			STORAGE_SET_ONE_RET(ERR_FAULT)
			return;
		}

		bound_partition = partition_id;
		is_queue_set_bound = true;

		STORAGE_SET_ONE_RET(0)
	} else if (buf[0] == STORAGE_OP_LOCK) {
		if (!is_queue_set_bound) {
			printf("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
			printf("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		partitions[partition_id].is_locked = true;
		bound_partition = -1;
		is_queue_set_bound = false;
			
		STORAGE_SET_ONE_RET(0)
	} else if (buf[0] == STORAGE_OP_WIPE) {
		if (!is_queue_set_bound) {
			printf("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
			printf("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}
		if (partitions[partition_id].is_locked) {
			printf("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}
		int ret = wipe_partition(partition_id);
		if (ret) {
			printf("%s: Error: couldn't wipe the partition\n", __func__);
			STORAGE_SET_ONE_RET(ERR_FAULT)
			return;
		}

		ret = remove_partition_key(partition_id);
		if (ret) {
			printf("%s: Error: couldn't remove partition key\n", __func__);
			STORAGE_SET_ONE_RET(ERR_FAULT)
			return;
		}

		bound_partition = -1;
		is_queue_set_bound = false;

		STORAGE_SET_ONE_RET(0)
	/* creates a new secure partition */
	/* FIXME: temp implementation */
	} else if (buf[0] == STORAGE_OP_CREATE_SECURE_PARTITION) {
		if (is_config_locked) {
			printf("%s: Error: config is locked (create partition op)\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			SEC_HW_DEBUG_HANG();
			return;
		}

		STORAGE_GET_ONE_ARG_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			printf("%s: Error: incorrect key size\n", __func__);
			STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
			SEC_HW_DEBUG_HANG();
			return;
		}
		uint32_t partition_size = arg0;

		int partition_id = -1;

		for (int i = 0; i < NUM_PARTITIONS; i++) {
			if (!partitions[i].is_created && partitions[i].size == partition_size) {
				partition_id = i;
				break;
			}
		}

		if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
			printf("%s: Error: no partitions with the requested size available\n", __func__);
			STORAGE_SET_TWO_RETS(ERR_AVAILABLE, 0)
			return;
		}

		int ret = set_partition_key(data, partition_id);
		if (ret) {
			STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
			SEC_HW_DEBUG_HANG();
			return;
		}

#ifndef ARCH_SEC_HW_STORAGE
		filep = fop_open(partitions[partition_id].create_name, "r+");
		if (!filep) {
			STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
			return;
		}

		fop_seek(filep, 0, SEEK_SET);
		uint32_t tag = 1;
		uint32_t size = (uint32_t) fop_write(&tag, sizeof(uint8_t), 4, filep);
		fop_close(filep);
#else
		uint8_t tag[4] __attribute__ ((aligned(64)));
		tag[0] = 1;
		uint32_t size = partition_write_header(partition_id,
											create_header_offset,
											4, tag);
#endif
		if (size != 4) {
			SEC_HW_DEBUG_HANG();
			STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
			if (size > 0) { /* partial write */
				/* wipe the file */
#ifndef ARCH_SEC_HW_STORAGE
				FILE *filep2 = fop_open(partitions[partition_id].create_name, "w");
				fop_close(filep2);
#else
				// FIXME: implement
//				partition_erase(partition_id, ERASE_HEADER);
#endif
			}
			return;
		}

		partitions[partition_id].is_created = true;

		/* FIXME: don't return the partition ID */
		STORAGE_SET_TWO_RETS(0, partition_id)
	} else if (buf[0] == STORAGE_OP_DELETE_SECURE_PARTITION) {
		if (is_config_locked) {
			printf("%s: Error: config is locked (delete partition op)\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		STORAGE_GET_ONE_ARG
		uint32_t partition_id = arg0;

		if (partition_id >= NUM_PARTITIONS) {
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		if (!partitions[partition_id].is_created) {
			printf("%s: Error: partition does not exist\n", __func__);
			STORAGE_SET_ONE_RET(ERR_EXIST)
			return;
		}

		if (is_queue_set_bound && (bound_partition == (int) partition_id)) {
			printf("%s: Error: partition currently bound to the queue set\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}
		if (partitions[partition_id].is_locked) {
			printf("%s: Error: can't delete a locked partition\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		partitions[partition_id].is_created = false;
		/* wipe the create and lock files of the partition */
#ifndef ARCH_SEC_HW_STORAGE
		FILE *filep2 = fop_open(partitions[partition_id].create_name, "w");
		fop_close(filep2);
		filep2 = fop_open(partitions[partition_id].lock_name, "w");
		fop_close(filep2);
		/* FIXME: do we need to wipe the partition content? */
#else
		// FIXME: implement
//		partition_erase(partition_id, ERASE_ALL);
#endif

		STORAGE_SET_ONE_RET(0)
	} else if (buf[0] == STORAGE_OP_SET_CONFIG_KEY) {
		if (is_config_locked) {
			printf("%s: Error: config is locked (set config key op)\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		STORAGE_GET_ZERO_ARGS_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			printf("%s: Error: incorrect config key size\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		for (int i = 0; i < STORAGE_KEY_SIZE; i++)
			config_key[i] = data[i];

		STORAGE_SET_ONE_RET(0)

	} else if (buf[0] == STORAGE_OP_UNLOCK_CONFIG) {
		if (!is_config_locked) {
			STORAGE_SET_ONE_RET(0)
			return;
		}

		STORAGE_GET_ZERO_ARGS_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			printf("%s: Error: incorrect key size (sent for unlocking config)\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		for (int i = 0; i < STORAGE_KEY_SIZE; i++) {
			if (config_key[i] != data[i]) {
				STORAGE_SET_ONE_RET(ERR_INVALID);
				return;
			}
		}

		is_config_locked = false;

		STORAGE_SET_ONE_RET(0)
	} else if (buf[0] == STORAGE_OP_LOCK_CONFIG) {
		is_config_locked = true;
		STORAGE_SET_ONE_RET(0)
#ifdef ARCH_SEC_HW_STORAGE
	} else if (buf[0] == STORAGE_OP_BOOT_REQ) {


#endif
	} else {
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}
}

#ifndef ARCH_SEC_HW_BOOT
int main(int argc, char **argv)
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: storage init\n", __func__);

	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error: storage data queue msg size must be equal to storage block size\n");
		return -1;
	}

	init_storage();
	storage_event_loop();
	close_storage();
}
#endif
