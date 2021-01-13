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
#include "ff.h"
#include "arch/sec_hw.h"
#define FILE FIL
#define	SEEK_SET	0

FIL* fop_open(const char *filename, const char *mode)
{
	FIL* filep = (FIL*) malloc(sizeof(FIL));
	BYTE _mode;
	FRESULT result;

	if (strcmp(mode, "r") == 0) {
		_mode = FA_READ;
	} else if (strcmp(mode, "r+") == 0) {
		_mode = FA_READ | FA_WRITE;
	} else if (strcmp(mode, "w") == 0) {
		_mode = FA_CREATE_ALWAYS | FA_WRITE;
	} else if (strcmp(mode, "w+") == 0) {
		_mode = FA_CREATE_ALWAYS | FA_WRITE | FA_READ;
	} else if (strcmp(mode, "a") == 0) {
		_mode = FA_OPEN_APPEND | FA_WRITE;
	} else if (strcmp(mode, "a+") == 0) {
		_mode = FA_OPEN_APPEND | FA_WRITE | FA_READ;
	} else if (strcmp(mode, "wx") == 0) {
		_mode = FA_CREATE_NEW | FA_WRITE;
	} else if (strcmp(mode, "w+x") == 0) {
		_mode = FA_CREATE_NEW | FA_WRITE | FA_READ;
	} else {
		return NULL;
	}
	
	result = f_open(filep, filename, _mode);
	if (result == FR_OK) {
		return filep;
	} else {
		return NULL;
	}

}

int fop_close(FIL *filep)
{
	FRESULT result;

	if (!filep) {
		SEC_HW_DEBUG_HANG();
		return ERR_INVALID;
	}

	result = f_close(filep);
	free(filep);
	if (result == FR_OK) {
		return 0;
	} else {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}
}

int fop_seek(FIL *filep, long int offset, int origin)
{
	FRESULT result;

	if (origin != SEEK_SET) {
		SEC_HW_DEBUG_HANG();
		return ERR_INVALID;
	}

	result = f_lseek(filep, offset);
	if (result == FR_OK) {
		return 0;
	} else {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}
}

size_t fop_read(void *ptr, size_t size, size_t count, FIL *filep)
{
	FRESULT result;
	UINT NumBytesRead = 0;
	UINT _size = size * count;

	result = f_read(filep, ptr, _size, &NumBytesRead);
	if (result == FR_OK) {
		return (size_t) NumBytesRead;
	} else {
		SEC_HW_DEBUG_HANG();
		return 0;
	}
}

size_t fop_write(void *ptr, size_t size, size_t count, FIL *filep)
{
	FRESULT result;
	UINT NumBytesWrite = 0;
	UINT _size = size * count;

	result = f_write(filep, ptr, _size, &NumBytesWrite);
	if (result == FR_OK) {
		return (size_t) NumBytesWrite;
	} else {
		SEC_HW_DEBUG_HANG();
		return 0;
	}
}
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
	STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE, 100, 100, 100};

bool is_queue_set_bound = false;
int bound_partition = -1;

uint8_t config_key[STORAGE_KEY_SIZE];
bool is_config_locked = false;

#ifdef ARCH_SEC_HW_STORAGE
// FIXME: Move to a header file
extern u8 ReadCmd;
extern u8 WriteCmd;
int FlashErase(u32 Address, u32 ByteCount, u8 *WriteBfrPtr);
int FlashWrite(u32 Address, u32 ByteCount, u8 Command,
				u8 *WriteBfrPtr);
int FlashRead(u32 Address, u32 ByteCount, u8 Command,
				u8 *WriteBfrPtr, u8 *ReadBfrPtr);

/* partition creation info and locks are saved in headers */
/* the first 1MB is reserved for headers */
#define header_size 1024 * 64
#define data_offset 1024 * 1024 * 1 

#define create_header_offset 0
#define lock_header_offset 15

// FIXME: Copied from qspi driver
#define DATA_OFFSET		5 /* Start of Data for Read/Write */
#define DUMMY_SIZE		1 /* Number of dummy bytes for fast, dual and quad reads */

#define PAGE_SIZE		512 /* ZCU106 flash (micron) page size is 512. 
							 * other board may have page size up to 1024. 
							 */

#define QSPI_BUF_SIZE	PAGE_SIZE + (DATA_OFFSET + DUMMY_SIZE) * 8
u8 CmdBfr[8];

#define is_aligned_64(PTR) \
	(((uintptr_t)(const void *)(PTR)) % 64 == 0)

#define ERASE_HEADER	0x10
#define ERASE_DATA		0x01
#define ERASE_ALL		0x11

static int get_partition_data_address(int partition_id)
{
	int i;
	u32 data_address = data_offset;

	for (i = 0; i < partition_id; i++) {
		data_address += partition_sizes[i];
	}

	return data_address;
}

static int partition_erase(int partition_id, int part)
{
	struct partition *partition;
	u32 header_address, data_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	partition = &partitions[partition_id];
	header_address = partition_id * header_size;
	data_address = get_partition_data_address(partition_id);

	if (part & ERASE_HEADER) {
		/* erase partition header */
		status = FlashErase(header_address, header_size, CmdBfr);
		if (status != XST_SUCCESS) {
			SEC_HW_DEBUG_HANG();
			return ERR_FAULT;
		}	
	}


	if (part & ERASE_DATA) {
		/* erase partition data */
		status = FlashErase(data_address, partition->size, CmdBfr);
		if (status != XST_SUCCESS) {
			SEC_HW_DEBUG_HANG();
			return ERR_FAULT;
		}
	}

	return 0;
}

static int partition_reset_key(int partition_id)
{
	u32 header_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	header_address = partition_id * header_size;

	/* erase partition header */
	status = FlashErase(header_address + lock_header_offset, 
						header_size - lock_header_offset, 
						CmdBfr);

	if (status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}	

	return 0;
}

static int partition_read_header(int partition_id, u32 offset, u32 length, void *ptr)
{
	u32 header_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	if (offset + length > header_size)
		return ERR_INVALID;

	if (!is_aligned_64(ptr)) {
		SEC_HW_DEBUG_HANG();
		return ERR_INVALID;
	}

	header_address = partition_id * header_size;

	/* read partition header */
	status = FlashRead(header_address + offset, 
					length, ReadCmd, 
					CmdBfr, 
					(u8 *) ptr);
	if (status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	return length;
}

static int partition_read(int partition_id, u32 offset, u32 length, void *ptr)
{
	u32 data_address, status;
	struct partition *partition;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	partition = &partitions[partition_id];
	if (offset + length > partition->size)
		return ERR_INVALID;

	if (!is_aligned_64(ptr)) {
		SEC_HW_DEBUG_HANG();
		return ERR_INVALID;
	}

	data_address = get_partition_data_address(partition_id);

	/* read partition header */
	status = FlashRead(data_address + offset, 
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

static int partition_write_header(int partition_id, u32 offset, u32 length, void *ptr)
{
	u32 header_address, status;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	if (offset + length > header_size)
		return ERR_INVALID;

	header_address = partition_id * header_size;

	/* read partition header */
	status = FlashWrite(header_address + offset, length, WriteCmd, (u8 *) ptr);
	if (status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	return length;
}

static int partition_write(int partition_id, u32 offset, u32 length, void *ptr)
{
	u32 data_address, status;
	struct partition *partition;

	if (partition_id >= NUM_PARTITIONS)
		return ERR_INVALID;

	partition = &partitions[partition_id];
	if (offset + length > partition->size)
		return ERR_INVALID;

	data_address = get_partition_data_address(partition_id);

	/* read partition header */
	status = FlashWrite(data_address + offset, length, WriteCmd, (u8 *) ptr);
	if (status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return ERR_FAULT;
	}

	return length;
}
#endif

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
void initialize_storage_space(void)
{
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
		uint8_t tag[4] __attribute__ ((aligned(64)));
		uint32_t size = partition_read_header(i, create_header_offset, 4, tag);
		if (size == 4 && *((int*) tag) == 1) {
			partition->is_created = true;
		} else {
			partition_erase(i, ERASE_ALL);
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
		partition_reset_key(partition_id);
		return ERR_FAULT;
	}
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
		partition_reset_key(partition_id);
	} else {
		return ERR_FAULT;
	}
#endif
	return 0;
}

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
	uint8_t key[STORAGE_KEY_SIZE] __attribute__ ((aligned(64)));
	uint32_t size = partition_read_header(partition_id,
										lock_header_offset,
										STORAGE_KEY_SIZE,
										key);
#endif
	if (size != STORAGE_KEY_SIZE) {
		/* TODO: if the key file is corrupted, then we might need to unlock, otherwise, we'll lose the partition. */
		return ERR_FAULT;
	}

	for (int i = 0; i < STORAGE_KEY_SIZE; i++) {
		if (key[i] != data[i])
			return ERR_INVALID;
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
	partition_erase(partition_id, ERASE_DATA);
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
			printf("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
			printf("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		if (partitions[partition_id].is_locked) {
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
			printf("%s: Error: invalid args\n", __func__);
			STORAGE_SET_ONE_RET(0)
#ifndef ARCH_SEC_HW_STORAGE
			fop_close(filep);
#endif
			return;
		}
		uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
#ifndef ARCH_SEC_HW_STORAGE
		fop_seek(filep, seek_off, SEEK_SET);
#endif
		uint8_t data_buf[STORAGE_BLOCK_SIZE];
		uint32_t size = 0;
		for (uint32_t i = 0; i < num_blocks; i++) {
			read_data_from_queue(data_buf, Q_STORAGE_DATA_IN);
#ifndef ARCH_SEC_HW_STORAGE
			size += (uint32_t) fop_write(data_buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
#else
			size += partition_write(partition_id, 
									seek_off + i * STORAGE_BLOCK_SIZE, 
									STORAGE_BLOCK_SIZE, 
									data_buf);
#endif
		}
		STORAGE_SET_ONE_RET(size);
#ifndef ARCH_SEC_HW_STORAGE
		fop_close(filep);
#endif
	} else if (buf[0] == STORAGE_OP_READ) { /* read */
		if (!is_queue_set_bound) {
			printf("%s: Error: no partition is bound to queue set\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		int partition_id = bound_partition;

		if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
			printf("%s: Error: invalid partition ID\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}

		if (partitions[partition_id].is_locked) {
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
		if (start_block + num_blocks > partitions[partition_id].size) {
			printf("%s: Error: invalid args\n", __func__);
			STORAGE_SET_ONE_RET(0)
#ifndef ARCH_SEC_HW_STORAGE
			fop_close(filep);
#endif
			return;
		}
		uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
#ifndef ARCH_SEC_HW_STORAGE
		fop_seek(filep, seek_off, SEEK_SET);
#endif
		uint8_t data_buf[STORAGE_BLOCK_SIZE] __attribute__ ((aligned(64)));
		uint32_t size = 0;
		for (uint32_t i = 0; i < num_blocks; i++) {
#ifndef ARCH_SEC_HW_STORAGE
			size += (uint32_t) fop_read(data_buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
#else
			size += partition_read(partition_id, 
									seek_off + i * STORAGE_BLOCK_SIZE, 
									STORAGE_BLOCK_SIZE, 
									data_buf);
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
			SEC_HW_DEBUG_HANG();
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
#endif
		uint32_t tag = 1;
#ifndef ARCH_SEC_HW_STORAGE
		uint32_t size = (uint32_t) fop_write(&tag, sizeof(uint8_t), 4, filep);
		fop_close(filep);
#else
		uint32_t size = partition_write_header(partition_id,
											create_header_offset,
											4,
											&tag);
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
				partition_erase(partition_id, ERASE_HEADER);
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
		partition_erase(partition_id, ERASE_ALL);
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
	} else {
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}
}

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
