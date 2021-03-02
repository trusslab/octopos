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
#include <octopos/io.h>
#include <octopos/error.h>

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
uint32_t partition_sizes[NUM_PARTITIONS] = {STORAGE_BOOT_PARTITION_SIZE,
	STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE, 100, 100, 100};

uint8_t bound_partition = 0xFF; /* 0xFF is an invalid partition number. */
uint8_t bound = 0;
uint8_t used = 0;
uint8_t authenticated = 0;

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
void initialize_storage_space(void)
{
	FILE *filep, *filep2;
	struct partition *partition;
	int suffix, i;
	uint32_t tag, size, j;

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

		memset(partition->lock_name, 0x0, 256);
		sprintf(partition->lock_name, "octopos_partition_%d_lock",
			suffix);

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
			/* Also wipe lock info (which should not have any valid
			 * key anyway.
			 */
			filep2 = fop_open(partition->lock_name, "w");
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
			filep2 = fop_open(partition->lock_name, "w");
			fop_close(filep2);
			continue;
		}

		///* lock partitions that have an active key */
		//filep = fop_open(partition->lock_name, "r");
		//if (!filep) {
		//	/* create empty file */
		//	FILE *filep2 = fop_open(partition->lock_name, "w");
		//	fop_close(filep2);
		//	continue;
		//}

		//uint8_t key[STORAGE_KEY_SIZE];
		//fop_seek(filep, 0, SEEK_SET);
		//size = (uint32_t) fop_read(key, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
		//fop_close(filep);
		//if (size == STORAGE_KEY_SIZE) {
		//	partition->is_locked = true;
		//} else {
		//	/* wipe lock file */
		//	FILE *filep2 = fop_open(partition->lock_name, "w");
		//	fop_close(filep2);
		//	partition->is_locked = false;
		//}
	}
}

static int set_partition_key(uint8_t *data, int partition_id)
{
	FILE *filep;
	uint32_t size;
	
	filep = fop_open(partitions[partition_id].lock_name, "r+");
	if (!filep) {
		printf("Error: %s: couldn't open %s\n", __func__,
		       partitions[partition_id].lock_name);
		return ERR_FAULT;
	}

	fop_seek(filep, 0, SEEK_SET);
	size = (uint32_t) fop_write(data, sizeof(uint8_t), STORAGE_KEY_SIZE,
				    filep);
	fop_close(filep);
	if (size < STORAGE_KEY_SIZE) {
		/* make sure to delete what was written */
		filep = fop_open(partitions[partition_id].lock_name, "w");
		fop_close(filep);
		return ERR_FAULT;
	}

	return 0;
}

static int remove_partition_key(int partition_id)
{
	FILE *filep = fop_open(partitions[partition_id].lock_name, "w");
	if (!filep) {
		printf("Error: %s: couldn't open %s\n", __func__,
		       partitions[partition_id].lock_name);
		return ERR_FAULT;
	}

	fop_close(filep);

	return 0;
}

static int authenticate_partition(int partition_id)
{
	/* FIXME: now: bring back */
	//uint8_t key[STORAGE_KEY_SIZE];
	//FILE *filep;
	//uint32_t size;
	//int i, ret;
	//
	//filep = fop_open(partitions[partition_id].lock_name, "r");
	//if (!filep) {
	//	printf("Error: %s: couldn't open %s\n", __func__,
	//	       partitions[partition_id].lock_name);
	//	return ERR_FAULT;
	//}

	//fop_seek(filep, 0, SEEK_SET);
	//size = (uint32_t) fop_read(key, sizeof(uint8_t), STORAGE_KEY_SIZE,
	//			   filep);
	//fop_close(filep);

	//if (size != STORAGE_KEY_SIZE) {
	//	printf("Error: %s: corrupted key data.\n", __func__);
	//	return ERR_FAULT;
	//}

	//ret = memcmp(key, data, STORAGE_KEY_SIZE);
	//if (ret)
	//	return ERR_INVALID;

	return 0;
}

static int wipe_partition(int partition_id)
{
#ifdef ARCH_SEC_HW_STORAGE
	FILINFO finfo;
	UINT NumBytesWritten = 0;
	uint8_t zero_buf[STORAGE_BLOCK_SIZE] = {0};
	f_stat(partitions[partition_id].data_name, &finfo);
#endif
	FILE *filep = fop_open(partitions[partition_id].data_name, "w");
	if (!filep) {
		printf("Error: %s: couldn't open %s\n", __func__,
		       partitions[partition_id].data_name);
		return ERR_FAULT;
	}
#ifdef ARCH_SEC_HW_STORAGE
	f_write(filep, (const void*)zero_buf, finfo.fsize, &NumBytesWritten);
#endif
	fop_close(filep);
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
	FILE *filep;
	uint8_t partition_id;
	uint32_t start_block, num_blocks, seek_off, size, i;
	uint8_t data_buf[STORAGE_BLOCK_SIZE];
	
	used = 1;

	if (!bound || !authenticated) {
		printf("Error: %s: the send_data op is invalid if bound (%d) "
		       "or authenticated (%d) is not set.\n", __func__,
		       bound, authenticated);
		STORAGE_SET_ONE_RET(0)
		return;
	}

	partition_id = bound_partition;

	/* Technically, an unnecessary check. */
	if (partition_id >= NUM_PARTITIONS) {
		printf("Error: %s: invalid ID for the bound partition\n",
		       __func__);
		STORAGE_SET_ONE_RET(0)
		return;
	}

	if (!partitions[partition_id].is_created) {
		printf("Error: %s: partition does not exist\n", __func__);
		STORAGE_SET_ONE_RET(0)
		return;
	}

	filep = fop_open(partitions[partition_id].data_name, "r+");
	if (!filep) {
		printf("Error: %s: couldn't open %s for write\n", __func__,
					partitions[partition_id].data_name);
		STORAGE_SET_ONE_RET(0)
		return;
	}

	STORAGE_GET_TWO_ARGS
	start_block = arg0;
	num_blocks = arg1;
	
	if (start_block + num_blocks > partitions[partition_id].size) {
		printf("Error: %s: invalid args\n", __func__);
		STORAGE_SET_ONE_RET(0)
		fop_close(filep);
		return;
	}

	seek_off = start_block * STORAGE_BLOCK_SIZE;
	fop_seek(filep, seek_off, SEEK_SET);
	size = 0;

	for (i = 0; i < num_blocks; i++) {
		read_data_from_queue(data_buf, Q_STORAGE_DATA_IN);
		size += (uint32_t) fop_write(data_buf, sizeof(uint8_t),
					     STORAGE_BLOCK_SIZE, filep);
	}

	STORAGE_SET_ONE_RET(size);
	fop_close(filep);
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
	FILE *filep;
	uint8_t partition_id;
	uint32_t start_block, num_blocks, seek_off, size, i;
	uint8_t data_buf[STORAGE_BLOCK_SIZE];

	used = 1;

	if (!bound || !authenticated) {
		printf("Error: %s: the receive_data op is invalid if bound (%d) "
		       "or authenticated (%d) is not set.\n", __func__,
		       bound, authenticated);
		STORAGE_SET_ONE_RET(0)
		return;
	}

	partition_id = bound_partition;
	
	/* Technically, an unnecessary check. */
	if (partition_id >= NUM_PARTITIONS) {
		printf("Error: %s: invalid ID for the bound partition\n",
		       __func__);
		STORAGE_SET_ONE_RET(0)
		return;
	}

	if (!partitions[partition_id].is_created) {
		printf("Error: %s: partition does not exist\n", __func__);
		STORAGE_SET_ONE_RET(0)
		return;
	}

	filep = fop_open(partitions[partition_id].data_name, "r");
	if (!filep) {
		printf("Error: %s: couldn't open %s for read\n", __func__,
					partitions[partition_id].data_name);
		STORAGE_SET_ONE_RET(0)
		return;
	}

	STORAGE_GET_TWO_ARGS
	start_block = arg0;
	num_blocks = arg1;
	
	if (start_block + num_blocks > partitions[partition_id].size) {
		printf("Error: %s: invalid args\n", __func__);
		STORAGE_SET_ONE_RET(0)
		fop_close(filep);
		return;
	}
	
	seek_off = start_block * STORAGE_BLOCK_SIZE;
	fop_seek(filep, seek_off, SEEK_SET);
	size = 0;
	
	for (i = 0; i < num_blocks; i++) {
		size += (uint32_t) fop_read(data_buf, sizeof(uint8_t),
					    STORAGE_BLOCK_SIZE, filep);
		write_data_to_queue(data_buf, Q_STORAGE_DATA_OUT);
	}

	STORAGE_SET_ONE_RET(size);
	fop_close(filep);
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
	FILE *filep, *filep2;
	uint32_t partition_size, tag, size;
	int partition_id, i, ret;

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

	partition_size = arg0;
	partition_id = -1;

	for (i = 0; i < NUM_PARTITIONS; i++) {
		if (!partitions[i].is_created &&
		    (partitions[i].size == partition_size)) {
			partition_id = i;
			break;
		}
	}

	if (partition_id < 0 || partition_id >= NUM_PARTITIONS) {
		printf("Error: %s: no partitions with the requested size "
		       "available\n", __func__);
		STORAGE_SET_ONE_RET(ERR_AVAILABLE)
		return;
	}

	ret = set_partition_key(data, partition_id);
	if (ret) {
		STORAGE_SET_ONE_RET(ERR_FAULT)
		return;
	}

	filep = fop_open(partitions[partition_id].create_name, "r+");
	if (!filep) {
		STORAGE_SET_ONE_RET(ERR_FAULT)
		return;
	}

	fop_seek(filep, 0, SEEK_SET);
	tag = 1;
	size = (uint32_t) fop_write(&tag, sizeof(uint8_t), 4, filep);
	fop_close(filep);
	if (size != 4) {
		STORAGE_SET_ONE_RET(ERR_FAULT)
		if (size > 0) { /* partial write */
			/* wipe the file */
			filep2 = fop_open(partitions[partition_id].create_name,
					  "w");
			fop_close(filep2);
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
	FILE *filep;
	uint32_t size;
	uint8_t num_partitions, partition_id;

	if (bound) {
		printf("Error: %s: the query_all_resources op cannot be used "
		       "when some partition is bound\n", __func__);
		char dummy;
		STORAGE_SET_ONE_RET_DATA(ERR_INVALID, &dummy, 0)
		return;
	}

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
			filep = fop_open(partitions[partition_id].lock_name,
					 "r");
			if (!filep) {
				printf("Error: %s: couldn't open %s\n", __func__,
				       partitions[partition_id].lock_name);
				char dummy;
				STORAGE_SET_ONE_RET_DATA(ERR_FAULT, &dummy, 0)
				return;
			}

			fop_seek(filep, 0, SEEK_SET);
			size = (uint32_t) fop_read(key, sizeof(uint8_t),
						   STORAGE_KEY_SIZE, filep);
			fop_close(filep);

			if (size != STORAGE_KEY_SIZE) {
				printf("Error: %s: corrupted key data.\n",
				       __func__);
				char dummy;
				STORAGE_SET_ONE_RET_DATA(ERR_FAULT, &dummy, 0)
				return;
			}

			memcpy(&data[5], key, STORAGE_KEY_SIZE);
				
			STORAGE_SET_ONE_RET_DATA(0, &data, 5 + STORAGE_KEY_SIZE)
		}
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
 */
static void storage_authenticate(uint8_t *buf)
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
		STORAGE_SET_ONE_RET(0)
		return;
	}

	if (!partitions[partition_id].is_created) {
		printf("Error: %s: partition does not exist\n", __func__);
		STORAGE_SET_ONE_RET(0)
		return;
	}

	ret = authenticate_partition(partition_id);
	if (!ret) {
		printf("Error: %s: authentication failed\n",__func__);
		STORAGE_SET_ONE_RET(ERR_PERMISSION)
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
		STORAGE_SET_ONE_RET(0)
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
		STORAGE_SET_ONE_RET(0)
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
	/* wipe the create file of the partition */
	filep = fop_open(partitions[partition_id].create_name, "w");
	fop_close(filep);

	STORAGE_SET_ONE_RET(0)
}

void process_request(uint8_t *buf)
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
		storage_authenticate(buf);
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

int main(int argc, char **argv)
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: storage init\n", __func__);

	/* Need to make sure msgs are big enough so that we don't overflow
	 * when processing incoming msgs and preparing outgoing ones.
	 */
	/* FIXME: find the smallest bound. 64 is conservative. */
	if (MAILBOX_QUEUE_MSG_SIZE < 64) {
		printf("Error: %s: MAILBOX_QUEUE_MSG_SIZE is too small (%d).\n",
		       __func__, MAILBOX_QUEUE_MSG_SIZE);
		return -1;
	}

	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error: storage data queue msg size must be equal to "
		       "storage block size\n");
		return -1;
	}

	if (STORAGE_KEY_SIZE != TPM_EXTEND_HASH_SIZE) {
		printf("Error: storage key size must be equal to the TPM "
		       "extend hash size\n");
		return -1;
	}

	init_storage();
	storage_event_loop();
	close_storage();
}
