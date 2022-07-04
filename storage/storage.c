/* octopos storage code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#ifndef ARCH_SEC_HW_STORAGE
/* Note: unistd.h conflicts with PmodSD.h */
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <tpm/tpm.h>
#else
#include "xil_cache.h"
#include "arch/sec_hw.h"
#include "arch/semaphore.h"
#include "PmodSD.h"
#include "arch/pmod_fop.h"
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
	DESERIALIZE_32(&arg0, &buf[1])	\

#define STORAGE_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	DESERIALIZE_32(&arg0, &buf[1])	\
	DESERIALIZE_32(&arg1, &buf[5])	\

#define STORAGE_GET_THREE_ARGS		\
	uint32_t arg0, arg1, arg2;	\
	DESERIALIZE_32(&arg0, &buf[1])	\
	DESERIALIZE_32(&arg1, &buf[5])	\
	DESERIALIZE_32(&arg2, &buf[9])	\

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
	DESERIALIZE_32(&arg0, &buf[1])	\
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
uint32_t partition_sizes[NUM_PARTITIONS] = {STORAGE_BOOT_PARTITION_SIZE,
	STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE, 100, 100, 100, 100};

#ifdef ARCH_SEC_HW
unsigned int partition_base[NUM_PARTITIONS] = {
	RAM_ROOT_PARTITION_BASE,
	RAM_UNTRUSTED_PARTITION_BASE,
	RAM_ENCLAVE_PARTITION_1_BASE,
	RAM_ENCLAVE_PARTITION_2_BASE,
	RAM_ENCLAVE_PARTITION_3_BASE,
	RAM_ENCLAVE_PARTITION_4_BASE
};
#endif
	
// // DEBUG>>>
// extern long long global_counter;
// // DEBUG<<<

uint8_t bound_partition = 0xFF; /* 0xFF is an invalid partition number. */
uint8_t bound = 0;
uint8_t used = 0;
uint8_t authenticated = 0;

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
void initialize_storage_space(void)
{	
#ifdef ARCH_UMODE
	FILE *filep, *filep2;
#endif
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

#ifdef ARCH_UMODE
		memset(partition->data_name, 0x0, 256);
		sprintf(partition->data_name, "octopos_partition_%d_data",
			suffix);

		memset(partition->create_name, 0x0, 256);
		sprintf(partition->create_name, "octopos_partition_%d_create",
			suffix);

		memset(partition->keys_name, 0x0, 256);
		sprintf(partition->keys_name, "octopos_partition_%d_keys",
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
		tag = *((uint32_t *) RAM_ROOT_PARTITION_METADATA_BASE 
			+ i * STORAGE_METADATA_SIZE);
		if (tag == 1)
			partition->is_created = 1;
#endif
	}
}

static int set_partition_key(uint8_t *data, int partition_id)
{
#ifdef ARCH_UMODE
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
	/* FIXME: make metadata size into a macro. metadata is now 
	 * 64 bytes per partition, 32 bytes for tags and 32 bytes for key 
	 */
	memcpy((void *) RAM_ROOT_PARTITION_METADATA_BASE 
			+ partition_id * STORAGE_METADATA_SIZE + 32,
			data, STORAGE_KEY_SIZE);
#endif

	return 0;
}

static int remove_partition_key(int partition_id)
{
#ifdef ARCH_UMODE
	FILE *filep = fop_open(partitions[partition_id].keys_name, "w");
	if (!filep) {
		printf("Error: %s: couldn't open %s\n", __func__,
		       partitions[partition_id].keys_name);
		return ERR_FAULT;
	}

	fop_close(filep);
#else
	memset((void *) RAM_ROOT_PARTITION_METADATA_BASE 
			+ partition_id * STORAGE_METADATA_SIZE + 32,
			0, STORAGE_KEY_SIZE);
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
#ifdef ARCH_UMODE
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
	printf("Wipe %d\r\n", partition_id);
	memset((void *) partition_base[partition_id],  
		0, partition_sizes[partition_id]);
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

// void * Memcpy(void* dst, const void* src, unsigned int cnt)
// {
//     char *pszDest = (char *)dst;
//     const char *pszSource =( const char*)src;
//     if((pszDest!= NULL) && (pszSource!= NULL))
//     {
//         while(cnt) //till cnt
//         {
//             //Copy byte by byte
//             *(pszDest++)= *(pszSource++);
//             --cnt;
//         }
//     }
//     return dst;
// }

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
#ifndef ARCH_SEC_HW
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

#ifndef ARCH_SEC_HW
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
#ifndef ARCH_SEC_HW
		fop_close(filep);
#endif
		return;
	}

	seek_off = start_block * STORAGE_BLOCK_SIZE;
#ifndef ARCH_SEC_HW
	fop_seek(filep, seek_off, SEEK_SET);
#endif
	size = 0;

	for (i = 0; i < num_blocks; i++) {
		read_data_from_queue(data_buf, Q_STORAGE_DATA_IN);
#ifndef ARCH_SEC_HW
		size += (uint32_t) fop_write(data_buf, sizeof(uint8_t),
					     STORAGE_BLOCK_SIZE, filep);
#else
		memcpy((void *) (partition_base[partition_id] +
			seek_off + i * STORAGE_BLOCK_SIZE),
			data_buf, STORAGE_BLOCK_SIZE);
		size += STORAGE_BLOCK_SIZE;
//		printf("tx %d %d\r\n", partition_id, i);
#endif
	}

	STORAGE_SET_TWO_RETS(0, size)
#ifndef ARCH_SEC_HW
	fop_close(filep);
#endif
}

// #include "xil_cache.h"

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
#ifndef ARCH_SEC_HW
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

#ifndef ARCH_SEC_HW
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

	if (start_block + num_blocks > partitions[partition_id].size) {
		printf("Error: %s: invalid args\n", __func__);
		STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
#ifndef ARCH_SEC_HW
		fop_close(filep);
#endif
		return;
	}
	
	seek_off = start_block * STORAGE_BLOCK_SIZE;
#ifndef ARCH_SEC_HW
	fop_seek(filep, seek_off, SEEK_SET);
#endif
	size = 0;
	
	for (i = 0; i < num_blocks; i++) {
#ifndef ARCH_SEC_HW
		size += (uint32_t) fop_read(data_buf, sizeof(uint8_t),
					    STORAGE_BLOCK_SIZE, filep);
#else
		// if (partition_id == 2) {
		// 	// memset(data_buf, 0x67, STORAGE_BLOCK_SIZE);
		// 	// memcpy(
		// 	// 	(void *) (partition_base[partition_id] + 
		// 	// 	seek_off + i * STORAGE_BLOCK_SIZE), 
		// 	// 	data_buf, STORAGE_BLOCK_SIZE);

		// 	// for (int jj = 0; jj < 100; jj++)
		// 	// memcpy(data_buf, 
		// 	// 	(void *) (partition_base[1] + 500 * STORAGE_BLOCK_SIZE),
		// 	// 	STORAGE_BLOCK_SIZE);

		// 	// microblaze_invalidate_dcache();
		// 	for (int jj = 0; jj < 1; jj++)
		// 		memcpy(data_buf, 
		// 		(void *) (partition_base[1] + 
		// 		(i + jj) * STORAGE_BLOCK_SIZE),
		// 		STORAGE_BLOCK_SIZE);
		// } else {
		// // DEBUG
		// global_counter = 0;
			memcpy(data_buf, 
				(void *) (partition_base[partition_id] + 
				seek_off + i * STORAGE_BLOCK_SIZE),
				STORAGE_BLOCK_SIZE);
		// }
		// // DEBUG
		// printf("%d\r\n", global_counter);
		size += STORAGE_BLOCK_SIZE;
#endif
		write_data_to_queue(data_buf, Q_STORAGE_DATA_OUT);
	}

	STORAGE_SET_TWO_RETS(0, size)
#ifndef ARCH_SEC_HW
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
#ifndef ARCH_SEC_HW
	FILE *filep, *filep2;
#endif
	uint32_t partition_id, tag, size;
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

#ifndef ARCH_SEC_HW
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
#else
	*((uint32_t *) RAM_ROOT_PARTITION_METADATA_BASE 
		+ partition_id * STORAGE_METADATA_SIZE) = 1;
#endif

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
#ifndef ARCH_SEC_HW
	FILE *filep;
#endif
	uint32_t size;
	uint32_t num_partitions;
	uint8_t partition_id;

/* FIXME: sec_hw doesn't support storage domain reboot. */
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

			if (size != STORAGE_KEY_SIZE) {
				printf("Error: %s: corrupted key data.\n",
				       __func__);
				char dummy;
				STORAGE_SET_ONE_RET_DATA(ERR_FAULT, &dummy, 0)
				return;
			}
#else
			/* FIXME: key not set */
			memset(key, 0x0, STORAGE_KEY_SIZE);
#endif
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
#ifndef ARCH_SEC_HW
	FILE *filep;
#endif

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

	/* wipe the create file of the partition */
#ifndef ARCH_SEC_HW
	filep = fop_open(partitions[partition_id].create_name, "w");
	fop_close(filep);
#else
	memset((void *) RAM_ROOT_PARTITION_METADATA_BASE 
			+ partition_id * STORAGE_METADATA_SIZE,
			0, STORAGE_METADATA_SIZE);
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

//void mem_test() __attribute__((aligned, section("memaccess")));

// void mem_test()
// {
//         for (u32 i = 0; i < 0xfffffff; i+=1) {
//                 *((unsigned char *) 0x30000000 + i) = 0xDE;
//                 // debug
// //                if (i % 4 ==0) while(1);
//                 if (i % 0x10000 == 0)
//                         printf("%08x\r\n", i+0x30000000);
//                 if (*((unsigned char *) 0x30000000 + i) != 0xDE) {
//                 	printf("%08x wrong (%02x)\r\n", i+0x30000000, *((unsigned char *) 0x30000000 + i));
//                     while(1);
//                 }
//         }

//         return;

// 		memset((void*) 0x30000000, 0xac, 0xffffff);
// 		printf("%08x\r\n", *((u32*) 0x30ff0000));
// 		while(1);
// }

/* 
void raw_memory_benchmark()
{
	uint8_t bram_buffer[512];
	memset(&bram_buffer[0], 0xF0, 512);

	printf("write start\r\n");
	for (int i = 0; i < 2000; i++) {
		memcpy((void*) 0x30000000 + i * 512, &bram_buffer[0], 512);
	}
	printf("write end\r\n");

	printf("read start\r\n");
	for (int i = 0; i < 2000; i++) {
		memcpy(&bram_buffer[0], (void*) 0x30000000 + i * 512, 512);
	}
	printf("read end\r\n");
	while(1){};
}
*/

#ifndef ARCH_SEC_HW_BOOT
int main(int argc, char **argv)
{
#ifdef ARCH_SEC_HW
//	Xil_DCacheFlush();
//	Xil_ICacheInvalidate();
//	Xil_ICacheEnable();
//	Xil_DCacheEnable();
#endif

	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: storage init\n", __func__);

	/* raw_memory_benchmark(); */

#ifdef ARCH_SEC_HW
	Xil_Out32(
		XPAR_STORAGE_SUBSYSTEM_PMODSD_0_AXI_LITE_SPI_BASEADDR + 0x40,
		0x0000000A
		);
#endif

#ifndef ARCH_SEC_HW
	enforce_running_process(P_STORAGE);
#endif

	init_storage();
	storage_event_loop();
	close_storage();
}
#endif
