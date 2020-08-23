/* octopos storage code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include "arch/semaphore.h"
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/error.h>

#include "arch/mailbox_storage.h"


/* FIXME: determine partitions and their sizes dynamically. */
struct partition partitions[NUM_PARTITIONS];
uint32_t partition_sizes[NUM_PARTITIONS] = {1000, 2048, 100, 100, 100};

//bool is_queue_set_bound = false;
//int bound_partition = -1;

// int fd_out, fd_in, fd_intr;

/* Not all will be used */
// sem_t interrupts[NUM_QUEUES + 1];

///* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
//static void initialize_storage_space(void)
//{
//	for (int i = 0; i < (NUM_SEC_PARTITIONS + 1); i++) {
//		struct partition *partition;
//		int suffix = 0;
//		if (i == 0) {
//			partition = &main_partition;
//			partition->size = STORAGE_MAIN_PARTITION_SIZE;
//			suffix = 1;
//		} else {
//			partition = &sec_partitions[i - 1];
//			partition->size = STORAGE_SECURE_PARTITION_SIZE;
//			suffix = i + 1;
//		}
//
//		memset(partition->data_name, 0x0, 256);
//		sprintf(partition->data_name, "octopos_partition_%d_data", suffix);
//
//		memset(partition->create_name, 0x0, 256);
//		sprintf(partition->create_name, "octopos_partition_%d_create", suffix);
//
//		memset(partition->lock_name, 0x0, 256);
//		sprintf(partition->lock_name, "octopos_partition_%d_lock", suffix);
//
//		FILE *filep = fopen(partition->data_name, "r");
//		if (!filep) {
//			/* create empty file */
//			FILE *filep2 = fopen(partition->data_name, "w");
//			fclose(filep2);
//		}
//
//		/* Is partition created? */
//		filep = fopen(partition->create_name, "r");
//		if (!filep) {
//			/* create empty file */
//			FILE *filep2 = fopen(partition->create_name, "w");
//			fclose(filep2);
//			/* Also wipe lock info (which should not have any valid key anyway. */
//			filep2 = fopen(partition->lock_name, "w");
//			fclose(filep2);
//			partition->is_locked = false;
//			continue;
//		}
//
//		fseek(filep, 0, SEEK_SET);
//		uint32_t tag = 0;
//		uint32_t size = (uint32_t) fread(&tag, sizeof(uint8_t), 4, filep);
//		fclose(filep);
//		if (size == 4 && tag == 1) {
//			partition->is_created = true;
//		} else {
//			/* create empty file */
//			FILE *filep2 = fopen(partition->create_name, "w");
//			fclose(filep2);
//			/* Also wipe any key info. This should not normally happen. */
//			filep2 = fopen(partition->lock_name, "w");
//			fclose(filep2);
//			partition->is_locked = false;
//			continue;
//		}
//
//		/* lock partitions that have an active key */
//		filep = fopen(partition->lock_name, "r");
//		if (!filep) {
//			/* create empty file */
//			FILE *filep2 = fopen(partition->lock_name, "w");
//			fclose(filep2);
//			partition->is_locked = false;
//			continue;
//		}
//
//		uint8_t key[STORAGE_KEY_SIZE];
//		fseek(filep, 0, SEEK_SET);
//		size = (uint32_t) fread(key, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
//		fclose(filep);
//		if (size == STORAGE_KEY_SIZE) {
//			partition->is_locked = true;
//		} else {
//			/* wipe lock file */
//			FILE *filep2 = fopen(partition->lock_name, "w");
//			fclose(filep2);
//			partition->is_locked = false;
//		}
//	}
//}
//
//static int set_secure_partition_key(uint8_t *data, int partition_id)
//{
//	FILE *filep = fopen(sec_partitions[partition_id].lock_name, "r+");
//	if (!filep) {
//		printf("%s: Error: couldn't open %s\n", __func__, sec_partitions[partition_id].lock_name);
//		return ERR_FAULT;
//	}
//
//	fseek(filep, 0, SEEK_SET);
//	uint32_t size = (uint32_t) fwrite(data, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
//        fclose(filep);
//	if (size < STORAGE_KEY_SIZE) {
//		/* make sure to delete what was written */
//		filep = fopen(sec_partitions[partition_id].lock_name, "w");
//		fclose(filep);
//		return ERR_FAULT;
//	}
//
//	return 0;
//}
//
//static int remove_partition_key(int partition_id)
//{
//	FILE *filep = fopen(sec_partitions[partition_id].lock_name, "w");
//	if (!filep) {
//		printf("%s: Error: couldn't open %s\n", __func__, sec_partitions[partition_id].lock_name);
//		return ERR_FAULT;
//	}
//	fclose(filep);
//	return 0;
//}
//
//static int unlock_partition(uint8_t *data, int partition_id)
//{
//	uint8_t key[STORAGE_KEY_SIZE];
//	FILE *filep = fopen(sec_partitions[partition_id].lock_name, "r");
//	if (!filep) {
//		printf("%s: Error: couldn't open %s\n", __func__, sec_partitions[partition_id].lock_name);
//		return ERR_FAULT;
//	}
//
//	fseek(filep, 0, SEEK_SET);
//	uint32_t size = (uint32_t) fread(key, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
//        fclose(filep);
//	if (size != STORAGE_KEY_SIZE) {
//		/* TODO: if the key file is corrupted, then we might need to unlock, otherwise, we'll lose the partition. */
//		return ERR_FAULT;
//	}
//
//	for (int i = 0; i < STORAGE_KEY_SIZE; i++) {
//		if (key[i] != data[i])
//			return ERR_INVALID;
//	}
//
//	sec_partitions[partition_id].is_locked = false;
//	return 0;
//}
//
//static int wipe_partition(int partition_id)
//{
//	FILE *filep = fopen(sec_partitions[partition_id].data_name, "w");
//	if (!filep) {
//		printf("%s: Error: couldn't open %s\n", __func__, sec_partitions[partition_id].data_name);
//		return ERR_FAULT;
//	}
//	fclose(filep);
//	return 0;
//}
//
//static void send_response(uint8_t *buf, uint8_t queue_id)
//{
//	uint8_t opcode[2];
//
//	sem_wait(&interrupts[queue_id]);
//
//	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
//	opcode[1] = queue_id;
//	write(fd_out, opcode, 2);
//	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
//}
//
//static void read_data_from_queue(uint8_t *buf, uint8_t queue_id)
//{
//	uint8_t opcode[2];
//
//	sem_wait(&interrupts[queue_id]);
//
//	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
//	opcode[1] = queue_id;
//	write(fd_out, opcode, 2),
//	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
//}
//
//static void write_data_to_queue(uint8_t *buf, uint8_t queue_id)
//{
//	uint8_t opcode[2];
//
//	sem_wait(&interrupts[queue_id]);
//
//	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
//	opcode[1] = queue_id;
//	write(fd_out, opcode, 2),
//	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
//}
//
//static void process_request(uint8_t *buf)
//{
//	FILE *filep = NULL;
//
//	/* write */
//	if (buf[0] == STORAGE_OP_WRITE) {
//		if (main_partition.is_locked) {
//			printf("%s: Error: partition is locked\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//		filep = fopen(main_partition.data_name, "r+");
//		if (!filep) {
//			printf("%s: Error: couldn't open %s for write\n", __func__, main_partition.data_name);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//		STORAGE_GET_TWO_ARGS
//		int start_block = (int) arg0;
//		int num_blocks = (int) arg1;
//		if (start_block + num_blocks >= main_partition.size) {
//			printf("%s: Error: invalid args\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			fclose(filep);
//			return;
//		}
//		int seek_off = start_block * STORAGE_BLOCK_SIZE;
//		fseek(filep, seek_off, SEEK_SET);
//		uint8_t data_buf[STORAGE_BLOCK_SIZE];
//		uint32_t size = 0;
//		for (int i = 0; i < num_blocks; i++) {
//			read_data_from_queue(data_buf, Q_STORAGE_DATA_IN);
//			size += (uint32_t) fwrite(data_buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
//		}
//		STORAGE_SET_ONE_RET(size);
//		fclose(filep);
//	} else if (buf[0] == STORAGE_OP_READ) { /* read */
//		if (main_partition.is_locked) {
//			printf("%s: Error: partition is locked\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//		filep = fopen(main_partition.data_name, "r");
//		if (!filep) {
//			printf("%s: Error: couldn't open %s for read\n", __func__, main_partition.data_name);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//		STORAGE_GET_TWO_ARGS
//		int start_block = (int) arg0;
//		int num_blocks = (int) arg1;
//		if (start_block + num_blocks >= main_partition.size) {
//			printf("%s: Error: invalid args\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			fclose(filep);
//			return;
//		}
//		int seek_off = start_block * STORAGE_BLOCK_SIZE;
//		fseek(filep, seek_off, SEEK_SET);
//		uint8_t data_buf[STORAGE_BLOCK_SIZE];
//		uint32_t size = 0;
//		for (int i = 0; i < num_blocks; i++) {
//			size += (uint32_t) fread(data_buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
//			write_data_to_queue(data_buf, Q_STORAGE_DATA_OUT);
//		}
//		STORAGE_SET_ONE_RET(size);
//		fclose(filep);
//	/* creates a new secure partition */
//	/* FIXME: temp implementation */
//	} else if (buf[0] == STORAGE_OP_CREATE_SECURE_PARTITION) {
//		STORAGE_GET_ZERO_ARGS_DATA
//		if (data_size != STORAGE_KEY_SIZE) {
//			printf("%s: Error: incorrect key size\n", __func__);
//			STORAGE_SET_TWO_RETS(ERR_INVALID, 0)
//			return;
//		}
//
//		int partition_id = -1;
//
//		for (int i = 0; i < NUM_SEC_PARTITIONS; i++) {
//			if (!sec_partitions[i].is_created) {
//				partition_id = i;
//				break;
//			}
//		}
//
//		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
//			printf("%s: Error: no secure partitions available\n", __func__);
//			STORAGE_SET_TWO_RETS(ERR_AVAILABLE, 0)
//			return;
//		}
//
//		int ret = set_secure_partition_key(data, partition_id);
//		if (ret) {
//			STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
//			return;
//		}
//
//		filep = fopen(sec_partitions[partition_id].create_name, "r+");
//		if (!filep) {
//			STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
//			return;
//		}
//
//		fseek(filep, 0, SEEK_SET);
//		uint32_t tag = 1;
//		uint32_t size = (uint32_t) fwrite(&tag, sizeof(uint8_t), 4, filep);
//		fclose(filep);
//		if (size != 4) {
//			STORAGE_SET_TWO_RETS(ERR_FAULT, 0)
//			if (size > 0) { /* partial write */
//				/* wipe the file */
//				FILE *filep2 = fopen(sec_partitions[partition_id].create_name, "w");
//				fclose(filep2);
//			}
//			return;
//		}
//
//		sec_partitions[partition_id].is_created = true;
//
//		STORAGE_SET_TWO_RETS(0, partition_id)
//	} else if (buf[0] == STORAGE_OP_DELETE_SECURE_PARTITION) {
//		STORAGE_GET_ONE_ARG
//		uint32_t sec_partition_id = arg0;
//
//		if (sec_partition_id >= NUM_SEC_PARTITIONS) {
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		if (!sec_partitions[sec_partition_id].is_created) {
//			printf("%s: Error: secure partition does not exist\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_EXIST)
//			return;
//		}
//
//		if (is_queue_set_bound && (bound_partition == (int) sec_partition_id)) {
//			printf("%s: Error: secure partition currently bound to a queue set\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//		if (sec_partitions[sec_partition_id].is_locked) {
//			printf("%s: Error: can't delete a locked partition\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		sec_partitions[sec_partition_id].is_created = false;
//		/* wipe the create and lock files of the partition */
//		FILE *filep2 = fopen(sec_partitions[sec_partition_id].create_name, "w");
//		fclose(filep2);
//		filep2 = fopen(sec_partitions[sec_partition_id].lock_name, "w");
//		fclose(filep2);
//
//		STORAGE_SET_ONE_RET(0)
//	} else {
//		STORAGE_SET_ONE_RET(ERR_INVALID)
//		return;
//	}
//}
//
///* FIXME: there's duplicate code between process_request and this function */
//static void process_secure_request(uint8_t *buf)
//{
//	FILE *filep = NULL;
//
//	/* write */
//	if (buf[0] == STORAGE_OP_WRITE) {
//		if (!is_queue_set_bound) {
//			printf("%s: Error: no partition is bound to queue set\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//
//		int partition_id = bound_partition;
//
//		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
//			printf("%s: Error: invalid partition ID\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//
//		if (sec_partitions[partition_id].is_locked) {
//			printf("%s: Error: partition is locked\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//
//		filep = fopen(sec_partitions[partition_id].data_name, "r+");
//		if (!filep) {
//			printf("%s: Error: couldn't open %s for write\n", __func__, sec_partitions[partition_id].data_name);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//
//		STORAGE_GET_TWO_ARGS_DATA
//		if (((int) arg0) > sec_partitions[partition_id].size) {
//			printf("%s: Error: invalid block size\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			fclose(filep);
//			return;
//		}
//
//		int seek_off = (arg0 * STORAGE_BLOCK_SIZE) + arg1;
//		fseek(filep, seek_off, SEEK_SET);
//		uint32_t size = (uint32_t) fwrite(data, sizeof(uint8_t), data_size, filep);
//
//		STORAGE_SET_ONE_RET(size);
//		fclose(filep);
//	} else if (buf[0] == STORAGE_OP_READ) { /* read */
//		if (!is_queue_set_bound) {
//			printf("%s: Error: no partition is bound to queue set\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//
//		int partition_id = bound_partition;
//
//		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
//			printf("%s: Error: invalid partition ID\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//
//		if (sec_partitions[partition_id].is_locked) {
//			printf("%s: Error: partition is locked\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//
//		filep = fopen(sec_partitions[partition_id].data_name, "r");
//		if (!filep) {
//			printf("%s: Error: couldn't open %s for read\n", __func__, sec_partitions[partition_id].data_name);
//			STORAGE_SET_ONE_RET(0)
//			return;
//		}
//
//		STORAGE_GET_THREE_ARGS
//		if (((int) arg0) > sec_partitions[partition_id].size) {
//			printf("%s: Error: invalid block size\n", __func__);
//			STORAGE_SET_ONE_RET(0)
//			fclose(filep);
//			return;
//		}
//
//		uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];
//		int seek_off = (arg0 * STORAGE_BLOCK_SIZE) + arg1;
//		fseek(filep, seek_off, SEEK_SET);
//		uint32_t size = (uint32_t) fread(ret_buf, sizeof(uint8_t), arg2, filep);
//
//		STORAGE_SET_ONE_RET_DATA(size, ret_buf, size);
//		fclose(filep);
//	} else if (buf[0] == STORAGE_OP_SET_KEY) {
//		if (!is_queue_set_bound) {
//			printf("%s: Error: no partition is bound to queue set\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		int partition_id = bound_partition;
//
//		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
//			printf("%s: Error: invalid partition ID\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		if (sec_partitions[partition_id].is_locked) {
//			printf("%s: Error: can't set the key for a locked partition\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		STORAGE_GET_ZERO_ARGS_DATA
//		if (data_size != STORAGE_KEY_SIZE) {
//			printf("%s: Error: incorrect key size\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		uint32_t ret = (uint32_t) set_secure_partition_key(data, partition_id);
//		STORAGE_SET_ONE_RET(ret)
//	} else if (buf[0] == STORAGE_OP_UNLOCK) {
//		STORAGE_GET_ZERO_ARGS_DATA
//		if (data_size != STORAGE_KEY_SIZE) {
//			printf("%s: Error: incorrect key size (sent for unlocking)\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		int partition_id = -1;
//
//		for (int i = 0; i < NUM_SEC_PARTITIONS; i++) {
//			int ret = unlock_partition(data, i);
//			if (!ret) {
//				partition_id = i;
//				break;
//			}
//		}
//
//		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
//			STORAGE_SET_ONE_RET(ERR_EXIST)
//			return;
//		}
//
//		if (sec_partitions[partition_id].is_locked) {
//			STORAGE_SET_ONE_RET(ERR_FAULT)
//			return;
//		}
//
//		bound_partition = partition_id;
//		is_queue_set_bound = true;
//
//		STORAGE_SET_ONE_RET(0)
//	} else if (buf[0] == STORAGE_OP_LOCK) {
//		if (!is_queue_set_bound) {
//			printf("%s: Error: no partition is bound to queue set\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		int partition_id = bound_partition;
//
//		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
//			printf("%s: Error: invalid partition ID\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		sec_partitions[partition_id].is_locked = true;
//		bound_partition = -1;
//		is_queue_set_bound = false;
//
//		STORAGE_SET_ONE_RET(0)
//	} else if (buf[0] == STORAGE_OP_WIPE) {
//		if (!is_queue_set_bound) {
//			printf("%s: Error: no partition is bound to queue set\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//
//		int partition_id = bound_partition;
//
//		if (partition_id < 0 || partition_id >= NUM_SEC_PARTITIONS) {
//			printf("%s: Error: invalid partition ID\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//		if (sec_partitions[partition_id].is_locked) {
//			printf("%s: Error: partition is locked\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_INVALID)
//			return;
//		}
//		int ret = wipe_partition(partition_id);
//		if (ret) {
//			printf("%s: Error: couldn't wipe the partition\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_FAULT)
//			return;
//		}
//
//		ret = remove_partition_key(partition_id);
//		if (ret) {
//			printf("%s: Error: couldn't remove partition key\n", __func__);
//			STORAGE_SET_ONE_RET(ERR_FAULT)
//			return;
//		}
//
//		bound_partition = -1;
//		is_queue_set_bound = false;
//
//		STORAGE_SET_ONE_RET(0)
//	} else {
//		STORAGE_SET_ONE_RET(ERR_INVALID)
//		return;
//	}
//}

// static void *handle_mailbox_interrupts(void *data)
// {
// 	uint8_t interrupt;

// 	while (1) {
// 		read(fd_intr, &interrupt, 1);
// 		if (interrupt < 1 || interrupt > NUM_QUEUES) {
// 			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
// 			exit(-1);
// 		}
// 		sem_post(&interrupts[interrupt]);
// 		if (interrupt == Q_STORAGE_IN_2)
// 			sem_post(&interrupts[Q_STORAGE_CMD_IN]);
// 	}
// }

int main(int argc, char **argv)
{
	// uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	// uint8_t opcode[2];
	// pthread_t mailbox_thread;
	// int is_secure_queue = 0;

	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error: storage data queue msg size must be equal to storage block size\n");
		return -1;
	}

	init_storage();
	storage_event_loop();

	// sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, 0);
	// sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);
	// sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, 0);
	// sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, MAILBOX_QUEUE_SIZE);
	// sem_init(&interrupts[Q_STORAGE_IN_2], 0, 0);
	// sem_init(&interrupts[Q_STORAGE_OUT_2], 0, MAILBOX_QUEUE_SIZE);

	// initialize_storage_space();

	// mkfifo(FIFO_STORAGE_OUT, 0666);
	// mkfifo(FIFO_STORAGE_IN, 0666);
	// mkfifo(FIFO_STORAGE_INTR, 0666);

	// fd_out = open(FIFO_STORAGE_OUT, O_WRONLY);
	// fd_in = open(FIFO_STORAGE_IN, O_RDONLY);
	// fd_intr = open(FIFO_STORAGE_INTR, O_RDONLY);

	// int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	// if (ret) {
	// 	printf("Error: couldn't launch the mailbox thread\n");
	// 	return -1;
	// }

	// opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	
	// while(1) {
	// 	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	// 	sem_wait(&interrupts[Q_STORAGE_CMD_IN]);
	// 	sem_getvalue(&interrupts[Q_STORAGE_IN_2], &is_secure_queue);
	// 	if (!is_secure_queue) {
	// 		opcode[1] = Q_STORAGE_CMD_IN;
	// 		write(fd_out, opcode, 2); 
	// 		read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
	// 		process_request(buf);
	// 		send_response(buf, Q_STORAGE_CMD_OUT);
	// 	} else {
	// 		sem_wait(&interrupts[Q_STORAGE_IN_2]);
	// 		opcode[1] = Q_STORAGE_IN_2;
	// 		write(fd_out, opcode, 2); 
	// 		read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
	// 		process_secure_request(buf);
	// 		send_response(buf, Q_STORAGE_OUT_2);
	// 	}
	// }
	
	// pthread_cancel(mailbox_thread);
	// pthread_join(mailbox_thread, NULL);

	// close(fd_out);
	// close(fd_in);
	// close(fd_intr);

	// remove(FIFO_STORAGE_OUT);
	// remove(FIFO_STORAGE_IN);
	// remove(FIFO_STORAGE_INTR);
}
