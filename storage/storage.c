/* octopos storage code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/error.h>

#define STORAGE_SET_ONE_RET(ret0)	\
	*((uint32_t *) &buf[0]) = ret0; \

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

#define STORAGE_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	arg0 = *((uint32_t *) &buf[1]); \
	arg1 = *((uint32_t *) &buf[5]); \

#define STORAGE_GET_THREE_ARGS		\
	uint32_t arg0, arg1, arg2;	\
	arg0 = *((uint32_t *) &buf[1]); \
	arg1 = *((uint32_t *) &buf[5]); \
	arg2 = *((uint32_t *) &buf[9]);\

#define STORAGE_GET_TWO_ARGS_DATA				\
	uint32_t arg0, arg1;					\
	uint8_t data_size, *data;				\
	arg0 = *((uint32_t *) &buf[1]);				\
	arg1 = *((uint32_t *) &buf[5]);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 10;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data_size = buf[9];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data = &buf[10];					\

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
	data = &buf[2];

/* partition information */
struct partition {
	int size; /* in blocks */
	char data_name[256];
	char lock_name[256];
	bool is_locked;
};

#define NUM_PARTITIONS		2
struct partition partitions[NUM_PARTITIONS];

int fd_out, fd_in, fd_intr;

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
static void initialize_storage_space(void)
{
	partitions[0].size = STORAGE_MAIN_PARTITION_SIZE;
	memset(partitions[0].data_name, 0x0, 256);
	strcpy(partitions[0].data_name, "octopos_partition_1_data");
	memset(partitions[0].lock_name, 0x0, 256);
	strcpy(partitions[0].lock_name, "octopos_partition_1_lock");

	partitions[1].size = 20;
	memset(partitions[1].data_name, 0x0, 256);
	strcpy(partitions[1].data_name, "octopos_partition_2_data");
	memset(partitions[1].lock_name, 0x0, 256);
	strcpy(partitions[1].lock_name, "octopos_partition_2_lock");

	for (int i = 0; i < NUM_PARTITIONS; i++) {
		FILE *filep = fopen(partitions[i].data_name, "r");
		if (!filep) {
			/* create empty file */
			FILE *filep2 = fopen(partitions[i].data_name, "w");
			fclose(filep2);
		}

		/* lock partitions that have an active key */
		filep = fopen(partitions[i].lock_name, "r");
		if (!filep) {
			/* create empty file */
			FILE *filep2 = fopen(partitions[i].lock_name, "w");
			fclose(filep2);
			partitions[i].is_locked = false;
			continue;
		}

		uint8_t key[STORAGE_KEY_SIZE];
		fseek(filep, 0, SEEK_SET);
		uint32_t size = (uint32_t) fread(key, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
		fclose(filep);
		if (size == STORAGE_KEY_SIZE)
			partitions[i].is_locked = true;
		else
			partitions[i].is_locked = false;
	}
}

static int set_partition_key(uint8_t *data, int partition_id)
{
	FILE *filep = fopen(partitions[partition_id].lock_name, "r+");
	if (!filep) {
		printf("%s: Error: couldn't open %s\n", __func__, partitions[partition_id].lock_name);
		return ERR_FAULT;
	}

	fseek(filep, 0, SEEK_SET);
	uint32_t size = (uint32_t) fwrite(data, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
        fclose(filep);
	if (size < STORAGE_KEY_SIZE) {
		/* make sure to delete what was written */
		filep = fopen(partitions[partition_id].lock_name, "w");
		fclose(filep);
		return ERR_FAULT;
	}

	return 0;
}

static int remove_partition_key(int partition_id)
{
	FILE *filep = fopen(partitions[partition_id].lock_name, "w");
	if (!filep) {
		printf("%s: Error: couldn't open %s\n", __func__, partitions[partition_id].lock_name);
		return ERR_FAULT;
	}
	fclose(filep);
	return 0;
}

static int unlock_partition(uint8_t *data, int partition_id)
{
	uint8_t key[STORAGE_KEY_SIZE];
	FILE *filep = fopen(partitions[partition_id].lock_name, "r");
	if (!filep) {
		printf("%s: Error: couldn't open %s\n", __func__, partitions[partition_id].lock_name);
		return ERR_FAULT;
	}

	fseek(filep, 0, SEEK_SET);
	uint32_t size = (uint32_t) fread(key, sizeof(uint8_t), STORAGE_KEY_SIZE, filep);
        fclose(filep);
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
	FILE *filep = fopen(partitions[partition_id].data_name, "w");
	if (!filep) {
		printf("%s: Error: couldn't open %s\n", __func__, partitions[partition_id].data_name);
		return ERR_FAULT;
	}
	fclose(filep);
	return 0;
}

static void send_response(uint8_t *buf, uint8_t queue_id)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void read_data_from_queue(uint8_t *buf, uint8_t queue_id)
{
	uint8_t opcode[2], interrupt;

	read(fd_intr, &interrupt, 1);
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

static void write_data_to_queue(uint8_t *buf, uint8_t queue_id)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2), 
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

static void process_request(uint8_t *buf, int partition_id)
{
	FILE *filep = NULL;

	/* write */
	if (buf[0] == STORAGE_OP_WRITE) {
		if (partitions[partition_id].is_locked) {
			printf("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		filep = fopen(partitions[partition_id].data_name, "r+");
		if (!filep) {
			printf("%s: Error: couldn't open %s for write\n", __func__, partitions[partition_id].data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_TWO_ARGS
		int start_block = (int) arg0;
		int num_blocks = (int) arg1;
		if (start_block + num_blocks >= partitions[partition_id].size) {
			printf("%s: Error: invalid args\n", __func__);
			STORAGE_SET_ONE_RET(0)
			fclose(filep);
			return;
		}
		int seek_off = start_block * STORAGE_BLOCK_SIZE;
		fseek(filep, seek_off, SEEK_SET);
		uint8_t data_buf[STORAGE_BLOCK_SIZE];
		uint32_t size = 0;
		for (int i = 0; i < num_blocks; i++) {
			read_data_from_queue(data_buf, Q_STORAGE_DATA_IN);
			size += (uint32_t) fwrite(data_buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
		}
		STORAGE_SET_ONE_RET(size);
		fclose(filep);
	} else if (buf[0] == STORAGE_OP_READ) { /* read */
		if (partitions[partition_id].is_locked) {
			printf("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		filep = fopen(partitions[partition_id].data_name, "r");
		if (!filep) {
			printf("%s: Error: couldn't open %s for read\n", __func__, partitions[partition_id].data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_TWO_ARGS
		int start_block = (int) arg0;
		int num_blocks = (int) arg1;
		if (start_block + num_blocks >= partitions[partition_id].size) {
			printf("%s: Error: invalid args\n", __func__);
			STORAGE_SET_ONE_RET(0)
			fclose(filep);
			return;
		}
		int seek_off = start_block * STORAGE_BLOCK_SIZE;
		fseek(filep, seek_off, SEEK_SET);
		uint8_t data_buf[STORAGE_BLOCK_SIZE];
		uint32_t size = 0;
		for (int i = 0; i < num_blocks; i++) {
			size += (uint32_t) fread(data_buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
			write_data_to_queue(data_buf, Q_STORAGE_DATA_OUT);
		}
		STORAGE_SET_ONE_RET(size);
		fclose(filep);
	} else if (buf[0] == STORAGE_OP_SET_KEY) {
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
	} else if (buf[0] == STORAGE_OP_REMOVE_KEY) {
		if (partitions[partition_id].is_locked) {
			printf("%s: Error: can't remove the key for a locked partition\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		uint32_t ret = (uint32_t) remove_partition_key(partition_id);
		STORAGE_SET_ONE_RET(ret)
	} else if (buf[0] == STORAGE_OP_UNLOCK) {
		if (!partitions[partition_id].is_locked) {
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		STORAGE_GET_ZERO_ARGS_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			printf("%s: Error: incorrect key size (sent for unlocking)\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		uint32_t ret = (uint32_t) unlock_partition(data, partition_id);
		STORAGE_SET_ONE_RET(ret)
	} else if (buf[0] == STORAGE_OP_WIPE) {
		uint32_t ret = (uint32_t) wipe_partition(partition_id);
		STORAGE_SET_ONE_RET(ret)
	} else {
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}
}

/* FIXME: there's duplicate code between process_request and this function */
static void process_secure_request(uint8_t *buf, int partition_id)
{
	FILE *filep = NULL;

	/* write */
	if (buf[0] == STORAGE_OP_WRITE) {
		if (partitions[partition_id].is_locked) {
			printf("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		filep = fopen(partitions[partition_id].data_name, "r+");
		if (!filep) {
			printf("%s: Error: couldn't open %s for write\n", __func__, partitions[partition_id].data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_TWO_ARGS_DATA
		if (((int) arg0) > partitions[partition_id].size) {
			printf("%s: Error: invalid block size\n", __func__);
			STORAGE_SET_ONE_RET(0)
			fclose(filep);
			return;
		}
		int seek_off = (arg0 * STORAGE_BLOCK_SIZE) + arg1;
		fseek(filep, seek_off, SEEK_SET);
		uint32_t size = (uint32_t) fwrite(data, sizeof(uint8_t), data_size, filep);
		STORAGE_SET_ONE_RET(size);
		fclose(filep);
	} else if (buf[0] == STORAGE_OP_READ) { /* read */
		if (partitions[partition_id].is_locked) {
			printf("%s: Error: partition is locked\n", __func__);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		filep = fopen(partitions[partition_id].data_name, "r");
		if (!filep) {
			printf("%s: Error: couldn't open %s for read\n", __func__, partitions[partition_id].data_name);
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_THREE_ARGS
		if (((int) arg0) > partitions[partition_id].size) {
			printf("%s: Error: invalid block size\n", __func__);
			STORAGE_SET_ONE_RET(0)
			fclose(filep);
			return;
		}
		uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];
		int seek_off = (arg0 * STORAGE_BLOCK_SIZE) + arg1;
		fseek(filep, seek_off, SEEK_SET);
		uint32_t size = (uint32_t) fread(ret_buf, sizeof(uint8_t), arg2, filep);
		STORAGE_SET_ONE_RET_DATA(size, ret_buf, size);
		fclose(filep);
	} else if (buf[0] == STORAGE_OP_SET_KEY) {
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
	} else if (buf[0] == STORAGE_OP_REMOVE_KEY) {
		if (partitions[partition_id].is_locked) {
			printf("%s: Error: can't remove the key for a locked partition\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		uint32_t ret = (uint32_t) remove_partition_key(partition_id);
		STORAGE_SET_ONE_RET(ret)
	} else if (buf[0] == STORAGE_OP_UNLOCK) {
		if (!partitions[partition_id].is_locked) {
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		STORAGE_GET_ZERO_ARGS_DATA
		if (data_size != STORAGE_KEY_SIZE) {
			printf("%s: Error: incorrect key size (sent for unlocking)\n", __func__);
			STORAGE_SET_ONE_RET(ERR_INVALID)
			return;
		}

		uint32_t ret = (uint32_t) unlock_partition(data, partition_id);
		STORAGE_SET_ONE_RET(ret)
	} else if (buf[0] == STORAGE_OP_WIPE) {
		uint32_t ret = (uint32_t) wipe_partition(partition_id);
		STORAGE_SET_ONE_RET(ret)
	} else {
		STORAGE_SET_ONE_RET(ERR_INVALID)
		return;
	}
}

int main(int argc, char **argv)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t interrupt, opcode[2];

	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error: storage data queue msg size must be equal to storage block size\n");
		return -1;
	}

	initialize_storage_space();

	mkfifo(FIFO_STORAGE_OUT, 0666);
	mkfifo(FIFO_STORAGE_IN, 0666);
	mkfifo(FIFO_STORAGE_INTR, 0666);

	fd_out = open(FIFO_STORAGE_OUT, O_WRONLY);
	fd_in = open(FIFO_STORAGE_IN, O_RDONLY);
	fd_intr = open(FIFO_STORAGE_INTR, O_RDONLY);
		
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		read(fd_intr, &interrupt, 1);
		if (interrupt == Q_STORAGE_CMD_IN) {
			opcode[1] = Q_STORAGE_CMD_IN;
			write(fd_out, opcode, 2), 
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			process_request(buf, 0);
			send_response(buf, Q_STORAGE_CMD_OUT);
		} else if (interrupt == Q_STORAGE_IN_2) {
			opcode[1] = Q_STORAGE_IN_2;
			write(fd_out, opcode, 2), 
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			process_secure_request(buf, 1);
			send_response(buf, Q_STORAGE_OUT_2);
		}
	}
	
	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_STORAGE_OUT);
	remove(FIFO_STORAGE_IN);
	remove(FIFO_STORAGE_INTR);
}
