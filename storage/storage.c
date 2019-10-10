/* octopos storage code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
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
	}							\
	data_size = buf[9];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
	}							\
	data = &buf[10];					\

/* partition information */
#define NUM_PARTITIONS		2
#define PARTITION_ONE_SIZE	100 /* blocks */
#define PARTITION_TWO_SIZE	20  /* blocks */

#define BLOCK_SIZE		32  /* bytes */

int fd_out, fd_in, fd_intr;

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
static void initialize_storage_space(void)
{
	FILE *filep = NULL;

        filep = fopen("octopos_disk", "w");
	if (!filep) {
		printf("Error: initialize_storage_space: couldn't open octopos_disk\n");
		_exit(-1);
	}
        fclose(filep);

        filep = fopen("octopos_disk_2", "w");
	if (!filep) {
		printf("Error: initialize_storage_space: couldn't open octopos_disk\n");
		_exit(-1);
	}
        fclose(filep);
}

static void send_response(uint8_t *buf, uint8_t queue_id)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void process_request_partition_1(uint8_t *buf)
{
	FILE *filep = NULL;

	/* write */
	if (buf[0] == 0) {
		filep = fopen("octopos_disk", "r+");
		if (!filep) {
			printf("Error: couldn't open octopos_disk\n");
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_TWO_ARGS_DATA
		if (arg0 > PARTITION_ONE_SIZE) {
			printf("Error: invalid partition number\n");
			STORAGE_SET_ONE_RET(0)
			fclose(filep);
			return;
		}
		int seek_off = (arg0 * BLOCK_SIZE) + arg1;
		fseek(filep, seek_off, SEEK_SET);
		uint32_t size = (uint32_t) fwrite(data, sizeof(uint8_t), data_size, filep);
		STORAGE_SET_ONE_RET(size);
		fclose(filep);
	} else { /* read */
		filep = fopen("octopos_disk", "r");
		if (!filep) {
			printf("Error: couldn't open octopos_disk\n");
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_THREE_ARGS
		if (arg0 > PARTITION_ONE_SIZE) {
			printf("Error: invalid partition number\n");
			STORAGE_SET_ONE_RET(0)
			fclose(filep);
			return;
		}
		uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];
		int seek_off = (arg0 * BLOCK_SIZE) + arg1;
		fseek(filep, seek_off, SEEK_SET);
		uint32_t size = (uint32_t) fread(ret_buf, sizeof(uint8_t), arg2, filep);
		STORAGE_SET_ONE_RET_DATA(size, ret_buf, size);
		fclose(filep);
	}
}

static void process_request_partition_2(uint8_t *buf)
{
	FILE *filep = NULL;

	/* write */
	if (buf[0] == 0) {
		filep = fopen("octopos_disk_2", "r+");
		if (!filep) {
			printf("Error: couldn't open octopos_disk_2\n");
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_TWO_ARGS_DATA
		if (arg0 > PARTITION_TWO_SIZE) {
			printf("Error: invalid partition number\n");
			STORAGE_SET_ONE_RET(0)
			fclose(filep);
			return;
		}
		int seek_off = (arg0 * BLOCK_SIZE) + arg1;
		fseek(filep, seek_off, SEEK_SET);
		uint32_t size = (uint32_t) fwrite(data, sizeof(uint8_t), data_size, filep);
		STORAGE_SET_ONE_RET(size);
		fclose(filep);
	} else { /* read */
		filep = fopen("octopos_disk_2", "r");
		if (!filep) {
			printf("Error: couldn't open octopos_disk\n");
			STORAGE_SET_ONE_RET(0)
			return;
		}
		STORAGE_GET_THREE_ARGS
		if (arg0 > PARTITION_TWO_SIZE) {
			printf("Error: invalid partition number\n");
			STORAGE_SET_ONE_RET(0)
			fclose(filep);
			return;
		}
		uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];
		int seek_off = (arg0 * BLOCK_SIZE) + arg1;
		fseek(filep, seek_off, SEEK_SET);
		uint32_t size = (uint32_t) fread(ret_buf, sizeof(uint8_t), arg2, filep);
		STORAGE_SET_ONE_RET_DATA(size, ret_buf, size);
		fclose(filep);
	}
}

int main(int argc, char **argv)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t interrupt, opcode[2];

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
		if (interrupt == Q_STORAGE_IN) {
			opcode[1] = Q_STORAGE_IN;
			write(fd_out, opcode, 2), 
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			process_request_partition_1(buf);
			send_response(buf, Q_STORAGE_OUT);
		} else if (interrupt == Q_STORAGE_IN_2) {
			opcode[1] = Q_STORAGE_IN_2;
			write(fd_out, opcode, 2), 
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			process_request_partition_2(buf);
			send_response(buf, Q_STORAGE_OUT_2);
		}
	}
	
	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_SERIAL_OUT_OUT);
	remove(FIFO_SERIAL_OUT_IN);
	remove(FIFO_SERIAL_OUT_INTR);
}
