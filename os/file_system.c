/* OctopOS file system */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/error.h>

#define PARTITION_SIZE		100 /* blocks */
#define BLOCK_SIZE		32  /* bytes */

/* FIXME: move to header file */
int send_msg_to_storage(uint8_t *buf);

struct file {
	char filename[256];
	int start_block;
	int num_blocks;
	bool opened;
};

#define NUM_FILES		3
struct file files[NUM_FILES];

#define STORAGE_SET_THREE_ARGS(arg0, arg1, arg2)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	*((uint32_t *) &buf[1]) = arg0;				\
	*((uint32_t *) &buf[5]) = arg1;				\
	*((uint32_t *) &buf[9]) = arg2;				\


#define STORAGE_SET_TWO_ARGS_DATA(arg0, arg1, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 10;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	*((uint32_t *) &buf[1]) = arg0;						\
	*((uint32_t *) &buf[5]) = arg1;						\
	buf[9] = size;								\
	memcpy(&buf[10], (uint8_t *) data, size);				\

#define STORAGE_GET_ONE_RET				\
	uint32_t ret0;					\
	ret0 = *((uint32_t *) &buf[0]);			\

#define STORAGE_GET_ONE_RET_DATA(data)						\
	uint32_t ret0;								\
	uint8_t _size, max_size = MAILBOX_QUEUE_MSG_SIZE - 5;			\
	ret0 = *((uint32_t *) &buf[0]);						\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	_size = buf[4];								\
	if (_size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	memcpy(data, &buf[5], _size);						\


void initialize_file_system(void)
{
	/* read the partition table */
	/* dummy implementation for now */
	strcpy(files[0].filename, "test_file_1.txt");
	files[0].start_block = 0;
	files[0].num_blocks = 20;
	files[0].opened = false;

	strcpy(files[1].filename, "test_file_2.txt");
	files[1].start_block = 20;
	files[1].num_blocks = 50;
	files[1].opened = false;

	strcpy(files[2].filename, "test_file_3.txt");
	files[2].start_block = 70;
	files[2].num_blocks = 30;
	files[2].opened = false;
}

uint32_t file_system_open_file(char *filename)
{
	for (int i = 0; i < NUM_FILES; i++) {
		if (!strcmp(filename, files[i].filename)) {
			files[i].opened = true;
			return (uint32_t) i+1;
		}
	}

	/* error */
	return (uint32_t) 0;
}

static int write_to_block(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t write_size)
{
	STORAGE_SET_TWO_ARGS_DATA(block_num, block_offset, data, write_size)
	buf[0] = STORAGE_OP_WRITE;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int read_from_block(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t read_size)
{
	STORAGE_SET_THREE_ARGS(block_num, block_offset, read_size)
	buf[0] = STORAGE_OP_READ;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET_DATA(data)
	return (int) ret0;
}

int file_system_write_to_file(uint32_t fd, uint8_t *data, int size, int offset)
{
	if (fd < 1 && fd > 3) {
		printf("%s: Error: invalid fd\n", __func__);
		return 0;
	}

	int f_index = fd - 1;

	if (!files[f_index].opened) {
		printf("%s: Error: file not opened\n", __func__);
		return 0;
	}

	if ((files[f_index].num_blocks * BLOCK_SIZE) - offset < size) {
		printf("%s: Error: invalid size/offset\n", __func__);
		return 0;
	}

	int block_num = offset / BLOCK_SIZE;
	int block_offset = offset % BLOCK_SIZE;
	int written_size = 0;
	int next_write_size = BLOCK_SIZE - block_offset;
	if (next_write_size > size)
		next_write_size = size;
	int ret = 0;

	while (written_size < size) {
		ret = write_to_block(&data[written_size], (uint32_t) files[f_index].start_block + block_num,
				(uint32_t) block_offset, (uint32_t) next_write_size);
		if (ret != next_write_size) {
			written_size += ret;
			break;
		}
		written_size += next_write_size;
		block_num++;
		block_offset = 0;
		if ((size - written_size) >= BLOCK_SIZE)
			next_write_size = BLOCK_SIZE - block_offset;
		else
			next_write_size = (size - written_size);
	}
	
	return written_size;
}


int file_system_read_from_file(uint32_t fd, uint8_t *data, int size, int offset)
{
	if (fd < 1 && fd > 3) {
		printf("%s: Error: invalid fd\n", __func__);
		return 0;
	}

	int f_index = fd - 1;

	if (!files[f_index].opened) {
		printf("%s: Error: file not opened\n", __func__);
		return 0;
	}

	if ((files[f_index].num_blocks * BLOCK_SIZE) - offset < size) {
		printf("%s: Error: invalid size/offset\n", __func__);
		return 0;
	}

	int block_num = offset / BLOCK_SIZE;
	int block_offset = offset % BLOCK_SIZE;
	int read_size = 0;
	int next_read_size = BLOCK_SIZE - block_offset;
	if (next_read_size > size)
		next_read_size = size;
	int ret = 0;

	while (read_size < size) {
		ret = read_from_block(&data[read_size], (uint32_t) files[f_index].start_block + block_num,
				(uint32_t) block_offset, (uint32_t) next_read_size);
		if (ret != next_read_size) {
			read_size += ret;
			break;
		}
		read_size += next_read_size;
		block_num++;
		block_offset = 0;
		if ((size - read_size) >= BLOCK_SIZE)
			next_read_size = BLOCK_SIZE - block_offset;
		else
			next_read_size = (size - read_size);
	}
	
	return read_size;
}

int file_system_close_file(uint32_t fd)
{
	int f_index = fd - 1;
	files[f_index].opened = false;
	return 0;
}
