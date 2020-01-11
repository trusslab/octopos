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
#include "mailbox.h"

#define PARTITION_SIZE		1000 /* blocks */
#define BLOCK_SIZE		32  /* bytes */

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

#define MAX_FILENAME_SIZE	256

struct file {
	char filename[MAX_FILENAME_SIZE];
	int start_block;
	int num_blocks;
	bool opened;
};

/* FIXME: use per-process fd */
#define MAX_NUM_FD	64 /* must be divisible by 8 */
uint8_t fd_bitmap[MAX_NUM_FD / 8];

struct file *fd_array[MAX_NUM_FD];

struct file_list_node {
	struct file *file;
	struct file_list_node *next;
};

struct file_list_node *file_list_head = NULL;
struct file_list_node *file_list_tail = NULL;

/* FIXME: too small */
#define DIR_BLOCK_SIZE 50
uint8_t dir_data[DIR_BLOCK_SIZE];

static int get_unused_fd(void)
{
	for (int i = 0; i < (MAX_NUM_FD / 8); i++) {
		if (fd_bitmap[i] == 0xFF)
			continue;

		uint8_t mask = 0b00000001;
		for (int j = 0; j < 8; j++) {
			if (((uint8_t) (fd_bitmap[i] | ~mask)) != 0xFF) {
				fd_bitmap[i] |= mask;
				return (i * 8) + j + 1;
			}

			mask = mask << 1;
		}
	}

	return ERR_EXIST;
}

static void mark_fd_as_unused(int _fd)
{
	int fd = _fd - 1;

	if (fd >= MAX_NUM_FD) {
		printf("%s: Error: invalid fd %d\n", __func__, fd);
		return;
	}

	int byte_off = fd / 8;
	int bit_off = fd % 8;

	uint8_t mask = 0b00000001;
	for (int i = 0; i < bit_off; i++)
		mask = mask << 1;

	fd_bitmap[byte_off] &= ~mask;
}

static int add_file_to_list(struct file *file)
{
	struct file_list_node *node = 
		(struct file_list_node *) malloc(sizeof(struct file_list_node));
	if (!node)
		return ERR_MEMORY;

	node->file = file;
	node->next = NULL;

	if (file_list_head == NULL && file_list_tail == NULL) {
		/* first node */
		file_list_head = node;
		file_list_tail = node;
	} else {
		file_list_tail->next = node;
		file_list_tail = node;
	}

	return 0;
}

//static int remove_file_from_list(struct file *file)
//{
//	struct file_list_node *prev_node = NULL;
//
//	for (struct file_list_node *node = file_list_head; node;
//	     node = node->next) {
//		if (node->file == file) {
//			if (prev_node == NULL) { /* removing head */
//				if (node == file_list_tail) { /* last node */
//					file_list_head = NULL;
//					file_list_tail = NULL;
//				} else {
//					file_list_head = node->next;
//				}
//			} else {
//				prev_node->next = node->next;
//				if (node == file_list_tail) {
//					file_list_tail = prev_node;
//				}
//			}
//
//			return 0;
//		}
//
//		prev_node = node;
//	}
//
//	return ERR_EXIST;
//}

//struct file *get_file(int file_id)
//{
//	for (struct file_list_node *node = file_list_head; node;
//	     node = node->next) {
//		if (node->file->id == file_id)
//			return node->file;
//	}
//
//	return NULL;
//}

uint32_t file_system_open_file(char *filename)
{
	for (struct file_list_node *node = file_list_head; node;
	     node = node->next) {
		if (!strcmp(node->file->filename, filename)) {
			if (node->file->opened)
				/* error */
				return (uint32_t) 0;

			int ret = get_unused_fd();
			if (ret < 0)
				return (uint32_t) 0;

			uint32_t fd = (uint32_t) ret;
			if (fd >= MAX_NUM_FD)
				return (uint32_t) 0;
			
			/* Shouldn't happen, but let's check. */
			if (fd_array[fd])
				return (uint32_t) 0;

			fd_array[fd] = node->file;
			node->file->opened = true;

			return fd;
		}
	}

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
	if (fd >= MAX_NUM_FD) { 
		printf("%s: Error: fd is too large\n", __func__);
		return 0;
	}

	struct file *file = fd_array[fd];
	if (!file) {
		printf("%s: Error: invalid fd\n", __func__);
		return 0;
	}

	if (!file->opened) {
		printf("%s: Error: file not opened!\n", __func__);
		return 0;
	}

	if ((file->num_blocks * BLOCK_SIZE) - offset < size) {
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
		ret = write_to_block(&data[written_size], (uint32_t) file->start_block + block_num,
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
	if (fd >= MAX_NUM_FD) { 
		printf("%s: Error: fd is too large\n", __func__);
		return 0;
	}

	struct file *file = fd_array[fd];
	if (!file) {
		printf("%s: Error: invalid fd\n", __func__);
		return 0;
	}

	if (!file->opened) {
		printf("%s: Error: file not opened!\n", __func__);
		return 0;
	}

	if ((file->num_blocks * BLOCK_SIZE) - offset < size) {
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
		ret = read_from_block(&data[read_size], (uint32_t) file->start_block + block_num,
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
	if (fd >= MAX_NUM_FD) { 
		printf("%s: Error: fd is too large\n", __func__);
		return ERR_INVALID;
	}

	struct file *file = fd_array[fd];
	if (!file) {
		printf("%s: Error: invalid fd\n", __func__);
		return ERR_INVALID;
	}

	if (!file->opened) {
		printf("%s: Error: file not opened!\n", __func__);
		return ERR_INVALID;
	}

	file->opened = false;
	mark_fd_as_unused(fd);

	return 0;
}

void initialize_file_system(void)
{
	/* read the directory */
	read_from_block(dir_data, 0, 0, DIR_BLOCK_SIZE);
	/* check to see if there's a valid directory */
	if (dir_data[0] == '$' && dir_data[1] == '%' &&
	    dir_data[2] == '^' && dir_data[3] == '&') {
		/* retrieve file info */
		uint16_t num_files = *((uint16_t *) &dir_data[4]);
		printf("%s [1]: num_files = %d\n", __func__, num_files);
		int data_ptr = 6;

		for (int i; i < num_files; i++) {
			if ((data_ptr + 2) > DIR_BLOCK_SIZE)
				break;
			int filename_size = *((uint16_t *) &dir_data[data_ptr]);
			data_ptr += 2;
			if ((data_ptr + filename_size + 4) > DIR_BLOCK_SIZE)
				break;

			if (filename_size > MAX_FILENAME_SIZE)
				break;

			struct file *file = (struct file *) malloc(sizeof(struct file));
			if (!file)
				break;

			strcpy(file->filename, (char *) &dir_data[data_ptr]);
			data_ptr += filename_size;

			file->start_block = *((uint16_t *) &dir_data[data_ptr]);
			data_ptr += 2;
			file->start_block = *((uint16_t *) &dir_data[data_ptr]);
			data_ptr += 2;

			add_file_to_list(file);
		}
	} else {
		/* initialize signature */
		dir_data[0] = '$';
		dir_data[1] = '%';
		dir_data[2] = '^';
		dir_data[3] = '&';
		/* set num files (two bytes) to 0 */
		dir_data[4] = 0;
		dir_data[5] = 0;
	}

	for (int i = 0; i < MAX_NUM_FD; i++)
		fd_array[i] = NULL;
}


