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
	int dir_data_off;
	bool opened;
};

/* FIXME: use per-process fd */
#define MAX_NUM_FD	64 /* must be divisible by 8 */
uint8_t fd_bitmap[MAX_NUM_FD / 8];

struct file *file_array[MAX_NUM_FD];

struct file_list_node {
	struct file *file;
	struct file_list_node *next;
};

struct file_list_node *file_list_head = NULL;
struct file_list_node *file_list_tail = NULL;

/* FIXME: too small */
#define DIR_BLOCK_SIZE 50
uint8_t dir_data[DIR_BLOCK_SIZE];
int dir_data_ptr = 0;

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

static int remove_file_from_list(struct file *file)
{
	struct file_list_node *prev_node = NULL;

	for (struct file_list_node *node = file_list_head; node;
	     node = node->next) {
		if (node->file == file) {
			if (prev_node == NULL) { /* removing head */
				if (node == file_list_tail) { /* last node */
					file_list_head = NULL;
					file_list_tail = NULL;
				} else {
					file_list_head = node->next;
				}
			} else {
				prev_node->next = node->next;
				if (node == file_list_tail) {
					file_list_tail = prev_node;
				}
			}

			return 0;
		}

		prev_node = node;
	}

	return ERR_EXIST;
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

static int add_file_to_directory(struct file *file)
{
	int filename_size = strlen(file->filename);
	printf("%s [1]: filename_size = %d\n", __func__, filename_size);
	if (filename_size > MAX_FILENAME_SIZE)
		return ERR_INVALID;
	printf("%s [2]: dir_data_ptr = %d\n", __func__, dir_data_ptr);

	if ((dir_data_ptr + filename_size + 7) > DIR_BLOCK_SIZE)
		return ERR_MEMORY;
	printf("%s [3]\n", __func__);

	int dir_data_off = dir_data_ptr;
	*((uint16_t *) &dir_data[dir_data_ptr]) = filename_size;
	dir_data_ptr += 2;

	strcpy((char *) &dir_data[dir_data_ptr], file->filename);
	dir_data_ptr = dir_data_ptr + filename_size + 1;

	*((uint16_t *) &dir_data[dir_data_ptr]) = file->start_block;
	dir_data_ptr += 2;
	*((uint16_t *) &dir_data[dir_data_ptr]) = file->num_blocks;
	dir_data_ptr += 2;

	/* increment number of files */
	(*((uint16_t *) &dir_data[4]))++;

	write_to_block(dir_data, 0, 0, DIR_BLOCK_SIZE);

	file->dir_data_off = dir_data_off;

	return 0;
}

static int remove_file_from_directory(struct file *file)
{
	int filename_size = *((uint16_t *) &dir_data[file->dir_data_off]);
	printf("%s [1]: filename_size = %d\n", __func__, filename_size);

	int file_dir_info_size = filename_size + 7;
	if ((file->dir_data_off + file_dir_info_size) > DIR_BLOCK_SIZE)
		return ERR_FAULT;
	printf("%s [2]\n", __func__);

	memset(dir_data + file->dir_data_off, 0x0, file_dir_info_size);

	if ((file->dir_data_off + file_dir_info_size) < (DIR_BLOCK_SIZE - 1)) {
		/* need to shift */
		printf("%s [3]\n", __func__);
		int shift_size = DIR_BLOCK_SIZE - (file->dir_data_off + file_dir_info_size);
		memcpy(dir_data + file->dir_data_off, dir_data + file->dir_data_off + shift_size, shift_size);
	}

	/* decrement number of files */
	(*((uint16_t *) &dir_data[4]))--;

	dir_data_ptr -= file_dir_info_size;
	write_to_block(dir_data, 0, 0, DIR_BLOCK_SIZE);

	return 0;
}


/* file open modes */
#define FILE_OPEN_MODE		0
#define FILE_OPEN_CREATE_MODE	1

uint32_t file_system_open_file(char *filename, uint32_t mode)
{
	struct file *file = NULL;
	printf("%s [1]: mode = %d\n", __func__, mode);
	if (!(mode == FILE_OPEN_MODE || mode == FILE_OPEN_CREATE_MODE)) {
		printf("Error: invalid mode for opening a file\n");
		return (uint32_t) 0;
	}

	printf("%s [1.1]: filename = %s\n", __func__, filename);
	for (struct file_list_node *node = file_list_head; node;
	     node = node->next) {
		printf("%s [1.2]: node->file->filename = %s\n", __func__, node->file->filename);
		if (!strcmp(node->file->filename, filename)) {
			printf("%s [2]\n", __func__);
			if (node->file->opened)
				/* error */
				return (uint32_t) 0;

			file = node->file;			
		}
	}

	if (file == NULL && mode == FILE_OPEN_CREATE_MODE) {
		printf("%s [3]: create mode\n", __func__);
		file = (struct file *) malloc(sizeof(struct file));
		if (!file)
			return (uint32_t) 0;
		printf("%s [4]\n", __func__);

		strcpy(file->filename, filename);

		/* FIXME: do not hardcode start_block and num_blocks */
		file->start_block = 1;
		file->num_blocks = 10;

		int ret = add_file_to_directory(file);
		if (ret) {
			free(file);
			return (uint32_t) 0;
		}
		printf("%s [5]\n", __func__);

		add_file_to_list(file);
	}

	if (file) {
		printf("%s [6]\n", __func__);
		int ret = get_unused_fd();
		if (ret < 0)
			return (uint32_t) 0;
		printf("%s [7]\n", __func__);

		uint32_t fd = (uint32_t) ret;
		if (fd == 0 || fd >= MAX_NUM_FD)
			return (uint32_t) 0;
		printf("%s [8]\n", __func__);
		
		/* Shouldn't happen, but let's check. */
		if (file_array[fd])
			return (uint32_t) 0;
		printf("%s [9]\n", __func__);

		file_array[fd] = file;
		file->opened = true;

		return fd;
	}
	printf("%s [10]\n", __func__);

	/* error */
	return (uint32_t) 0;
}

int file_system_write_to_file(uint32_t fd, uint8_t *data, int size, int offset)
{
	if (fd == 0 || fd >= MAX_NUM_FD) { 
		printf("%s: Error: fd is 0 or too large (%d)\n", __func__, fd);
		return 0;
	}

	struct file *file = file_array[fd];
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
	if (fd == 0 || fd >= MAX_NUM_FD) { 
		printf("%s: Error: fd is 0 or too large (%d)\n", __func__, fd);
		return 0;
	}

	struct file *file = file_array[fd];
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
	if (fd == 0 || fd >= MAX_NUM_FD) { 
		printf("%s: Error: fd is 0 or too large (%d)\n", __func__, fd);
		return ERR_INVALID;
	}

	struct file *file = file_array[fd];
	if (!file) {
		printf("%s: Error: invalid fd\n", __func__);
		return ERR_INVALID;
	}

	if (!file->opened) {
		printf("%s: Error: file not opened!\n", __func__);
		return ERR_INVALID;
	}

	file->opened = false;
	file_array[fd] = NULL;
	mark_fd_as_unused(fd);

	return 0;
}

int file_system_remove_file(char *filename)
{
	struct file *file = NULL;
	printf("%s [1.1]: filename = %s\n", __func__, filename);
	for (struct file_list_node *node = file_list_head; node;
	     node = node->next) {
		printf("%s [1.2]: node->file->filename = %s\n", __func__, node->file->filename);
		if (!strcmp(node->file->filename, filename)) {
			printf("%s [2]\n", __func__);
			if (node->file->opened) {
				printf("Error: can't remove an open file\n");
				return ERR_INVALID;
			}

			file = node->file;			
		}
	}

	if (file == NULL) {
		printf("Error: file to be removed does not exist\n");
		return ERR_INVALID;
	}


	int ret = remove_file_from_directory(file);
	if (ret)
		return ERR_FAULT;

	remove_file_from_list(file);

	return 0;
}

void initialize_file_system(void)
{
	printf("%s [1]\n", __func__);
	/* initialize fd bitmap */
	if (MAX_NUM_FD % 8) {
		printf("%s: Error: MAX_NUM_FD must be divisible by 8\n", __func__);
		_exit(-1);
	}
	printf("%s [2]\n", __func__);

	fd_bitmap[0] = 0x00000001; /* fd 0 is error */
	for (int i = 1; i < (MAX_NUM_FD / 8); i++)
		fd_bitmap[i] = 0;

	/* wipe dir */
	//memset(dir_data, 0x0, DIR_BLOCK_SIZE);
	//write_to_block(dir_data, 0, 0, DIR_BLOCK_SIZE);
	//exit(-1);

	/* read the directory */
	read_from_block(dir_data, 0, 0, DIR_BLOCK_SIZE);
	/* check to see if there's a valid directory */
	if (dir_data[0] == '$' && dir_data[1] == '%' &&
	    dir_data[2] == '^' && dir_data[3] == '&') {
		printf("%s [3]\n", __func__);
		/* retrieve file info */
		uint16_t num_files = *((uint16_t *) &dir_data[4]);
		printf("%s [4]: num_files = %d\n", __func__, num_files);
		dir_data_ptr = 6;

		for (int i = 0; i < num_files; i++) {
			int dir_data_off = dir_data_ptr;
			if ((dir_data_ptr + 2) > DIR_BLOCK_SIZE)
				break;
			int filename_size = *((uint16_t *) &dir_data[dir_data_ptr]);
			dir_data_ptr += 2;
			if ((dir_data_ptr + filename_size + 5) > DIR_BLOCK_SIZE)
				break;

			if (filename_size > MAX_FILENAME_SIZE)
				break;

			struct file *file = (struct file *) malloc(sizeof(struct file));
			if (!file)
				break;

			strcpy(file->filename, (char *) &dir_data[dir_data_ptr]);
			printf("%s [5]: file->filename = %s\n", __func__, file->filename);
			dir_data_ptr = dir_data_ptr + filename_size + 1;

			file->dir_data_off = dir_data_off;
			file->start_block = *((uint16_t *) &dir_data[dir_data_ptr]);
			dir_data_ptr += 2;
			file->num_blocks = *((uint16_t *) &dir_data[dir_data_ptr]);
			dir_data_ptr += 2;

			add_file_to_list(file);
		}
	} else {
		printf("%s [6]\n", __func__);
		/* initialize signature */
		dir_data[0] = '$';
		dir_data[1] = '%';
		dir_data[2] = '^';
		dir_data[3] = '&';
		/* set num files (two bytes) to 0 */
		dir_data[4] = 0;
		dir_data[5] = 0;
		dir_data_ptr = 6;
		/* update the directory in storage */
		write_to_block(dir_data, 0, 0, DIR_BLOCK_SIZE);
	}

	for (int i = 0; i < MAX_NUM_FD; i++)
		file_array[i] = NULL;
}
