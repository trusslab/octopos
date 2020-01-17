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

#define STORAGE_SET_TWO_ARGS(arg0, arg1)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	*((uint32_t *) &buf[1]) = arg0;				\
	*((uint32_t *) &buf[5]) = arg1;				\


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
#define DIR_DATA_NUM_BLOCKS	2 //16
#define DIR_DATA_SIZE		DIR_DATA_NUM_BLOCKS * STORAGE_BLOCK_SIZE
uint8_t dir_data[DIR_DATA_SIZE];
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

static int write_blocks(uint8_t *data, uint32_t start_block, uint32_t num_blocks)
{
	STORAGE_SET_TWO_ARGS(start_block, num_blocks)
	buf[0] = STORAGE_OP_WRITE;
	send_msg_to_storage_no_response(buf);
	for (int i = 0; i < (int) num_blocks; i++)
		write_to_storage_data_queue(data + (i * STORAGE_BLOCK_SIZE));
	get_response_from_storage(buf);

	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int read_blocks(uint8_t *data, uint32_t start_block, uint32_t num_blocks)
{
	STORAGE_SET_TWO_ARGS(start_block, num_blocks)
	buf[0] = STORAGE_OP_READ;
	send_msg_to_storage_no_response(buf);
	for (int i = 0; i < (int) num_blocks; i++)
		read_from_storage_data_queue(data + (i * STORAGE_BLOCK_SIZE));
	get_response_from_storage(buf);

	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int read_from_block(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t read_size)
{
	uint8_t buf[STORAGE_BLOCK_SIZE];

	if (block_offset + read_size > STORAGE_BLOCK_SIZE)
		return 0;

	int ret = read_blocks(buf, block_num, 1);
	if (ret != STORAGE_BLOCK_SIZE)
		return 0;

	memcpy(data, buf + block_offset, read_size);

	return (int) read_size;
}

static int write_to_block(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t write_size)
{
	uint8_t buf[STORAGE_BLOCK_SIZE];

	if (block_offset + write_size > STORAGE_BLOCK_SIZE)
		return 0;

	/* partial block write */
	if (!(block_offset == 0 && write_size == STORAGE_BLOCK_SIZE)) {
		int read_ret = read_blocks(buf, block_num, 1);
		if (read_ret != STORAGE_BLOCK_SIZE)
			return 0;
	}

	memcpy(buf + block_offset, data, write_size);

	int ret = write_blocks(buf, block_num, 1);

	return (int) ret;
}

static void flush_dir_data_to_storage(void)
{
	write_blocks(dir_data, 0, DIR_DATA_NUM_BLOCKS);
}

static void read_dir_data_from_storage(void)
{
	read_blocks(dir_data, 0, DIR_DATA_NUM_BLOCKS);
}

static int add_file_to_directory(struct file *file)
{
	int filename_size = strlen(file->filename);
	if (filename_size > MAX_FILENAME_SIZE)
		return ERR_INVALID;

	if ((dir_data_ptr + filename_size + 7) > DIR_DATA_SIZE)
		return ERR_MEMORY;

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

	flush_dir_data_to_storage();

	file->dir_data_off = dir_data_off;

	return 0;
}

static int remove_file_from_directory(struct file *file)
{
	int filename_size = *((uint16_t *) &dir_data[file->dir_data_off]);

	int file_dir_info_size = filename_size + 7;
	if ((file->dir_data_off + file_dir_info_size) > DIR_DATA_SIZE)
		return ERR_FAULT;

	memset(dir_data + file->dir_data_off, 0x0, file_dir_info_size);

	if ((file->dir_data_off + file_dir_info_size) < (DIR_DATA_SIZE - 1)) {
		/* need to shift */
		int shift_size = DIR_DATA_SIZE - (file->dir_data_off + file_dir_info_size);
		memcpy(dir_data + file->dir_data_off, dir_data + file->dir_data_off + file_dir_info_size, shift_size);

		/* update the dir_data_off in all other files */
		for (struct file_list_node *node = file_list_head; node;
		     node = node->next) {
			if (node->file->dir_data_off > file->dir_data_off)
				node->file->dir_data_off -= file_dir_info_size;
		}
	}

	/* decrement number of files */
	(*((uint16_t *) &dir_data[4]))--;

	dir_data_ptr -= file_dir_info_size;
	flush_dir_data_to_storage();

	return 0;
}

/* FIXME: inefficient and slow */
static int alloc_blocks_for_file(struct file *file)
{
	int start_block = DIR_DATA_NUM_BLOCKS;
	int num_blocks = 10; /* fixed for now */
	bool found = false;

	while ((start_block + num_blocks) <= STORAGE_MAIN_PARTITION_SIZE) {
		bool used = false;
		for (struct file_list_node *node = file_list_head; node;
		     node = node->next) {
			if (node->file->start_block == start_block) {
				used = true;
				break;
			}
		}

		if (!used) {
			found = true;
			break;
		}

		start_block += num_blocks;
	}

	if (found) {
		file->start_block = start_block;
		file->num_blocks = num_blocks;
		/* zero them out */
		/* FIXME: use one command to zero out all blocks */
		uint8_t zero_buf[STORAGE_BLOCK_SIZE];
		memset(zero_buf, 0x0, STORAGE_BLOCK_SIZE);
		for (int i = 0; i < num_blocks; i++) {
			write_blocks(zero_buf, start_block + i, 1);
		}
		return 0;
	} else {
		return ERR_FOUND;
	}
}

static void release_file_blocks(struct file *file)
{
	/* No op */
}

/* file open modes */
#define FILE_OPEN_MODE		0
#define FILE_OPEN_CREATE_MODE	1

uint32_t file_system_open_file(char *filename, uint32_t mode)
{
	struct file *file = NULL;
	if (!(mode == FILE_OPEN_MODE || mode == FILE_OPEN_CREATE_MODE)) {
		printf("Error: invalid mode for opening a file\n");
		return (uint32_t) 0;
	}

	for (struct file_list_node *node = file_list_head; node;
	     node = node->next) {
		if (!strcmp(node->file->filename, filename)) {
			if (node->file->opened)
				/* error */
				return (uint32_t) 0;

			file = node->file;			
		}
	}

	if (file == NULL && mode == FILE_OPEN_CREATE_MODE) {
		file = (struct file *) malloc(sizeof(struct file));
		if (!file)
			return (uint32_t) 0;

		strcpy(file->filename, filename);

		int ret = alloc_blocks_for_file(file);
		if (ret) {
			free(file);
			return (uint32_t) 0;
		}

		ret = add_file_to_directory(file);
		if (ret) {
			release_file_blocks(file);
			free(file);
			return (uint32_t) 0;
		}

		add_file_to_list(file);
	}

	if (file) {
		int ret = get_unused_fd();
		if (ret < 0)
			return (uint32_t) 0;

		uint32_t fd = (uint32_t) ret;
		if (fd == 0 || fd >= MAX_NUM_FD)
			return (uint32_t) 0;
		
		/* Shouldn't happen, but let's check. */
		if (file_array[fd])
			return (uint32_t) 0;

		file_array[fd] = file;
		file->opened = true;

		return fd;
	}

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

	if ((file->num_blocks * STORAGE_BLOCK_SIZE) - offset < size) {
		printf("%s: Error: invalid size/offset\n", __func__);
		return 0;
	}

	int block_num = offset / STORAGE_BLOCK_SIZE;
	int block_offset = offset % STORAGE_BLOCK_SIZE;
	int written_size = 0;
	int next_write_size = STORAGE_BLOCK_SIZE - block_offset;
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
		if ((size - written_size) >= STORAGE_BLOCK_SIZE)
			next_write_size = STORAGE_BLOCK_SIZE - block_offset;
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

	if ((file->num_blocks * STORAGE_BLOCK_SIZE) - offset < size) {
		printf("%s: Error: invalid size/offset\n", __func__);
		return 0;
	}

	int block_num = offset / STORAGE_BLOCK_SIZE;
	int block_offset = offset % STORAGE_BLOCK_SIZE;
	int read_size = 0;
	int next_read_size = STORAGE_BLOCK_SIZE - block_offset;
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
		if ((size - read_size) >= STORAGE_BLOCK_SIZE)
			next_read_size = STORAGE_BLOCK_SIZE - block_offset;
		else
			next_read_size = (size - read_size);
	}
	
	return read_size;
}

uint8_t file_system_write_file_blocks(uint32_t fd, int start_block, int num_blocks, uint8_t runtime_proc_id)
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

	if ((start_block + num_blocks) > file->num_blocks) {
		printf("%s: Error: invalid args\n", __func__);
		return 0;
	}

	/* FIXME: this is needed for now since count is uint8_t. */
	if (num_blocks > 255) {
		printf("%s: Error: num_blocks is too large\n", __func__);
		return 0;
	}

	mailbox_change_queue_access(Q_STORAGE_DATA_IN, WRITE_ACCESS,
							runtime_proc_id, (uint8_t) num_blocks);

	STORAGE_SET_TWO_ARGS(file->start_block + start_block, num_blocks)
	buf[0] = STORAGE_OP_WRITE;
	send_msg_to_storage_no_response(buf);

	return Q_STORAGE_DATA_IN;
}

void file_system_write_file_blocks_late(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	/* FIXME: we don't check the response */
	get_response_from_storage(buf);

	/* FIXME: the mailbox should automatically do this. */
	mailbox_change_queue_access(Q_STORAGE_DATA_IN, WRITE_ACCESS, P_OS, 0);
}

uint8_t file_system_read_file_blocks(uint32_t fd, int start_block, int num_blocks, uint8_t runtime_proc_id)
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

	if ((start_block + num_blocks) > file->num_blocks) {
		printf("%s: Error: invalid args\n", __func__);
		return 0;
	}

	/* FIXME: this is needed for now since count is uint8_t. */
	if (num_blocks > 255) {
		printf("%s: Error: num_blocks is too large\n", __func__);
		return 0;
	}

	mailbox_change_queue_access(Q_STORAGE_DATA_OUT, READ_ACCESS,
							runtime_proc_id, (uint8_t) num_blocks);

	STORAGE_SET_TWO_ARGS(file->start_block + start_block, num_blocks)
	buf[0] = STORAGE_OP_READ;
	send_msg_to_storage_no_response(buf);

	return Q_STORAGE_DATA_OUT;
}

void file_system_read_file_blocks_late(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	/* FIXME: we don't check the response */
	get_response_from_storage(buf);

	/* FIXME: the mailbox should automatically do this. */
	mailbox_change_queue_access(Q_STORAGE_DATA_OUT, READ_ACCESS, P_OS, 0);
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
	for (struct file_list_node *node = file_list_head; node;
	     node = node->next) {
		if (!strcmp(node->file->filename, filename)) {
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

	release_file_blocks(file);
	remove_file_from_list(file);

	return 0;
}

void initialize_file_system(void)
{
	/* initialize fd bitmap */
	if (MAX_NUM_FD % 8) {
		printf("%s: Error: MAX_NUM_FD must be divisible by 8\n", __func__);
		_exit(-1);
	}

	fd_bitmap[0] = 0x00000001; /* fd 0 is error */
	for (int i = 1; i < (MAX_NUM_FD / 8); i++)
		fd_bitmap[i] = 0;


	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error (file system): storage data queue msg size must be equal to storage block size\n");
		exit(-1);
	}

	/* wipe dir */
	memset(dir_data, 0x0, DIR_DATA_SIZE);
	flush_dir_data_to_storage();
	//exit(-1);

	/* read the directory */
	read_dir_data_from_storage();

	/* check to see if there's a valid directory */
	if (dir_data[0] == '$' && dir_data[1] == '%' &&
	    dir_data[2] == '^' && dir_data[3] == '&') {
		/* retrieve file info */
		uint16_t num_files = *((uint16_t *) &dir_data[4]);
		dir_data_ptr = 6;

		for (int i = 0; i < num_files; i++) {
			int dir_data_off = dir_data_ptr;
			if ((dir_data_ptr + 2) > DIR_DATA_SIZE)
				break;
			int filename_size = *((uint16_t *) &dir_data[dir_data_ptr]);
			dir_data_ptr += 2;
			if ((dir_data_ptr + filename_size + 5) > DIR_DATA_SIZE)
				break;

			if (filename_size > MAX_FILENAME_SIZE)
				break;

			struct file *file = (struct file *) malloc(sizeof(struct file));
			if (!file)
				break;

			strcpy(file->filename, (char *) &dir_data[dir_data_ptr]);
			dir_data_ptr = dir_data_ptr + filename_size + 1;

			file->dir_data_off = dir_data_off;
			file->start_block = *((uint16_t *) &dir_data[dir_data_ptr]);
			dir_data_ptr += 2;
			file->num_blocks = *((uint16_t *) &dir_data[dir_data_ptr]);
			dir_data_ptr += 2;

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
		dir_data_ptr = 6;
		/* update the directory in storage */
		flush_dir_data_to_storage();
	}

	for (int i = 0; i < MAX_NUM_FD; i++)
		file_array[i] = NULL;
}
