/* OctopOS file system
 *
 * This file is used the OS, the installer, and the loader for storage.
 * We use macros ROLE_... to specialize, i.e., to compile only the needed code for each.
 */
#include <arch/defines.h>
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
#include <octopos/error.h>
#include <octopos/storage.h>
#include <os/storage.h>
#include <os/file_system.h>
#include <arch/mailbox_os.h>

#define MAX_FILENAME_SIZE	256

#ifdef ARCH_SEC_HW
#include <arch/sec_hw.h>
#endif

/* FIXME: hard-coded */
uint32_t partition_num_blocks = 0;

struct file {
	char filename[MAX_FILENAME_SIZE];
	uint32_t start_block; /* First block of file in the partition */
	uint32_t num_blocks;
	uint32_t size; /* in bytes */
	uint32_t dir_data_off;
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

static uint32_t write_blocks(uint8_t *data, uint32_t start_block, uint32_t num_blocks)
{
	wait_for_storage();

	STORAGE_SET_TWO_ARGS(start_block, num_blocks)
	buf[0] = STORAGE_OP_WRITE;
	send_msg_to_storage_no_response(buf);
	for (uint32_t i = 0; i < num_blocks; i++)
		write_to_storage_data_queue(data + (i * STORAGE_BLOCK_SIZE));
	get_response_from_storage(buf);

	STORAGE_GET_ONE_RET
	return ret0;
}

static uint32_t read_blocks(uint8_t *data, uint32_t start_block, uint32_t num_blocks)
{
	wait_for_storage();

	STORAGE_SET_TWO_ARGS(start_block, num_blocks)
	buf[0] = STORAGE_OP_READ;
	send_msg_to_storage_no_response(buf);
	for (uint32_t i = 0; i < num_blocks; i++)
		read_from_storage_data_queue(data + (i * STORAGE_BLOCK_SIZE));
	get_response_from_storage(buf);

	STORAGE_GET_ONE_RET
	return ret0;
}

static uint32_t read_from_block(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t read_size)
{
	uint8_t buf[STORAGE_BLOCK_SIZE];

	if (block_offset + read_size > STORAGE_BLOCK_SIZE)
		return 0;

	uint32_t ret = read_blocks(buf, block_num, 1);
	if (ret != STORAGE_BLOCK_SIZE)
		return 0;

	memcpy(data, buf + block_offset, read_size);

	return read_size;
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

	uint32_t ret = write_blocks(buf, block_num, 1);

	if (ret >= write_size)
		return write_size;
	else
		return ret;
}

static void flush_dir_data_to_storage(void)
{
	write_blocks(dir_data, 0, DIR_DATA_NUM_BLOCKS);
}

static void read_dir_data_from_storage(void)
{
	read_blocks(dir_data, 0, DIR_DATA_NUM_BLOCKS);
}

static int update_file_in_directory(struct file *file)
{
	int dir_data_off = file->dir_data_off;

	int filename_size = strlen(file->filename);
	if (filename_size > MAX_FILENAME_SIZE)
		return ERR_INVALID;

	if ((dir_data_off + filename_size + 15) > DIR_DATA_SIZE)
		return ERR_MEMORY;

	*((uint16_t *) &dir_data[dir_data_off]) = filename_size;
	dir_data_off += 2;

	strcpy((char *) &dir_data[dir_data_off], file->filename);
	dir_data_off += (filename_size + 1);

	*((uint32_t *) &dir_data[dir_data_off]) = file->start_block;
	dir_data_off += 4;
	*((uint32_t *) &dir_data[dir_data_off]) = file->num_blocks;
	dir_data_off += 4;
	*((uint32_t *) &dir_data[dir_data_off]) = file->size;

	return 0;
}

static int add_file_to_directory(struct file *file)
{
	file->dir_data_off = dir_data_ptr;

	int ret = update_file_in_directory(file);
	if (ret) {
		printf("Error: %s: couldn't update file info in directory\n", __func__);
		return ret;
	}

	dir_data_ptr += (strlen(file->filename) + 15);
	
	/* increment number of files */
	(*((uint16_t *) &dir_data[4]))++;

	flush_dir_data_to_storage();

	return 0;
}

static int remove_file_from_directory(struct file *file)
{
	int filename_size = *((uint16_t *) &dir_data[file->dir_data_off]);

	int file_dir_info_size = filename_size + 15;
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

static int expand_existing_file(struct file *file, uint32_t needed_blocks)
{
	/* Figure out if we have enough empty blocks to allocate.
	 * The empty blocks must be at the end of the file blocks.
	 */
	bool found = true;

	for (struct file_list_node *node = file_list_head; node;
	     node = node->next) {
		if ((node->file->start_block >= (file->start_block + file->num_blocks)) &&
		    (node->file->start_block < (file->start_block + file->num_blocks + needed_blocks))) {
			found = false;
			break;
		}
	}

	if (found) {
		if (file->start_block + file->num_blocks + needed_blocks >= partition_num_blocks)
			return ERR_FOUND;

		/* zero out the new blocks */
		uint8_t zero_buf[STORAGE_BLOCK_SIZE];
		memset(zero_buf, 0x0, STORAGE_BLOCK_SIZE);
		for (uint32_t i = 0; i < needed_blocks; i++) {
			write_blocks(zero_buf, file->start_block + file->num_blocks + i, 1);
		}

		file->num_blocks += needed_blocks;
		
		return 0;
	} else {
		return ERR_FOUND;
	}
}

static int expand_empty_file(struct file *file, uint32_t needed_blocks)
{
	/* Figure out if we have enough empty blocks to allocate.
	 * We will allocate space only after the last file.
	 */
	uint32_t start_block = DIR_DATA_NUM_BLOCKS;

	for (struct file_list_node *node = file_list_head; node;
	     node = node->next) {
		if (node->file->start_block >= start_block)
				start_block = node->file->start_block + node->file->num_blocks;
	}

	if (start_block + needed_blocks >= partition_num_blocks)
		return ERR_FOUND;

	/* zero out the new blocks */
	uint8_t zero_buf[STORAGE_BLOCK_SIZE];
	memset(zero_buf, 0x0, STORAGE_BLOCK_SIZE);
	for (uint32_t i = 0; i < needed_blocks; i++) {
		write_blocks(zero_buf, start_block + i, 1);
	}

	file->start_block = start_block;
	file->num_blocks = needed_blocks;

	return 0;
}

/*
 * @size: the overall size needed for the file to be expanded to.
 */
static int expand_file_size(struct file *file, uint32_t size)
{
	bool empty_file;
	uint32_t needed_size, needed_blocks;
	int ret = 0;

	if (file->size >= size)
		return 0;

	/* Figure out how many more blocks we need */
	if (file->size == 0) {
		empty_file = true;
		needed_size = size;
	} else {
		empty_file = false;
		needed_size = size - file->size;
	}
	printf("%s [1]: needed_size = %d\n", __func__, needed_size);

	needed_blocks = needed_size / STORAGE_BLOCK_SIZE;
	if (needed_size % STORAGE_BLOCK_SIZE)
		needed_blocks++;
	printf("%s [2]: needed_blocks = %d\n", __func__, needed_blocks);

	if (empty_file)
		ret = expand_empty_file(file, needed_blocks);
	else
		ret = expand_existing_file(file, needed_blocks);

	if (!ret) {
		file->size = size;
		ret = update_file_in_directory(file);
		if (ret)
			/* FIXME: the dir is not consistent with the in-memory file info. */
			printf("Error: %s: couldn't update file info in directory.\n", __func__);
		flush_dir_data_to_storage();
	}

	return ret;
}

static void release_file_blocks(struct file *file)
{
	/* No op */
}

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

		file->start_block = 0;
		file->num_blocks = 0;
		file->size = 0;

		int ret = add_file_to_directory(file);
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

/*
 * This API allows growing the file size, but only if there is enough empty blocks
 * right after the last file block in the partition.
 */
uint32_t file_system_write_to_file(uint32_t fd, uint8_t *data, uint32_t size, uint32_t offset)
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
	printf("%s [0.1]: offset = %d\n", __func__, offset);
	printf("%s [0.2]: size = %d\n", __func__, size);
	printf("%s [1]: file->size = %d\n", __func__, file->size);
	printf("%s [2]: file->start_block = %d\n", __func__, file->start_block);
	printf("%s [3]: file->num_blocks = %d\n", __func__, file->num_blocks);

	if (file->size < (offset + size)) {
		/* Try to expand the file size */
		expand_file_size(file, offset + size);
	}

	if (offset >= file->size) {
		return 0;
	}

	/* partial write */
	if (file->size < (offset + size)) {
		size = file->size - offset; 
	}

	uint32_t block_num = offset / STORAGE_BLOCK_SIZE;
	uint32_t block_offset = offset % STORAGE_BLOCK_SIZE;
	uint32_t written_size = 0;
	uint32_t next_write_size = STORAGE_BLOCK_SIZE - block_offset;
	if (next_write_size > size)
		next_write_size = size;
	uint32_t ret = 0;

	while (written_size < size) {
		printf("%s [4]: written_size = %d\n", __func__, written_size);
		printf("%s [4.1]: next_write_size = %d\n", __func__, next_write_size);
		ret = write_to_block(&data[written_size], file->start_block + block_num,
				block_offset, next_write_size);
		printf("%s [4.2]: ret = %d\n", __func__, ret);
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
	printf("%s [5]: written_size = %d\n", __func__, written_size);

	return written_size;
}

uint32_t file_system_read_from_file(uint32_t fd, uint8_t *data, uint32_t size, uint32_t offset)
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

	printf("%s [1]: file->num_blocks = %d\n", __func__, file->num_blocks);

	if (offset >= file->size) {
		return 0;
	}

	/* partial read */
	if (file->size < (offset + size)) {
		size = file->size - offset; 
	}

	uint32_t block_num = offset / STORAGE_BLOCK_SIZE;
	uint32_t block_offset = offset % STORAGE_BLOCK_SIZE;
	uint32_t read_size = 0;
	uint32_t next_read_size = STORAGE_BLOCK_SIZE - block_offset;
	if (next_read_size > size)
		next_read_size = size;
	uint32_t ret = 0;

	while (read_size < size) {
		printf("%s [2]: next_read_size = %d\n", __func__, next_read_size);
		ret = read_from_block(&data[read_size], file->start_block + block_num,
				block_offset, next_read_size);
		printf("%s [3]: ret = %d\n", __func__, ret);
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
	printf("%s [4]: read_size = %d\n", __func__, read_size);

	return read_size;
}

#ifdef ROLE_OS
/*
 * @start_block: the first file block to write.
 * This API doesn't allow growing the file size.
 */
uint8_t file_system_write_file_blocks(uint32_t fd, uint32_t start_block, uint32_t num_blocks, uint8_t runtime_proc_id)
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

	wait_for_storage();

	wait_until_empty(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

	mark_queue_unavailable(Q_STORAGE_DATA_IN);

#ifndef ARCH_SEC_HW
	mailbox_change_queue_access(Q_STORAGE_DATA_IN, WRITE_ACCESS,
							runtime_proc_id, (uint8_t) num_blocks);
#else
	mailbox_change_queue_access(Q_STORAGE_DATA_IN, WRITE_ACCESS,
							runtime_proc_id, (uint16_t) num_blocks);
#endif

	STORAGE_SET_TWO_ARGS(file->start_block + start_block, num_blocks)
	buf[0] = STORAGE_OP_WRITE;
	send_msg_to_storage_no_response(buf);

	return Q_STORAGE_DATA_IN;
}

void file_system_write_file_blocks_late(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	/* FIXME: pretty inefficient. Why wait if we don't check the response? */
	get_response_from_storage(buf);
}

/*
 * @start_block: the first file block to read.
 */
uint8_t file_system_read_file_blocks(uint32_t fd, uint32_t start_block, uint32_t num_blocks, uint8_t runtime_proc_id)
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

	wait_for_storage();

	mark_queue_unavailable(Q_STORAGE_DATA_OUT);

#ifndef ARCH_SEC_HW
	mailbox_change_queue_access(Q_STORAGE_DATA_OUT, READ_ACCESS,
							runtime_proc_id, (uint8_t) num_blocks);
#else
	mailbox_change_queue_access(Q_STORAGE_DATA_OUT, READ_ACCESS,
							runtime_proc_id, (uint16_t) num_blocks);
#endif

	STORAGE_SET_TWO_ARGS(file->start_block + start_block, num_blocks)
	buf[0] = STORAGE_OP_READ;
	send_msg_to_storage_no_response(buf);

	return Q_STORAGE_DATA_OUT;
}

void file_system_read_file_blocks_late(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	/* FIXME: pretty inefficient. Why wait if we don't check the response? */
	get_response_from_storage(buf);
}
#endif /* ROLE_OS */

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

void initialize_file_system(uint32_t _partition_num_blocks)
{
	/* initialize fd bitmap */
	if (MAX_NUM_FD % 8) {
		printf("%s: Error: MAX_NUM_FD must be divisible by 8\n", __func__);
		_exit(-1);
	}

	fd_bitmap[0] = 0x00000001; /* fd 0 is error */
	for (int i = 1; i < (MAX_NUM_FD / 8); i++)
		fd_bitmap[i] = 0;


#ifdef ROLE_OS
	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error (file system): storage data queue msg size must be equal to storage block size\n");
		exit(-1);
	}
#endif

	partition_num_blocks = _partition_num_blocks;

	/* wipe dir */
	//memset(dir_data, 0x0, DIR_DATA_SIZE);
	//flush_dir_data_to_storage();
	//exit(-1);

	/* read the directory */
	read_dir_data_from_storage();

	/* check to see if there's a valid directory */
	if (dir_data[0] == '$' && dir_data[1] == '%' &&
	    dir_data[2] == '^' && dir_data[3] == '&') {
		printf("%s [1]: existing dir\n", __func__);
		/* retrieve file info */
		uint16_t num_files = *((uint16_t *) &dir_data[4]);
		dir_data_ptr = 6;

		for (int i = 0; i < num_files; i++) {
			int dir_data_off = dir_data_ptr;
			if ((dir_data_ptr + 2) > DIR_DATA_SIZE)
				break;
			int filename_size = *((uint16_t *) &dir_data[dir_data_ptr]);
			if ((dir_data_ptr + filename_size + 15) > DIR_DATA_SIZE)
				break;
			dir_data_ptr += 2;

			if (filename_size > MAX_FILENAME_SIZE)
				break;

			struct file *file = (struct file *) malloc(sizeof(struct file));
			if (!file)
				break;

			strcpy(file->filename, (char *) &dir_data[dir_data_ptr]);
			dir_data_ptr = dir_data_ptr + filename_size + 1;

			file->dir_data_off = dir_data_off;
			file->start_block = *((uint32_t *) &dir_data[dir_data_ptr]);
			dir_data_ptr += 4;
			file->num_blocks = *((uint32_t *) &dir_data[dir_data_ptr]);
			dir_data_ptr += 4;
			file->size = *((uint32_t *) &dir_data[dir_data_ptr]);
			dir_data_ptr += 4;

			add_file_to_list(file);
		}
	} else {
		printf("%s [1]: new dir\n", __func__);
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

void close_file_system(void)
{
	/* Not currently useful as we flush on every update. */
	flush_dir_data_to_storage();
}
