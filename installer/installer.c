/* OctopOS installer
 * Helps prepare the system image
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <octopos/storage.h>
#include <os/file_system.h>
#include <arch/syscall.h>

/* FIXME: copied from storage/storage.c */
#define STORAGE_SET_ONE_RET(ret0)		\
	SERIALIZE_32(ret0, &buf[0])

/* FIXME: copied from storage/storage.c */
#define STORAGE_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	arg0 = *((uint32_t *) &buf[1]); \
	arg1 = *((uint32_t *) &buf[5]); \

void wait_for_storage(void)
{
	/* No op */
	printf("%s [1]\n", __func__);
}

void wait_until_empty(uint8_t queue_id, int queue_size)
{
	/* No op */
	printf("%s [1]\n", __func__);
}

void mark_queue_unavailable(uint8_t queue_id)
{
	/* No op */
	printf("%s [1]\n", __func__);
}

void mailbox_change_queue_access(uint8_t queue_id, uint8_t access,
				 uint8_t proc_id, uint8_t count)
{
	/* No op */
	printf("%s [1]\n", __func__);
}

uint32_t start_block;
uint32_t num_blocks;
uint32_t size;
FILE *filep;
uint32_t total_blocks = 0;

int send_msg_to_storage_no_response(uint8_t *buf)
{
	printf("%s [1]\n", __func__);

	/* write */
	if (buf[0] == STORAGE_OP_WRITE) {
		STORAGE_GET_TWO_ARGS
		start_block = arg0;
		num_blocks = arg1;
		if (start_block + num_blocks > total_blocks) {
			total_blocks = start_block + num_blocks;
			printf("%s [2]: total_blocks = %d\n", __func__, total_blocks);
		}
		size = 0;
	} else if (buf[0] == STORAGE_OP_READ) { /* read */
		STORAGE_GET_TWO_ARGS
		start_block = arg0;
		num_blocks = arg1;
		if (start_block + num_blocks > total_blocks) {
			printf("%s: Error: invalid args (read)\n", __func__);
			exit(-1);
		}
		size = 0;
	} else {
		printf("Error: %s: invalid operation (%d)\n", __func__, buf[0]);
		exit(-1);
	}

	return 0;
}

int get_response_from_storage(uint8_t *buf)
{
	printf("%s [1]\n", __func__);
	STORAGE_SET_ONE_RET(size);
	return 0;
}

void read_from_storage_data_queue(uint8_t *buf)
{
	/* No op */
	printf("%s [1]: start_block = %d, num_blocks = %d\n", __func__, start_block, num_blocks);
	if (num_blocks == 0) {
		printf("Error: %s: too many block reads\n", __func__);
		exit(-1);
	}

	uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
	fseek(filep, seek_off, SEEK_SET);
	size += (uint32_t) fread(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
	printf("%s [2]: size = %d\n", __func__, size);
	//printf("%s [3]: %c %c %c %c\n", __func__, buf[0], buf[1], buf[2], buf[3]);
	start_block++;
	num_blocks--;
}

void write_to_storage_data_queue(uint8_t *buf)
{
	printf("%s [1]: start_block = %d, num_blocks = %d\n", __func__, start_block, num_blocks);
	uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
	if (num_blocks == 0) {
		printf("Error: %s: too many block writes\n", __func__);
		exit(-1);
	}

	//printf("%s [2]: %c %c %c %c\n", __func__, buf[0], buf[1], buf[2], buf[3]);
	fseek(filep, seek_off, SEEK_SET);
	size += (uint32_t) fwrite(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, filep);
	printf("%s [3]: size = %d\n", __func__, size);
	start_block++;
	num_blocks--;
}

int main(int argc, char **argv)
{
	printf("%s [1]\n", __func__);
	uint32_t fd;
	FILE *src_filep, *copy_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int _size;
	int offset;

	filep = fopen("partition", "r+");
	if (!filep) {
		printf("%s: Creating partition file.\n", __func__);
		filep = fopen("partition", "w");
		fclose(filep);
		filep = fopen("partition", "r+");
		if (!filep) {
			printf("Error: %s: Couldn't create/open the partition file.\n", __func__);
			return -1;
		}
	}

	total_blocks += DIR_DATA_NUM_BLOCKS;

	initialize_file_system();

	fd = file_system_open_file((char *) "keyboard", FILE_OPEN_CREATE_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open keyboard in octopos file system.\n", __func__);
		return -1;
	}

	src_filep = fopen("keyboard", "r");
	if (!src_filep) {
		printf("Error: %s: Couldn't open the keyboard source file.\n", __func__);
		return -1;
	}

	offset = 0;

	while (1) { 
		printf("%s [2]: offset = %d\n", __func__, offset);
		fseek(src_filep, offset, SEEK_SET);
		_size = fread(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, src_filep);
		printf("%s [3]: _size = %d\n", __func__, _size);
		if (_size == 0)
			break;

		if (_size < 0 || _size > STORAGE_BLOCK_SIZE) {
			printf("Error: %s: reading file.\n", __func__);
			break;
		}

		file_system_write_to_file(fd, buf, _size, offset);

		offset += _size;
	}

	fclose(src_filep);
	file_system_close_file(fd);
	
	printf("%s: total number of written blocks = %d\n", __func__, total_blocks);

	/* test start */
	fd = file_system_open_file((char *) "keyboard", FILE_OPEN_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open keyboard in octopos file system (test).\n", __func__);
		return -1;
	}

	copy_filep = fopen("keyboard_copy", "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the keyboard copy file.\n", __func__);
		return -1;
	}

	offset = 0;

	for (int i = 0; i < 28; i++) {
		printf("%s [4]: offset = %d\n", __func__, offset);
		if (i == 27)
			_size = file_system_read_from_file(fd, buf, 408, offset);
		else
			_size = file_system_read_from_file(fd, buf, STORAGE_BLOCK_SIZE, offset);
		printf("%s [5]: _size = %d\n", __func__, _size);
		if (_size == 0)
			break;

		if (_size < 0 || _size > STORAGE_BLOCK_SIZE) {
			printf("Error: %s: reading file.\n", __func__);
			break;
		}

		fseek(copy_filep, offset, SEEK_SET);
		fwrite(buf, sizeof(uint8_t), _size, copy_filep);

		offset += _size;
	}

	fclose(copy_filep);
	file_system_close_file(fd);
	/* test end */

	fclose(filep);

	return 0;
}	
