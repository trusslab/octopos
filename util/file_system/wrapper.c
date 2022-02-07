/* Simple wrapper for OctopOS file system
 * To use the file system as a standalone component
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <octopos/storage.h>
#include <octopos/io.h>
#include <arch/syscall.h>

uint32_t start_block;
uint32_t num_blocks;
uint32_t size;
FILE *filep;
uint32_t total_blocks = 0;

void wait_for_storage_for_os_use(void)
{
	/* No op */
}

int send_msg_to_storage_no_response(uint8_t *buf)
{
	/* write */
	if (buf[0] == IO_OP_SEND_DATA) {
		STORAGE_GET_TWO_ARGS
		start_block = arg0;
		num_blocks = arg1;
		if (start_block + num_blocks > total_blocks) {
			total_blocks = start_block + num_blocks;
		}
		size = 0;
	} else if (buf[0] == IO_OP_RECEIVE_DATA) { /* read */
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
	STORAGE_SET_TWO_RETS(0, size);
	return 0;
}

void read_from_storage_data_queue(uint8_t *buf)
{
	if (num_blocks == 0) {
		printf("Error: %s: too many block reads\n", __func__);
		exit(-1);
	}

	uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
	fseek(filep, seek_off, SEEK_SET);
	size += (uint32_t) fread(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE,
				 filep);
	start_block++;
	num_blocks--;
}

void write_to_storage_data_queue(uint8_t *buf)
{
	uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
	if (num_blocks == 0) {
		printf("Error: %s: too many block writes\n", __func__);
		exit(-1);
	}

	fseek(filep, seek_off, SEEK_SET);
	size += (uint32_t) fwrite(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE,
				  filep);
	start_block++;
	num_blocks--;
}
