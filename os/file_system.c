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

/* FIXME: move to header file */
int send_msg_to_storage(uint8_t *msg_buf, uint8_t *resp_buf);

uint32_t file_system_open_file(char *filename)
{
	return (uint32_t) 10;
}

int file_system_write_to_file(uint32_t fd, uint8_t *data, int size, int offset)
{
	if (size != 4) {
		printf("%s: size not supported\n", __func__);
		return 0;
	}

	uint32_t intdata = *((uint32_t *) data);
	uint8_t data_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t resp_buf[MAILBOX_QUEUE_MSG_SIZE];
	data_buf[0] = 0; /* write */
	*((uint32_t *) &data_buf[1]) = intdata;
	send_msg_to_storage(data_buf, resp_buf);
	return 4;
}


int file_system_read_from_file(uint32_t fd, uint8_t *data, int size, int offset)
{
	if (size != 4) {
		printf("%s: size not supported\n", __func__);
		return 0;
	}
	uint8_t data_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t resp_buf[MAILBOX_QUEUE_MSG_SIZE];
	data_buf[0] = 1; /* read */
	send_msg_to_storage(data_buf, resp_buf);
	memcpy(data, &resp_buf[1], 4);
	return 4;
}

int file_system_close_file(uint32_t fd)
{
	return 0;
}
