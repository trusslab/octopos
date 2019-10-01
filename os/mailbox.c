/* OctopOS mailbox frontend */

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

int fd_out;
int fd_in;
int fd_intr;

static int intialize_channels(void)
{
	mkfifo(FIFO_OS_OUT, 0666);
	mkfifo(FIFO_OS_IN, 0666);
	mkfifo(FIFO_OS_INTR, 0666);

	fd_out = open(FIFO_OS_OUT, O_WRONLY);
	fd_in = open(FIFO_OS_IN, O_RDONLY);
	fd_intr = open(FIFO_OS_INTR, O_RDONLY);

	return 0;
}

static void close_channels(void)
{
	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_OS_OUT);
	remove(FIFO_OS_IN);
	remove(FIFO_OS_INTR);
}

int send_output(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = SERIAL_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

static int recv_input(uint8_t *buf, uint8_t *queue_id)
{
	uint8_t interrupt, opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;

	read(fd_intr, &interrupt, 1);
	opcode[1] = interrupt;
	*queue_id = interrupt;
	write(fd_out, opcode, 2);
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int send_msg_to_runtime(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = RUNTIME;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

void initialize_shell(void);
void shell_process_input(char buf);

/* FIXME: move to a different file */
void process_system_call(uint8_t *buf)
{
	uint8_t opcode[2], ret;
	if (buf[0] == RUNTIME) {
		uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];

		if (buf[1] == 0) {
			opcode[0] = MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS;
			opcode[1] = 0;
			write(fd_out, opcode, 2);
			ret = 0;
		} else if (buf[1] == 1) {
			opcode[0] = MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS;
			opcode[1] = 1;
			write(fd_out, opcode, 2);
			ret = 0;
		} else if (buf[1] == 2) {
			opcode[0] = MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS;
			opcode[1] = 2;
			write(fd_out, opcode, 2);
			ret = 0;
		} else if (buf[1] == 3) {
			opcode[0] = MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS;
			opcode[1] = 3;
			write(fd_out, opcode, 2);
			ret = 0;
		} else {
			printf("Error: invalid syscall\n");
			ret = 1;
		}

		/* send response */
		ret_buf[0] = ret;
		opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
		opcode[1] = RUNTIME;
		write(fd_out, opcode, 2);
		write(fd_out, ret_buf, MAILBOX_QUEUE_MSG_SIZE);
	} else {
		printf("Error: invalid data\n");
	}

}

static void distribute_input(void)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t queue_id;

	memset(input_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	recv_input(input_buf, &queue_id);
	if (queue_id == KEYBOARD)
		shell_process_input((char) input_buf[0]);
	else if (queue_id == OS)
		process_system_call(input_buf);
	else
		printf("Error: Interrupt received from an invalid queue\n");
}

int main()
{
	intialize_channels();
	initialize_shell();

	while (1) {
		distribute_input();
	}

	close_channels();
	return 0;
}
