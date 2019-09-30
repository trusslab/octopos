/* OctopOS mailbox frontend */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>

int fd_out;
int fd_in;
int fd_intr;

char input_buf[MAILBOX_QUEUE_MSG_SIZE];


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

int send_output(char *buf)
{
	char opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = SERIAL_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

static int recv_input(char *buf)
{
	char interrupt, opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = KEYBOARD;

	read(fd_intr, &interrupt, 1);
	write(fd_out, opcode, 2);
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int send_msg_to_runtime(char *buf)
{
	char opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = RUNTIME;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

void initialize_shell(void);
void shell_process_input(char buf);

static void distribute_input(void)
{
	memset(input_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	recv_input(input_buf);
	shell_process_input(input_buf[0]);
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
