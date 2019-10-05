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
#include <octopos/error.h>

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
	opcode[1] = Q_SERIAL_OUT;
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
	opcode[1] = Q_RUNTIME;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint8_t access_mode, uint8_t count)
{
	uint8_t opcode[6];

	opcode[0] = MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	opcode[3] = proc_id;
	opcode[4] = access_mode;
	opcode[5] = count;
	write(fd_out, opcode, 6);
}

int send_msg_to_storage(uint8_t *msg_buf, uint8_t *resp_buf) {
{
	uint8_t opcode[2], interrupt;

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_STORAGE_IN;
	write(fd_out, opcode, 2);
	write(fd_out, msg_buf, MAILBOX_QUEUE_MSG_SIZE);

	/* wait for response */
	read(fd_intr, &interrupt, 1);
	if (!(interrupt == Q_STORAGE_OUT)) {
		printf("Interrupt from an unexpected queue\n");
		_exit(-1);
		return ERR_UNEXPECTED;
	}

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_OUT;
	write(fd_out, opcode, 2), 
	read(fd_in, resp_buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

}
void initialize_shell(void);
void shell_process_input(char buf);
void process_system_call(uint8_t *buf);

static void distribute_input(void)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t queue_id;

	memset(input_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	recv_input(input_buf, &queue_id);
	if (queue_id == Q_KEYBOARD)
		shell_process_input((char) input_buf[0]);
	else if (queue_id == Q_OS)
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
