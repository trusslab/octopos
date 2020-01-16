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
#include "scheduler.h"
#include "shell.h"
#include "file_system.h"
#include "syscall.h"

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

int send_msg_to_runtime(uint8_t runtime_proc_id, uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	/* FIXME: use get_runtime_queue_id() */
	switch(runtime_proc_id) {
	case P_RUNTIME1:
		opcode[1] = Q_RUNTIME1;
		break;
	case P_RUNTIME2:
		opcode[1] = Q_RUNTIME2;
		break;
	default:
		printf("Error (%s): unexpected runtime_proc_id (%d).\n", __func__, runtime_proc_id);
		return -1;
	}
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint8_t count)
{
	uint8_t opcode[5];

	opcode[0] = MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	opcode[3] = proc_id;
	opcode[4] = count;
	write(fd_out, opcode, 5);
}

/* FIXME: needed? */
int send_msg_to_storage(uint8_t *buf)
{
	uint8_t opcode[2], interrupt;

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_STORAGE_CMD_IN;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	/* wait for response */
	while (1) {
		read(fd_intr, &interrupt, 1);
		if (!(interrupt == Q_STORAGE_CMD_OUT) && !(interrupt == Q_STORAGE_DATA_OUT)) {
			printf("Error (%s): Interrupt from an unexpected queue (%d)\n", __func__, interrupt);
			_exit(-1);
			return ERR_UNEXPECTED;
		}

		if (interrupt == Q_STORAGE_CMD_OUT)
			break;
	}

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_CMD_OUT;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int send_msg_to_storage_no_response(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_STORAGE_CMD_IN;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int get_response_from_storage(uint8_t *buf)
{
	uint8_t opcode[2], interrupt;

	/* wait for response */
	read(fd_intr, &interrupt, 1);
	if (!(interrupt == Q_STORAGE_CMD_OUT)) {
		printf("Error (%s): Interrupt from an unexpected queue (%d)\n", __func__, interrupt);
		_exit(-1);
		return ERR_UNEXPECTED;
	}

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_CMD_OUT;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

void read_from_storage_data_queue(uint8_t *buf)
{
	uint8_t opcode[2], interrupt;
	printf("%s [1]\n", __func__);

	/* wait for data */
	read(fd_intr, &interrupt, 1);
	if (!(interrupt == Q_STORAGE_DATA_OUT)) {
		printf("Error (%s): Interrupt from an unexpected queue (%d)\n", __func__, interrupt);
		_exit(-1);
		return;
	}
	printf("%s [2]\n", __func__);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_DATA_OUT;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
	printf("%s [3]\n", __func__);
}

void write_to_storage_data_queue(uint8_t *buf)
{
	uint8_t opcode[2];
	printf("%s [1]\n", __func__);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_STORAGE_DATA_IN;
	write(fd_out, opcode, 2), 
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
	printf("%s [2]\n", __func__);
}



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
	initialize_file_system();
	initialize_scheduler();

	while (1) {
		distribute_input();
		sched_next_app();
	}

	close_channels();
	return 0;
}
