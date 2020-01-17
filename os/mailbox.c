/* OctopOS mailbox frontend */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
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

sem_t interrupts[NUM_QUEUES + 1];

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

/* reads from Q_OS and Q_KEYBOARD */
/* FIXME: we should use separate threads for these two */
static int recv_input(uint8_t *buf, uint8_t *queue_id)
{
	uint8_t opcode[2];
	int is_keyboard = 0; 

	sem_wait(&interrupts[Q_OS]);
	*queue_id = Q_OS;

	sem_getvalue(&interrupts[Q_KEYBOARD], &is_keyboard);
	if (is_keyboard) {
		sem_wait(&interrupts[Q_KEYBOARD]);
		*queue_id = Q_KEYBOARD;
	}

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = *queue_id;
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
	uint8_t opcode[2];

	sem_wait(&interrupts[Q_STORAGE_CMD_OUT]);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_CMD_OUT;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

void read_from_storage_data_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[Q_STORAGE_DATA_OUT]);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_DATA_OUT;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void write_to_storage_data_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_STORAGE_DATA_IN;
	write(fd_out, opcode, 2), 
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

static void distribute_input(void)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t queue_id;

	memset(input_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	/* FIXME: we should use separate threads for these two */
	recv_input(input_buf, &queue_id);
	if (queue_id == Q_KEYBOARD)
		shell_process_input((char) input_buf[0]);
	else if (queue_id == Q_OS)
		process_system_call(input_buf);
	else
		printf("Error: Interrupt received from an invalid queue\n");
}

static void *handle_mailbox_interrupts(void *data)
{

	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt < 1 || interrupt > NUM_QUEUES) {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
		sem_post(&interrupts[interrupt]);
		/* FIXME: we should use separate threads for these two */
		if (interrupt == Q_KEYBOARD) {
			sem_post(&interrupts[Q_OS]);
		}
	}
}

int main()
{
	pthread_t mailbox_thread;
	for (int i = 0; i <= NUM_QUEUES; i++)
		sem_init(&interrupts[i], 0, 0);
	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		exit(-1);
	}

	intialize_channels();
	initialize_shell();
	initialize_file_system();
	initialize_scheduler();

	while (1) {
		distribute_input();
		sched_next_app();
	}

	pthread_join(mailbox_thread, NULL);

	close_channels();
	return 0;
}
