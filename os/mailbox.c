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
sem_t interrupt_input;

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
	sem_wait(&interrupts[Q_SERIAL_OUT]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

/* reads from Q_OS's and Q_KEYBOARD */
/* FIXME: we should use separate threads for keyboard and syscalls */
/* FIXME: not scalable to more than two runtimes */
static int recv_input(uint8_t *buf, uint8_t *queue_id)
{
	uint8_t opcode[2];
	int is_keyboard = 0, is_os1 = 0, is_os2 = 0; 
	printf("%s [1]\n", __func__);
	static uint8_t turn = Q_OS1;

	sem_wait(&interrupt_input);

	sem_getvalue(&interrupts[Q_KEYBOARD], &is_keyboard);
	sem_getvalue(&interrupts[Q_OS1], &is_os1);
	sem_getvalue(&interrupts[Q_OS2], &is_os2);
	if (is_keyboard) {
		printf("%s [2]\n", __func__);
		sem_wait(&interrupts[Q_KEYBOARD]);
		*queue_id = Q_KEYBOARD;
	} else {
		if (is_os1 && !is_os2) {
			printf("%s [3]\n", __func__);
			sem_wait(&interrupts[Q_OS1]);
			*queue_id = Q_OS1;
			turn = Q_OS2;
		} else if (is_os2 && !is_os1) {
			printf("%s [4]\n", __func__);
			sem_wait(&interrupts[Q_OS2]);
			*queue_id = Q_OS2;
			turn = Q_OS1;
		} else { /* is_os1 && is_os2 */
			printf("%s [5]\n", __func__);
			sem_wait(&interrupts[turn]);
			*queue_id = turn;
			if (turn == Q_OS1)
				turn = Q_OS2;
			else
				turn = Q_OS1;
		}

	}
	printf("%s [3]\n", __func__);

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
	sem_wait(&interrupts[opcode[1]]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

/* Only to be used for queues that OS writes to */
/* FIXME: busy-waiting */
void wait_until_empty(uint8_t queue_id, int queue_size)
{
	int left;
	
	while (1) {
		sem_getvalue(&interrupts[queue_id], &left);
		if (left == queue_size)
			break;
	}
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
	sem_wait(&interrupts[Q_STORAGE_CMD_IN]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int get_response_from_storage(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_CMD_OUT;
	sem_wait(&interrupts[Q_STORAGE_CMD_OUT]);
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

void read_from_storage_data_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_DATA_OUT;
	sem_wait(&interrupts[Q_STORAGE_DATA_OUT]);
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void write_to_storage_data_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_STORAGE_DATA_IN;
	printf("%s [1]\n", __func__);
	sem_wait(&interrupts[Q_STORAGE_DATA_IN]);
	printf("%s [2]\n", __func__);
	write(fd_out, opcode, 2), 
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

static void distribute_input(void)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t queue_id;
	printf("%s [1]\n", __func__);

	memset(input_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	/* FIXME: we should use separate threads for these two */
	recv_input(input_buf, &queue_id);
	printf("%s [2]: queue_id = %d\n", __func__, queue_id);
	if (queue_id == Q_KEYBOARD) {
		shell_process_input((char) input_buf[0]);
	} else if (queue_id == Q_OS1) {
		process_system_call(input_buf, P_RUNTIME1);
	} else if (queue_id == Q_OS2) {
		process_system_call(input_buf, P_RUNTIME2);
	} else {
		printf("Error (%s): invalid queue_id (%d)\n", __func__, queue_id);
		exit(-1);
	}
}

static void *handle_mailbox_interrupts(void *data)
{

	uint8_t interrupt;
	printf("%s [1]\n", __func__);

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt < 1 || interrupt > NUM_QUEUES) {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
		sem_post(&interrupts[interrupt]);
		/* FIXME: we should use separate threads for these two */
		if (interrupt == Q_KEYBOARD || interrupt == Q_OS1 || interrupt == Q_OS2)
			sem_post(&interrupt_input);
	}
}

int main()
{
	pthread_t mailbox_thread;

	intialize_channels();
	
	sem_init(&interrupts[Q_OS1], 0, 0);
	sem_init(&interrupts[Q_OS2], 0, 0);
	sem_init(&interrupts[Q_KEYBOARD], 0, 0);
	sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
	sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, 0);
	sem_init(&interrupts[Q_STORAGE_IN_2], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_OUT_2], 0, 0);
	sem_init(&interrupts[Q_SENSOR], 0, 0);
	sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}
	printf("%s [1]\n", __func__);

	initialize_shell();
	initialize_file_system();
	initialize_scheduler();
	printf("%s [2]\n", __func__);

	while (1) {
		printf("%s [3]\n", __func__);
		distribute_input();
		sched_next_app();
	}

	pthread_join(mailbox_thread, NULL);

	close_channels();
	
	return 0;
}
