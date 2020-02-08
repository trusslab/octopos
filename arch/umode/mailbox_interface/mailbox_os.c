/* OctopOS OS mailbox interface */

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
#include <os/scheduler.h>
#include <os/shell.h>
#include <os/file_system.h>
#include <os/syscall.h>

int fd_out, fd_in, fd_intr;
pthread_t mailbox_thread;

sem_t interrupts[NUM_QUEUES + 1];
sem_t interrupt_input;
sem_t availables[NUM_QUEUES + 1];

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

int is_queue_available(uint8_t queue_id)
{
	int available;

	sem_getvalue(&availables[queue_id], &available);
	return available;
}

void wait_for_queue_availability(uint8_t queue_id)
{
	sem_wait(&availables[queue_id]);
}

void mark_queue_unavailable(uint8_t queue_id)
{
	sem_init(&availables[queue_id], 0, 0);
}

int send_output(uint8_t *buf)
{
	uint8_t opcode[2];

	int ret = is_queue_available(Q_SERIAL_OUT);
	if (!ret)
		sem_wait(&availables[Q_SERIAL_OUT]);

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
int recv_input(uint8_t *buf, uint8_t *queue_id)
{
	uint8_t opcode[2];
	int is_keyboard = 0, is_os1 = 0, is_os2 = 0; 
	static uint8_t turn = Q_OS1;

	sem_wait(&interrupt_input);

	sem_getvalue(&interrupts[Q_KEYBOARD], &is_keyboard);
	sem_getvalue(&interrupts[Q_OS1], &is_os1);
	sem_getvalue(&interrupts[Q_OS2], &is_os2);
	if (is_keyboard) {
		sem_wait(&interrupts[Q_KEYBOARD]);
		*queue_id = Q_KEYBOARD;
	} else {
		if (is_os1 && !is_os2) {
			sem_wait(&interrupts[Q_OS1]);
			*queue_id = Q_OS1;
			turn = Q_OS2;
		} else if (is_os2 && !is_os1) {
			sem_wait(&interrupts[Q_OS2]);
			*queue_id = Q_OS2;
			turn = Q_OS1;
		} else { /* is_os1 && is_os2 */
			sem_wait(&interrupts[turn]);
			*queue_id = turn;
			if (turn == Q_OS1)
				turn = Q_OS2;
			else
				turn = Q_OS1;
		}

	}

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = *queue_id;
	write(fd_out, opcode, 2);
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

static int send_msg_to_runtime_queue(uint8_t runtime_queue_id, uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = runtime_queue_id;

	sem_wait(&interrupts[opcode[1]]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int check_avail_and_send_msg_to_runtime(uint8_t runtime_proc_id, uint8_t *buf)
{
	uint8_t runtime_queue_id = get_runtime_queue_id(runtime_proc_id);
	if (!runtime_queue_id) {
		return ERR_INVALID;
	}

	int ret = is_queue_available(runtime_queue_id);
	if (!ret)
		return ERR_AVAILABLE;

	send_msg_to_runtime_queue(runtime_queue_id, buf);

	return 0;
}

int send_cmd_to_network(uint8_t *buf)
{
	uint8_t opcode[2];
	printf("%s [1]\n", __func__);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_NETWORK_CMD_IN;

	sem_wait(&interrupts[Q_NETWORK_CMD_IN]);
	printf("%s [2]\n", __func__);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_NETWORK_CMD_OUT;
	sem_wait(&interrupts[Q_NETWORK_CMD_OUT]);
	printf("%s [3]\n", __func__);
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

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
	sem_wait(&interrupts[Q_STORAGE_DATA_IN]);
	write(fd_out, opcode, 2), 
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt == 0) {
			/* timer interrupt */
			update_timer_ticks();
			sched_next_app();
		} else if (interrupt > (2 * NUM_QUEUES)) {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		} else if (interrupt > NUM_QUEUES) {
			switch ((interrupt - NUM_QUEUES)) {
			case Q_KEYBOARD:
				sem_init(&interrupts[Q_KEYBOARD], 0, 0);
				sem_post(&availables[Q_KEYBOARD]);
				break;
			case Q_SERIAL_OUT:
				sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
				sem_post(&availables[Q_SERIAL_OUT]);
				break;
			case Q_STORAGE_IN_2:
				sem_init(&interrupts[Q_STORAGE_IN_2], 0, MAILBOX_QUEUE_SIZE);
				sem_post(&availables[Q_STORAGE_IN_2]);
				break;
			case Q_STORAGE_OUT_2:
				sem_init(&interrupts[Q_STORAGE_OUT_2], 0, 0);
				sem_post(&availables[Q_STORAGE_OUT_2]);
				break;
			case Q_STORAGE_DATA_IN:
				sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
				sem_post(&availables[Q_STORAGE_DATA_IN]);
				break;
			case Q_STORAGE_DATA_OUT:
				sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
				sem_post(&availables[Q_STORAGE_DATA_OUT]);
				break;
			case Q_SENSOR:
				sem_init(&interrupts[Q_SENSOR], 0, 0);
				sem_post(&availables[Q_SENSOR]);
				break;
			case Q_RUNTIME1:
				sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE);
				sem_post(&availables[Q_RUNTIME1]);
				break;
			case Q_RUNTIME2:
				sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE);
				sem_post(&availables[Q_RUNTIME2]);
				break;
			}
		} else {
			sem_post(&interrupts[interrupt]);
			/* FIXME: we should use separate threads for these two */
			if (interrupt == Q_KEYBOARD || interrupt == Q_OS1 || interrupt == Q_OS2)
				sem_post(&interrupt_input);
		}
	}
}

int init_os_mailbox(void)
{
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
	sem_init(&interrupts[Q_NETWORK_CMD_IN], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_NETWORK_CMD_OUT], 0, 0);
	sem_init(&interrupts[Q_SENSOR], 0, 0);
	sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE);

	sem_init(&availables[Q_KEYBOARD], 0, 1);
	sem_init(&availables[Q_SERIAL_OUT], 0, 1);
	sem_init(&availables[Q_STORAGE_DATA_IN], 0, 1);
	sem_init(&availables[Q_STORAGE_DATA_OUT], 0, 1);
	sem_init(&availables[Q_STORAGE_CMD_IN], 0, 1);
	sem_init(&availables[Q_STORAGE_CMD_OUT], 0, 1);
	sem_init(&availables[Q_STORAGE_IN_2], 0, 1);
	sem_init(&availables[Q_STORAGE_OUT_2], 0, 1);
	sem_init(&availables[Q_NETWORK_CMD_IN], 0, 1);
	sem_init(&availables[Q_NETWORK_CMD_OUT], 0, 1);
	sem_init(&availables[Q_SENSOR], 0, 1);
	sem_init(&availables[Q_RUNTIME1], 0, 1);
	sem_init(&availables[Q_RUNTIME2], 0, 1);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	return 0;
}

void close_os_mailbox(void)
{
	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);

	close_channels();
}	
