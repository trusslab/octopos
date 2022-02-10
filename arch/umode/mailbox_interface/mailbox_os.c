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
#include <arch/mailbox.h>

int fd_out, fd_in, fd_intr;
pthread_t mailbox_thread;

sem_t interrupts[NUM_QUEUES + 1];
sem_t interrupt_input;
sem_t availables[NUM_QUEUES + 1];

static int intialize_channels(void)
{
#ifdef ROLE_BOOTLOADER_OS
	mkfifo(FIFO_OS_OUT, 0666);
	mkfifo(FIFO_OS_IN, 0666);
	mkfifo(FIFO_OS_INTR, 0666);
#endif

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

#ifdef ROLE_OS
	remove(FIFO_OS_OUT);
	remove(FIFO_OS_IN);
	remove(FIFO_OS_INTR);
#endif
}

int is_queue_available(uint8_t queue_id)
{
	int available;

	sem_getvalue(&availables[queue_id], &available);
	return available;
}

/*
 * When this function returns, the queue is available
 * and the available semaphore is 1. If one needs to use
 * the queue, one needs to mark it unavailable.
 */ 
void wait_for_queue_availability(uint8_t queue_id)
{
	sem_wait(&availables[queue_id]);
	sem_init(&availables[queue_id], 0, 1);
}

void mark_queue_unavailable(uint8_t queue_id)
{
	sem_init(&availables[queue_id], 0, 0);
}

#ifdef ROLE_OS
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
	int is_keyboard = 0, is_os1 = 0, is_os2 = 0, is_osu = 0; 
	static uint8_t turn = Q_OS1;

	sem_wait(&interrupt_input);

	sem_getvalue(&interrupts[Q_KEYBOARD], &is_keyboard);
	sem_getvalue(&interrupts[Q_OS1], &is_os1);
	sem_getvalue(&interrupts[Q_OS2], &is_os2);
	sem_getvalue(&interrupts[Q_OSU], &is_osu);
	if (is_keyboard) {
		sem_wait(&interrupts[Q_KEYBOARD]);
		*queue_id = Q_KEYBOARD;
	} else if (is_os1 && !is_os2) {
		sem_wait(&interrupts[Q_OS1]);
		*queue_id = Q_OS1;
		turn = Q_OS2;
	} else if (is_os2 && !is_os1) {
		sem_wait(&interrupts[Q_OS2]);
		*queue_id = Q_OS2;
		turn = Q_OS1;
	} else if (is_os1 && is_os2) {
		sem_wait(&interrupts[turn]);
		*queue_id = turn;
		if (turn == Q_OS1)
			turn = Q_OS2;
		else
			turn = Q_OS1;
	} else if (is_osu) {
		sem_wait(&interrupts[Q_OSU]);
		*queue_id = Q_OSU;
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

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_NETWORK_CMD_IN;

	sem_wait(&interrupts[Q_NETWORK_CMD_IN]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_NETWORK_CMD_OUT;
	sem_wait(&interrupts[Q_NETWORK_CMD_OUT]);
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int send_cmd_to_untrusted(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_UNTRUSTED;

	sem_wait(&interrupts[Q_UNTRUSTED]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int send_cmd_to_bluetooth(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_BLUETOOTH_CMD_IN;

	sem_wait(&interrupts[Q_BLUETOOTH_CMD_IN]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_BLUETOOTH_CMD_OUT;
	sem_wait(&interrupts[Q_BLUETOOTH_CMD_OUT]);
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}
#endif /* ROLE_OS */

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

/*
 * Compares limit and timeout to the max vals allowed and use
 * the max vals if larger.
 */
void mailbox_delegate_queue_access(uint8_t queue_id, uint8_t proc_id,
				   limit_t limit, timeout_t timeout)
{
	uint8_t opcode[2];
	mailbox_state_reg_t new_state;

	new_state.owner = proc_id;
//FIXME : consider infinit delegation
//	if (limit > MAILBOX_MAX_LIMIT_VAL)
//		new_state.limit = MAILBOX_MAX_LIMIT_VAL;
//	else
//		new_state.limit = limit;
//
	new_state.limit = limit;

	if (timeout > MAILBOX_MAX_TIMEOUT_VAL)
		new_state.timeout = MAILBOX_MAX_TIMEOUT_VAL;
	else
		new_state.timeout = timeout;

	opcode[0] = MAILBOX_OPCODE_DELEGATE_QUEUE_ACCESS;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2);
	write(fd_out, &new_state, sizeof(mailbox_state_reg_t));
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
#ifdef ROLE_OS
			/* timer interrupt */
			update_timer_ticks();
			sched_next_app();
#endif
		} else if (interrupt > (2 * NUM_QUEUES)) {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		} else if (interrupt > NUM_QUEUES) {
			/* FIXME: some of the cases can be merged together */
			switch ((interrupt - NUM_QUEUES)) {
#ifdef ROLE_OS
			case Q_KEYBOARD:
				sem_init(&interrupts[Q_KEYBOARD], 0, 0);
				sem_post(&availables[Q_KEYBOARD]);
				break;
			case Q_SERIAL_OUT:
				sem_init(&interrupts[Q_SERIAL_OUT], 0,
					 MAILBOX_QUEUE_SIZE);
				sem_post(&availables[Q_SERIAL_OUT]);
				break;
#endif
			case Q_STORAGE_CMD_IN:
				sem_init(&interrupts[Q_STORAGE_CMD_IN], 0,
					 MAILBOX_QUEUE_SIZE);
				sem_post(&availables[Q_STORAGE_CMD_IN]);
				break;
			case Q_STORAGE_CMD_OUT:
				sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, 0);
				sem_post(&availables[Q_STORAGE_CMD_OUT]);
				break;
#ifdef ROLE_OS
			case Q_STORAGE_DATA_IN:
				sem_init(&interrupts[Q_STORAGE_DATA_IN], 0,
					 MAILBOX_QUEUE_SIZE_LARGE);
				sem_post(&availables[Q_STORAGE_DATA_IN]);
				break;
#endif
			case Q_STORAGE_DATA_OUT:
				sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
				sem_post(&availables[Q_STORAGE_DATA_OUT]);
				break;
#ifdef ROLE_OS
			case Q_NETWORK_DATA_IN:
				sem_init(&interrupts[Q_NETWORK_DATA_IN], 0,
					 MAILBOX_QUEUE_SIZE_LARGE);
				sem_post(&availables[Q_NETWORK_DATA_IN]);
				break;
			case Q_NETWORK_DATA_OUT:
				sem_init(&interrupts[Q_NETWORK_DATA_OUT], 0, 0);
				sem_post(&availables[Q_NETWORK_DATA_OUT]);
				break;
			case Q_BLUETOOTH_CMD_IN:
				sem_init(&interrupts[Q_BLUETOOTH_CMD_IN], 0,
					 MAILBOX_QUEUE_SIZE);
				sem_post(&availables[Q_BLUETOOTH_CMD_IN]);
				break;
			case Q_BLUETOOTH_CMD_OUT:
				sem_init(&interrupts[Q_BLUETOOTH_CMD_OUT], 0, 0);
				sem_post(&availables[Q_BLUETOOTH_CMD_OUT]);
				break;
			case Q_BLUETOOTH_DATA_IN:
				sem_init(&interrupts[Q_BLUETOOTH_DATA_IN], 0,
					 MAILBOX_QUEUE_SIZE_LARGE);
				sem_post(&availables[Q_BLUETOOTH_DATA_IN]);
				break;
			case Q_BLUETOOTH_DATA_OUT:
				sem_init(&interrupts[Q_BLUETOOTH_DATA_OUT], 0, 0);
				sem_post(&availables[Q_BLUETOOTH_DATA_OUT]);
				break;
			case Q_RUNTIME1:
				sem_init(&interrupts[Q_RUNTIME1], 0,
					 MAILBOX_QUEUE_SIZE);
				sem_post(&availables[Q_RUNTIME1]);
				break;
			case Q_RUNTIME2:
				sem_init(&interrupts[Q_RUNTIME2], 0,
					 MAILBOX_QUEUE_SIZE);
				sem_post(&availables[Q_RUNTIME2]);
				break;
#endif
			default:
				printf("%s: Error: unexpected ownership change "
				       "interrupt.\n", __func__);
				break;
			}
		} else {
			sem_post(&interrupts[interrupt]);
#ifdef ROLE_OS
			/* FIXME: we should use separate threads for these two */
			if (interrupt == Q_KEYBOARD || interrupt == Q_OS1 ||
				interrupt == Q_OS2 || interrupt == Q_OSU)
				sem_post(&interrupt_input);
#endif
		}
	}
}

int init_os_mailbox(void)
{
	intialize_channels();
	
#ifdef ROLE_OS
	sem_init(&interrupts[Q_OS1], 0, 0);
	sem_init(&interrupts[Q_OS2], 0, 0);
	sem_init(&interrupts[Q_OSU], 0, 0);
	sem_init(&interrupts[Q_KEYBOARD], 0, 0);
	sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
#endif
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
	sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, 0);
#ifdef ROLE_OS
	sem_init(&interrupts[Q_NETWORK_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_NETWORK_DATA_OUT], 0, 0);
	sem_init(&interrupts[Q_NETWORK_CMD_IN], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_NETWORK_CMD_OUT], 0, 0);
	sem_init(&interrupts[Q_BLUETOOTH_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_BLUETOOTH_DATA_OUT], 0, 0);
	sem_init(&interrupts[Q_BLUETOOTH_CMD_IN], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_BLUETOOTH_CMD_OUT], 0, 0);
	sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_UNTRUSTED], 0, MAILBOX_QUEUE_SIZE);
#endif
#ifdef ROLE_OS
	sem_init(&availables[Q_KEYBOARD], 0, 1);
	sem_init(&availables[Q_SERIAL_OUT], 0, 1);
	sem_init(&availables[Q_STORAGE_DATA_IN], 0, 1);
#endif
	sem_init(&availables[Q_STORAGE_DATA_OUT], 0, 1);
	sem_init(&availables[Q_STORAGE_CMD_IN], 0, 1);
	sem_init(&availables[Q_STORAGE_CMD_OUT], 0, 1);
#ifdef ROLE_OS
	sem_init(&availables[Q_NETWORK_DATA_IN], 0, 1);
	sem_init(&availables[Q_NETWORK_DATA_OUT], 0, 1);
	sem_init(&availables[Q_NETWORK_CMD_IN], 0, 1);
	sem_init(&availables[Q_NETWORK_CMD_OUT], 0, 1);
	sem_init(&availables[Q_BLUETOOTH_DATA_IN], 0, 1);
	sem_init(&availables[Q_BLUETOOTH_DATA_OUT], 0, 1);
	sem_init(&availables[Q_BLUETOOTH_CMD_IN], 0, 1);
	sem_init(&availables[Q_BLUETOOTH_CMD_OUT], 0, 1);
	sem_init(&availables[Q_RUNTIME1], 0, 1);
	sem_init(&availables[Q_RUNTIME2], 0, 1);
#endif

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
