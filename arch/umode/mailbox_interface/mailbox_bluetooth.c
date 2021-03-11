/* OctopOS bluetooth mailbox interface */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <arch/mailbox.h>

int fd_out, fd_in, fd_intr;

/* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];

pthread_t mailbox_thread;

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt == Q_BLUETOOTH_CMD_IN ||
		    interrupt == Q_BLUETOOTH_CMD_OUT ||
		    interrupt == Q_BLUETOOTH_DATA_IN ||
		    interrupt == Q_BLUETOOTH_DATA_OUT) {
			sem_post(&interrupts[interrupt]);
		} else {
			printf("Error: interrupt from an invalid queue (%d)\n",
			       interrupt);
			exit(-1);
		}
	}
}

/*
 * This API returns the message as well as the proc_id of the sender.
 * To achieve this, before reading the message, it disable queue delegation.
 * This will ensure that the owner of the queue won't change until the message
 * is read.
 *
 * FIXME: copied from read_request_get_owner_from_queue() in mailbox_storage.c
 */
uint8_t read_from_bluetooth_cmd_queue_get_owner(uint8_t *buf)
{
       uint8_t opcode[2];
       mailbox_state_reg_t state;

       sem_wait(&interrupts[Q_BLUETOOTH_CMD_IN]);

       /* disable delegation */
       opcode[0] = MAILBOX_OPCODE_DISABLE_QUEUE_DELEGATION;
       opcode[1] = Q_BLUETOOTH_CMD_IN;
       write(fd_out, opcode, 2);

       /* get owner proc_id */
       opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
       opcode[1] = Q_BLUETOOTH_CMD_IN;
       write(fd_out, opcode, 2);
       read(fd_in, &state, sizeof(mailbox_state_reg_t));

       /* enable delegation
        * We enable delegation before reading the message.
        * If we did it after, there would be a race condition.
        * That is, the queue would be given back to the OS since
        * it was delegated for 1 message only and the OS might try
        * to delegate to someone else but would fail.
        */
       opcode[0] = MAILBOX_OPCODE_ENABLE_QUEUE_DELEGATION;
       opcode[1] = Q_BLUETOOTH_CMD_IN;
       write(fd_out, opcode, 2);

       /* read message */
       opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
       opcode[1] = Q_BLUETOOTH_CMD_IN;
       memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
       write(fd_out, opcode, 2);
       read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

       return (uint8_t) state.owner;
}

void write_to_bluetooth_cmd_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[Q_BLUETOOTH_CMD_OUT]);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_BLUETOOTH_CMD_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

void read_from_bluetooth_data_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[Q_BLUETOOTH_DATA_IN]);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_BLUETOOTH_DATA_IN;
	write(fd_out, opcode, 2);
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void write_to_bluetooth_data_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[Q_BLUETOOTH_DATA_OUT]);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_BLUETOOTH_DATA_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

/* Initializes the bluetooth and its mailbox */
int init_bluetooth(void)
{
	fd_out = open(FIFO_BLUETOOTH_OUT, O_WRONLY);
	fd_in = open(FIFO_BLUETOOTH_IN, O_RDONLY);
	fd_intr = open(FIFO_BLUETOOTH_INTR, O_RDONLY);

	sem_init(&interrupts[Q_BLUETOOTH_CMD_OUT], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_BLUETOOTH_CMD_IN], 0, 0);
	sem_init(&interrupts[Q_BLUETOOTH_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_BLUETOOTH_DATA_IN], 0, 0);

	int ret = pthread_create(&mailbox_thread, NULL,
				 handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	return 0;
}

void close_bluetooth(void)
{
	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);

	close(fd_intr);
	close(fd_in);
	close(fd_out);
	remove(FIFO_BLUETOOTH_INTR);
	remove(FIFO_BLUETOOTH_IN);
	remove(FIFO_BLUETOOTH_OUT);
}
