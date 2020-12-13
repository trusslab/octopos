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
		if (interrupt == Q_BLUETOOTH_IN ||
		    interrupt == Q_BLUETOOTH_OUT) {
			sem_post(&interrupts[interrupt]);
		} else {
			printf("Error: interrupt from an invalid queue (%d)\n",
			       interrupt);
			exit(-1);
		}
	}
}

void read_msg_from_bluetooth_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[Q_BLUETOOTH_IN]);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_BLUETOOTH_IN;
	write(fd_out, opcode, 2);
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
}

void put_msg_on_bluetooth_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[Q_BLUETOOTH_OUT]);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_BLUETOOTH_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

/* Initializes the bluetooth and its mailbox */
int init_bluetooth(void)
{
	fd_out = open(FIFO_BLUETOOTH_OUT, O_WRONLY);
	fd_in = open(FIFO_BLUETOOTH_IN, O_RDONLY);
	fd_intr = open(FIFO_BLUETOOTH_INTR, O_RDONLY);

	sem_init(&interrupts[Q_BLUETOOTH_OUT], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_BLUETOOTH_IN], 0, 0);

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
