/* OctopOS display mailbox interface */
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

int fd_out, fd_intr;
sem_t interrupt_display;
pthread_t mailbox_thread;

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt == Q_DISPLAY) {
			sem_post(&interrupt_display);
		} else {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
	}
}

void put_int_on_display_queue(uint8_t value)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE], opcode[2];

	sem_wait(&interrupt_display);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_DISPLAY;
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	buf[0] = value;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

/* Initializes the display and its mailbox */
int init_display(void)
{
	printf("initing display mailbox\n");
	fd_out = open(FIFO_DISPLAY_OUT, O_WRONLY);
	fd_intr = open(FIFO_DISPLAY_INTR, O_RDONLY);

	sem_init(&interrupt_display, 0, MAILBOX_QUEUE_SIZE);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	return 0;
}

void close_display(void)
{
	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);

	close(fd_intr);
	close(fd_out);
	remove(FIFO_DISPLAY_INTR);
	remove(FIFO_DISPLAY_IN);
	remove(FIFO_DISPLAY_OUT);
}
