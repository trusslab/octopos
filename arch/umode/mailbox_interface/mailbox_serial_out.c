/* OctopOS serial_out mailbox interface */
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
#include <tpm/tpm.h>
#include <arch/mailbox.h>

int fd_out, fd_in, fd_intr;
sem_t interrupt_serial_out;
pthread_t mailbox_thread;
int first_message = 1;

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt == Q_SERIAL_OUT) {
			sem_post(&interrupt_serial_out);
		} else {
			printf("Error: interrupt from an invalid queue (%d)\n",
			       interrupt);
			exit(-1);
		}
	}
}

void get_chars_from_serial_out_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_SERIAL_OUT;
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	sem_wait(&interrupt_serial_out);

	/* This will allow a client domain verify whether this domain is
	 * freshly reset or not */
	if (first_message) {
		enforce_running_process(P_SERIAL_OUT);
		tpm_extend_null();
		first_message = 0;
	}

	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
}

void write_chars_to_serial_out(uint8_t *buf)
{
	fprintf(stderr, "%s", buf);

	/* Delete character on backspace. */
	if ((char) buf[0] == '\b')
		fprintf(stderr, " \b");
}

/* Initializes the serial_out (if needed) and its mailbox */
int init_serial_out(void)
{
	fd_out = open(FIFO_SERIAL_OUT_OUT, O_WRONLY);
	fd_in = open(FIFO_SERIAL_OUT_IN, O_RDONLY);
	fd_intr = open(FIFO_SERIAL_OUT_INTR, O_RDONLY);
	
	sem_init(&interrupt_serial_out, 0, 0);

	int ret = pthread_create(&mailbox_thread, NULL,
				 handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	return 0;
}

void close_serial_out(void)
{
	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_SERIAL_OUT_OUT);
	remove(FIFO_SERIAL_OUT_IN);
	remove(FIFO_SERIAL_OUT_INTR);
}
