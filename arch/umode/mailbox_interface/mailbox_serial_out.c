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
#include <arch/mailbox.h>

int fd_out, fd_in, fd_intr;
sem_t interrupt_serial_out, interrupt_tpm;
pthread_t mailbox_thread;

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt == Q_SERIAL_OUT) {
			sem_post(&interrupt_serial_out);
		} else if ((interrupt - NUM_QUEUES) == Q_TPM_DATA_IN) {
			sem_post(&interrupt_tpm);
		} else if (interrupt == Q_TPM_DATA_IN) {
		} else {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
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
	//mkfifo(FIFO_SERIAL_OUT_OUT, 0666);
	//mkfifo(FIFO_SERIAL_OUT_IN, 0666);
	//mkfifo(FIFO_SERIAL_OUT_INTR, 0666);

	fd_out = open(FIFO_SERIAL_OUT_OUT, O_WRONLY);
	fd_in = open(FIFO_SERIAL_OUT_IN, O_RDONLY);
	fd_intr = open(FIFO_SERIAL_OUT_INTR, O_RDONLY);
	
	sem_init(&interrupt_serial_out, 0, 0);
	sem_init(&interrupt_tpm, 0, 0);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
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

void send_ext_request_to_queue(uint8_t* buf)
{
	uint8_t opcode[2];

	sem_wait(&interrupt_tpm);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_TPM_DATA_IN;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}
