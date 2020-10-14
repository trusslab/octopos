/* OctopOS tpm mailbox interface */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <tpm/libtpm.h>
#include <octopos/mailbox.h>
#include <arch/mailbox.h>
#include <arch/mailbox_tpm.h>

int fd_out, fd_in, fd_intr;
sem_t interrupts[NUM_QUEUES + 1];
pthread_t mailbox_thread;

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1)
	{
		read(fd_intr, &interrupt, 1);
		printf("%s [1]: interrupt = %d\n", __func__, interrupt);
		if (interrupt < 1 || interrupt > NUM_QUEUES)
		{
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
		sem_post(&interrupts[interrupt]);
	}
}

void read_ext_request_from_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_TPM_DATA_IN;
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE);
	sem_wait(&interrupts[Q_TPM_DATA_IN]);
	write(fd_out, opcode, 2);
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

/* Initializes the tpm mailbox */
int init_tpm(void)
{
	mkfifo(FIFO_TPM_OUT, 0666);
	mkfifo(FIFO_TPM_IN, 0666);
	mkfifo(FIFO_TPM_INTR, 0666);

	fd_out = open(FIFO_TPM_OUT, O_WRONLY);
	fd_in = open(FIFO_TPM_IN, O_RDONLY);
	fd_intr = open(FIFO_TPM_INTR, O_RDONLY);

	sem_init(&interrupts[Q_TPM_DATA_IN], 0, 0);
	sem_init(&interrupts[Q_TPM_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret)
	{
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	return 0;
}

void close_tpm(void)
{
	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_TPM_OUT);
	remove(FIFO_TPM_IN);
	remove(FIFO_TPM_INTR);
}
