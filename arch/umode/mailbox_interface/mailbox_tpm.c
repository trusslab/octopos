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

	while (1) {
		read(fd_intr, &interrupt, 1);
		printf("%s [1]: interrupt = %d\n", __func__, interrupt);
		if (interrupt < 1 || interrupt > NUM_QUEUES) {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
		sem_post(&interrupts[interrupt]);
	}
}

/*
 * This API returns the message as well as the proc_id of the sender.
 * To achieve this, before reading the message, it disable queue delegation.
 * This will ensure that the owner of the queue won't change until the message
 * is read.
 */
uint8_t read_request_get_owner_from_queue(uint8_t *buf)
{
	uint8_t opcode[2];
	mailbox_state_reg_t state;

	sem_wait(&interrupts[Q_TPM_IN]);

	/* disable delegation */
	opcode[0] = MAILBOX_OPCODE_DISABLE_QUEUE_DELEGATION;
	opcode[1] = Q_TPM_IN;
	write(fd_out, opcode, 2);

	/* get owner proc_id */
	opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
	opcode[1] = Q_TPM_IN;
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
	opcode[1] = Q_TPM_IN;
	write(fd_out, opcode, 2);

	/* read message */
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_TPM_IN;
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	write(fd_out, opcode, 2);
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return (uint8_t) state.owner;
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

	sem_init(&interrupts[Q_TPM_IN], 0, 0);
	sem_init(&interrupts[Q_TPM_OUT], 0, MAILBOX_QUEUE_SIZE);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
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
