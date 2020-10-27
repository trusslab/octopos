/* octopos storage code */
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
#include <octopos/storage.h>
#include <octopos/error.h>
#include <arch/mailbox.h>

int fd_out, fd_in, fd_intr;
pthread_t mailbox_thread;

 /* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];

void process_request(uint8_t *buf);
void initialize_storage_space(void);

void send_response(uint8_t *buf, uint8_t queue_id)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[queue_id]);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

void read_data_from_queue(uint8_t *buf, uint8_t queue_id)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[queue_id]);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void write_data_to_queue(uint8_t *buf, uint8_t queue_id)
{
	uint8_t opcode[2];

	//printf("%s [1]\n", __func__);
	sem_wait(&interrupts[queue_id]);
	//printf("%s [2]\n", __func__);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2), 
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);

		/* FIXME: Do we need the TPM interrupts here? */
		if (interrupt > 0 && interrupt <= NUM_QUEUES && interrupt != Q_TPM_IN) {
			sem_post(&interrupts[interrupt]);
		} else if (interrupt == Q_TPM_IN) {
		} else if ((interrupt - NUM_QUEUES) == Q_TPM_IN) {
			sem_post(&interrupts[Q_TPM_IN]);
		} else {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
	}
}

void storage_event_loop(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		sem_wait(&interrupts[Q_STORAGE_CMD_IN]);
		opcode[1] = Q_STORAGE_CMD_IN;
		write(fd_out, opcode, 2); 
		read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
		process_request(buf);
		send_response(buf, Q_STORAGE_CMD_OUT);
	}
}

int init_storage(void)
{
	sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, 0);
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, 0);
	sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_TPM_IN], 0, 0);

	initialize_storage_space();

	mkfifo(FIFO_STORAGE_OUT, 0666);
	mkfifo(FIFO_STORAGE_IN, 0666);
	mkfifo(FIFO_STORAGE_INTR, 0666);

	fd_out = open(FIFO_STORAGE_OUT, O_WRONLY);
	fd_in = open(FIFO_STORAGE_IN, O_RDONLY);
	fd_intr = open(FIFO_STORAGE_INTR, O_RDONLY);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	return 0;
}

void close_storage(void)
{	
	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_STORAGE_OUT);
	remove(FIFO_STORAGE_IN);
	remove(FIFO_STORAGE_INTR);
}
