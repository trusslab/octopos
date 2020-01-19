/* octopos serial output code */
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

int fd_intr;
sem_t interrupt_serial_out;

static void *handle_mailbox_interrupts(void *data)
{

	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt != Q_SERIAL_OUT) {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
		sem_post(&interrupt_serial_out);
	}
}

int main(int argc, char **argv)
{
	int fd_out, fd_in;
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t opcode[2];
	pthread_t mailbox_thread;

	mkfifo(FIFO_SERIAL_OUT_OUT, 0666);
	mkfifo(FIFO_SERIAL_OUT_IN, 0666);
	mkfifo(FIFO_SERIAL_OUT_INTR, 0666);

	fd_out = open(FIFO_SERIAL_OUT_OUT, O_WRONLY);
	fd_in = open(FIFO_SERIAL_OUT_IN, O_RDONLY);
	fd_intr = open(FIFO_SERIAL_OUT_INTR, O_RDONLY);
	
	sem_init(&interrupt_serial_out, 0, 0);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_SERIAL_OUT;
	
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		sem_wait(&interrupt_serial_out);
		write(fd_out, opcode, 2), 
		read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
		printf("%s", buf);
		fflush(NULL);
	}

	pthread_join(mailbox_thread, NULL);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_SERIAL_OUT_OUT);
	remove(FIFO_SERIAL_OUT_IN);
	remove(FIFO_SERIAL_OUT_INTR);
}
