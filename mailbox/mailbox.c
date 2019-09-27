/* octopos mailbox */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/select.h>

enum processors {
	OS = 1,
	KEYBOARD = 2,
	SERIAL_OUT = 3
};

#define NUM_PROCESSORS	3

struct processor {
	char processor_id;
	void (*send_interrupt)(void);
	/* FIXME: do we need separate handles? */
	int out_handle;
	int in_handle;
	int intr_handle;
};

#define QUEUE_SIZE	4
#define QUEUE_MSG_SIZE	64

struct queue {
	struct processor *receiver;
	struct processor *sender;
	char messages[QUEUE_SIZE][QUEUE_MSG_SIZE];
	int head;
	int tail;
	int counter;
};

struct processor processors[NUM_PROCESSORS];
struct queue queues[NUM_PROCESSORS];

char fifo_shell_out[64] = "/tmp/octopos_mailbox_shell_out";
char fifo_shell_in[64] = "/tmp/octopos_mailbox_shell_in";
char fifo_shell_intr[64] = "/tmp/octopos_mailbox_shell_intr";
char fifo_keyboard[64] = "/tmp/octopos_mailbox_keyboard";
char fifo_serial_out_out[64] = "/tmp/octopos_mailbox_serial_out_out";
char fifo_serial_out_in[64] = "/tmp/octopos_mailbox_serial_out_in";
char fifo_serial_out_intr[64] = "/tmp/octopos_mailbox_serial_out_intr";

//#define OUTPUT_CHANNEL_MSG_SIZE	256
//#define INPUT_CHANNEL_MSG_SIZE	1

static void send_interrupt(struct processor *proc)
{
	write(proc->intr_handle, "1", 1);
}

static void os_send_interrupt(void)
{
	send_interrupt(&processors[OS]);
}

static void serial_out_send_interrupt(void)
{
	send_interrupt(&processors[SERIAL_OUT]);
}

static void initialize_processors(void)
{
	/* initialize connections to the processors */
	mkfifo(fifo_shell_out, 0666);
	mkfifo(fifo_shell_in, 0666);
	mkfifo(fifo_shell_intr, 0666);
	mkfifo(fifo_keyboard, 0666);
	mkfifo(fifo_serial_out_out, 0666);
	mkfifo(fifo_serial_out_in, 0666);
	mkfifo(fifo_serial_out_intr, 0666);

	/* initialize processor objects */
	/* OS processor */
	processors[OS].processor_id = OS;
	processors[OS].send_interrupt = os_send_interrupt;
	processors[OS].out_handle = open(fifo_shell_out, O_RDWR);
	processors[OS].in_handle = open(fifo_shell_in, O_RDWR);
	processors[OS].intr_handle = open(fifo_shell_intr, O_RDWR);

	/* keyboard processor */
	processors[KEYBOARD].processor_id = KEYBOARD;
	processors[KEYBOARD].send_interrupt = NULL; /* not needed */
	processors[KEYBOARD].out_handle = open(fifo_keyboard, O_RDWR);
	processors[KEYBOARD].in_handle = -1; /* not needed */

	/* serial output processor */
	processors[SERIAL_OUT].processor_id = KEYBOARD;
	processors[SERIAL_OUT].send_interrupt = serial_out_send_interrupt;
	processors[SERIAL_OUT].out_handle = open(fifo_serial_out_out, O_RDWR);
	processors[SERIAL_OUT].in_handle = open(fifo_serial_out_in, O_RDWR);
	processors[SERIAL_OUT].intr_handle = open(fifo_serial_out_intr, O_RDWR);
}

static void close_processors(void)
{
	close(processors[OS].out_handle);
	close(processors[OS].in_handle);
	close(processors[OS].intr_handle);
	close(processors[KEYBOARD].out_handle);
	close(processors[SERIAL_OUT].out_handle);
	close(processors[SERIAL_OUT].in_handle);
	close(processors[SERIAL_OUT].intr_handle);

	remove(fifo_shell_out);
	remove(fifo_shell_in);
	remove(fifo_shell_intr);
	remove(fifo_keyboard);
	remove(fifo_serial_out_out);
	remove(fifo_serial_out_in);
	remove(fifo_serial_out_intr);
}

int write_queue(struct queue *queue, char *buf)
{
	if (queue->counter == QUEUE_SIZE) {
		/* FIXME: we should communicate that back to the sender processor */
		printf("Error: queue is full\n");
		_exit(-1);
		return -1;
	}

	queue->counter++;
	memcpy(queue->messages[queue->head], buf, QUEUE_MSG_SIZE);
	queue->head = (queue->head + 1) % QUEUE_SIZE;

	return 0;
}

int read_queue(struct queue *queue, char *buf)
{
	if (queue->counter == 0) {
		/* FIXME: we should communicate that back to the sender processor */
		printf("Error: queue is empty\n");
		_exit(-1);
		return -1;
	}

	queue->counter--;
	memcpy(buf, queue->messages[queue->tail], QUEUE_MSG_SIZE);
	queue->tail = (queue->tail + 1) % QUEUE_SIZE;

	return 0;
}

static void initialize_queues(void)
{
	/* OS queue */
	queues[OS].receiver = &processors[OS];
	queues[OS].sender = &processors[KEYBOARD];
	queues[OS].head = 0;
	queues[OS].tail = 0;
	queues[OS].counter = 0;

	/* keyboard queue */
	/* FIXME: keyboard doesn't need a queue */
	queues[KEYBOARD].receiver = &processors[KEYBOARD];
	queues[KEYBOARD].sender = NULL;
	queues[KEYBOARD].head = 0;
	queues[KEYBOARD].tail = 0;
	queues[KEYBOARD].counter = 0;

	/* serial output queue */
	queues[SERIAL_OUT].receiver = &processors[SERIAL_OUT];
	queues[SERIAL_OUT].sender = &processors[OS];
	queues[SERIAL_OUT].head = 0;
	queues[SERIAL_OUT].tail = 0;
	queues[SERIAL_OUT].counter = 0;
}

int main(int argc, char **argv)
{
	char buf[QUEUE_MSG_SIZE], opcode;

	initialize_processors();
	initialize_queues();

	fd_set listen_fds;
	int nfds;
	
	FD_ZERO(&listen_fds);

	nfds = processors[KEYBOARD].out_handle;
	if (processors[OS].out_handle > nfds)
		nfds = processors[OS].out_handle;
	if (processors[SERIAL_OUT].out_handle > nfds)
		nfds = processors[SERIAL_OUT].out_handle;

	while(1) {
		FD_SET(processors[OS].out_handle, &listen_fds);
		FD_SET(processors[KEYBOARD].out_handle, &listen_fds);
		FD_SET(processors[SERIAL_OUT].out_handle, &listen_fds);
		if (select(nfds + 1, &listen_fds, NULL, NULL, NULL) < 0) {
			printf("Error: select\n");
			break;
		}

		if (FD_ISSET(processors[OS].out_handle, &listen_fds)) {
			opcode = -1;
			read(processors[OS].out_handle, &opcode, 1);
			if (opcode == 0) { /* read from own queue */
				read_queue(&queues[OS], buf);
				write(processors[OS].in_handle, buf, QUEUE_MSG_SIZE);
			} else if (opcode == SERIAL_OUT) {
				memset(buf, 0x0, QUEUE_MSG_SIZE);
				read(processors[OS].out_handle, buf, QUEUE_MSG_SIZE);
				write_queue(&queues[SERIAL_OUT], buf);
				processors[SERIAL_OUT].send_interrupt();
			} else {
				printf("Error: invalid opcode from shell\n");
			}
		}

		if (FD_ISSET(processors[KEYBOARD].out_handle, &listen_fds)) {
			opcode = -1;
			read(processors[KEYBOARD].out_handle, &opcode, 1);
			if (opcode == OS) {
				memset(buf, 0x0, QUEUE_MSG_SIZE);
				read(processors[KEYBOARD].out_handle, buf, QUEUE_MSG_SIZE);
				write_queue(&queues[OS], buf);
				processors[OS].send_interrupt();
			} else {
				printf("Error: invalid opcode from keyboard\n");
			}
		}		

		if (FD_ISSET(processors[SERIAL_OUT].out_handle, &listen_fds)) {
			opcode = -1;
			read(processors[SERIAL_OUT].out_handle, &opcode, 1);
			if (opcode == 0) { /* read from own queue */
				read_queue(&queues[SERIAL_OUT], buf);
				write(processors[SERIAL_OUT].in_handle, buf, QUEUE_MSG_SIZE);
			} else {
				printf("Error: invalid opcode from serial_out\n");
			}
		}
	}	

	close_processors();
}
