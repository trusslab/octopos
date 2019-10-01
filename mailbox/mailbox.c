/* octopos mailbox */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <octopos/mailbox.h>

struct processor {
	uint8_t processor_id;
	void (*send_interrupt)(uint8_t);
	/* FIXME: do we need separate handles? */
	int out_handle;
	int in_handle;
	int intr_handle;
};

struct queue {
	uint8_t queue_id;
	uint8_t messages[MAILBOX_QUEUE_SIZE][MAILBOX_QUEUE_MSG_SIZE];
	int head;
	int tail;
	int counter;
	/* access control */
	uint8_t reader_id;
	uint8_t writer_id;
};

struct processor processors[NUM_PROCESSORS];
struct queue queues[NUM_PROCESSORS];

//#define OUTPUT_CHANNEL_MSG_SIZE	256
//#define INPUT_CHANNEL_MSG_SIZE	1

static void send_interrupt(struct processor *proc, uint8_t queue_id)
{
	write(proc->intr_handle, &queue_id, 1);
}

static void os_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[OS], queue_id);
}

static void serial_out_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[SERIAL_OUT], queue_id);
}

static void runtime_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[RUNTIME], queue_id);
}

static void initialize_processors(void)
{
	/* initialize connections to the processors */
	mkfifo(FIFO_OS_OUT, 0666);
	mkfifo(FIFO_OS_IN, 0666);
	mkfifo(FIFO_OS_INTR, 0666);
	mkfifo(FIFO_KEYBOARD, 0666);
	mkfifo(FIFO_SERIAL_OUT_OUT, 0666);
	mkfifo(FIFO_SERIAL_OUT_IN, 0666);
	mkfifo(FIFO_SERIAL_OUT_INTR, 0666);
	mkfifo(FIFO_RUNTIME_OUT, 0666);
	mkfifo(FIFO_RUNTIME_IN, 0666);
	mkfifo(FIFO_RUNTIME_INTR, 0666);

	/* initialize processor objects */
	/* OS processor */
	processors[OS].processor_id = OS;
	processors[OS].send_interrupt = os_send_interrupt;
	processors[OS].out_handle = open(FIFO_OS_OUT, O_RDWR);
	processors[OS].in_handle = open(FIFO_OS_IN, O_RDWR);
	processors[OS].intr_handle = open(FIFO_OS_INTR, O_RDWR);

	/* keyboard processor */
	processors[KEYBOARD].processor_id = KEYBOARD;
	processors[KEYBOARD].send_interrupt = NULL; /* not needed */
	processors[KEYBOARD].out_handle = open(FIFO_KEYBOARD, O_RDWR);
	processors[KEYBOARD].in_handle = -1; /* not needed */

	/* serial output processor */
	processors[SERIAL_OUT].processor_id = KEYBOARD;
	processors[SERIAL_OUT].send_interrupt = serial_out_send_interrupt;
	processors[SERIAL_OUT].out_handle = open(FIFO_SERIAL_OUT_OUT, O_RDWR);
	processors[SERIAL_OUT].in_handle = open(FIFO_SERIAL_OUT_IN, O_RDWR);
	processors[SERIAL_OUT].intr_handle = open(FIFO_SERIAL_OUT_INTR, O_RDWR);

	/* runtime processor */
	processors[RUNTIME].processor_id = RUNTIME;
	processors[RUNTIME].send_interrupt = runtime_send_interrupt;
	processors[RUNTIME].out_handle = open(FIFO_RUNTIME_OUT, O_RDWR);
	processors[RUNTIME].in_handle = open(FIFO_RUNTIME_IN, O_RDWR);
	processors[RUNTIME].intr_handle = open(FIFO_RUNTIME_INTR, O_RDWR);
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
	close(processors[RUNTIME].out_handle);
	close(processors[RUNTIME].in_handle);
	close(processors[RUNTIME].intr_handle);

	remove(FIFO_OS_OUT);
	remove(FIFO_OS_IN);
	remove(FIFO_OS_INTR);
	remove(FIFO_KEYBOARD);
	remove(FIFO_SERIAL_OUT_OUT);
	remove(FIFO_SERIAL_OUT_IN);
	remove(FIFO_SERIAL_OUT_INTR);
	remove(FIFO_RUNTIME_OUT);
	remove(FIFO_RUNTIME_IN);
	remove(FIFO_RUNTIME_INTR);
}

int write_queue(struct queue *queue, uint8_t *buf)
{
	if (queue->counter == MAILBOX_QUEUE_SIZE) {
		/* FIXME: we should communicate that back to the sender processor */
		printf("Error: queue is full\n");
		_exit(-1);
		return -1;
	}

	queue->counter++;
	memcpy(queue->messages[queue->head], buf, MAILBOX_QUEUE_MSG_SIZE);
	queue->head = (queue->head + 1) % MAILBOX_QUEUE_SIZE;

	return 0;
}

int read_queue(struct queue *queue, uint8_t *buf)
{
	if (queue->counter == 0) {
		/* FIXME: we should communicate that back to the sender processor */
		printf("Error: queue %d is empty\n", queue->queue_id);
		_exit(-1);
		return -1;
	}

	queue->counter--;
	memcpy(buf, queue->messages[queue->tail], MAILBOX_QUEUE_MSG_SIZE);
	queue->tail = (queue->tail + 1) % MAILBOX_QUEUE_SIZE;

	return 0;
}

static void initialize_queues(void)
{
	/* OS queue */
	queues[OS].queue_id = OS;
	queues[OS].head = 0;
	queues[OS].tail = 0;
	queues[OS].counter = 0;
	queues[OS].reader_id = OS;
	queues[OS].writer_id = ALL_PROCESSORS;

	/* keyboard queue */
	queues[KEYBOARD].queue_id = KEYBOARD;
	queues[KEYBOARD].head = 0;
	queues[KEYBOARD].tail = 0;
	queues[KEYBOARD].counter = 0;
	queues[KEYBOARD].reader_id = OS;
	queues[KEYBOARD].writer_id = KEYBOARD;

	/* serial output queue */
	queues[SERIAL_OUT].queue_id = SERIAL_OUT;
	queues[SERIAL_OUT].head = 0;
	queues[SERIAL_OUT].tail = 0;
	queues[SERIAL_OUT].counter = 0;
	queues[SERIAL_OUT].reader_id = SERIAL_OUT;
	queues[SERIAL_OUT].writer_id = OS;

	/* runtime queue */
	queues[RUNTIME].queue_id = RUNTIME;
	queues[RUNTIME].head = 0;
	queues[RUNTIME].tail = 0;
	queues[RUNTIME].counter = 0;
	queues[RUNTIME].reader_id = RUNTIME;
	queues[RUNTIME].writer_id = OS;
}

static bool proc_has_queue_read_access(uint8_t queue_id, uint8_t proc_id)
{
	if (queues[(int) queue_id].reader_id == proc_id)
		return true;

	return false;
}

static bool proc_has_queue_write_access(uint8_t queue_id, uint8_t proc_id)
{
	if (queues[(int) queue_id].writer_id == proc_id ||
	    queues[(int) queue_id].writer_id == ALL_PROCESSORS)
		return true;
		
	return false;
}

static void handle_read_queue(uint8_t queue_id, uint8_t reader_id)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

	if (proc_has_queue_read_access(queue_id, reader_id)) {
		read_queue(&queues[(int) queue_id], buf);
		write(processors[(int) reader_id].in_handle, buf, MAILBOX_QUEUE_MSG_SIZE);
	} else {
		printf("Error: processor %d can't read from queue %d\n", reader_id, queue_id);
	}
}

static void handle_write_queue(uint8_t queue_id, uint8_t writer_id)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

	if (proc_has_queue_write_access(queue_id, writer_id)) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		read(processors[(int) writer_id].out_handle, buf, MAILBOX_QUEUE_MSG_SIZE);
		write_queue(&queues[(int) queue_id], buf);
		/* FIXME: check to make sure queues[queue_id].reader_id points to a
		 * single processor */
		processors[(int) queues[(int) queue_id].reader_id].send_interrupt(queue_id);
	} else {
		printf("Error: processor %d can't write to queue %d\n", writer_id, queue_id);
	}
}

int main(int argc, char **argv)
{
	uint8_t opcode[2], writer_id, reader_id, queue_id;

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
	if (processors[RUNTIME].out_handle > nfds)
		nfds = processors[RUNTIME].out_handle;

	while(1) {
		FD_SET(processors[OS].out_handle, &listen_fds);
		FD_SET(processors[KEYBOARD].out_handle, &listen_fds);
		FD_SET(processors[SERIAL_OUT].out_handle, &listen_fds);
		FD_SET(processors[RUNTIME].out_handle, &listen_fds);
		if (select(nfds + 1, &listen_fds, NULL, NULL, NULL) < 0) {
			printf("Error: select\n");
			break;
		}

		if (FD_ISSET(processors[OS].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[OS].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = OS;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = OS;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else if (opcode[0] == MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS) {
				if (opcode[1] == 0) {
					queues[SERIAL_OUT].writer_id = RUNTIME;
				} else if (opcode[1] == 1) {
					queues[SERIAL_OUT].writer_id = OS;
				} else if (opcode[1] == 2) {
					queues[KEYBOARD].reader_id = RUNTIME;
				} else if (opcode[1] == 3) {
					queues[KEYBOARD].reader_id = OS;
				} else
					printf("Error: invalid config option\n");
			} else {
				printf("Error: invalid opcode from OS\n");
			}
		}

		if (FD_ISSET(processors[KEYBOARD].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[KEYBOARD].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = KEYBOARD;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else {
				printf("Error: invalid opcode from keyboard\n");
			}
		}		

		if (FD_ISSET(processors[SERIAL_OUT].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[SERIAL_OUT].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = SERIAL_OUT;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else {
				printf("Error: invalid opcode from serial_out\n");
			}
		}

		if (FD_ISSET(processors[RUNTIME].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[RUNTIME].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = RUNTIME;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = RUNTIME;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else {
				printf("Error: invalid opcode from OS\n");
			}
		}
	}	

	close_processors();
}
