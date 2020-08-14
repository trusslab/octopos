/* octopos mailbox */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
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
	uint8_t queue_type;
#define QUEUE_TYPE_FIXED_READER		0
#define QUEUE_TYPE_FIXED_WRITER		1
	uint8_t **messages;
	int queue_size;
	int msg_size;
	int head;
	int tail;
	int counter;
	/* access control */
	uint8_t reader_id;
	uint8_t writer_id;
	/* FIXME: too small */
	uint8_t access_count;
	uint8_t prev_owner;
};

struct processor processors[NUM_PROCESSORS + 1];
struct queue queues[NUM_QUEUES + 1];

static void send_interrupt(struct processor *proc, uint8_t queue_id)
{
	write(proc->intr_handle, &queue_id, 1);
}

static void sensor_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_SENSOR], queue_id);
}

static void os_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_OS], queue_id);
}

static void keyboard_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_KEYBOARD], queue_id);
}

static void serial_out_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_SERIAL_OUT], queue_id);
}

static void storage_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_STORAGE], queue_id);
}

static void network_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_NETWORK], queue_id);
}

static void runtime1_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_RUNTIME1], queue_id);
}

static void runtime2_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_RUNTIME2], queue_id);
}

static void untrusted_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_UNTRUSTED], queue_id);
}

static void tpm_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_TPM], queue_id);
}

static void initialize_processors(void)
{
	/* initialize connections to the processors */
	mkfifo(FIFO_OS_OUT, 0666);
	mkfifo(FIFO_OS_IN, 0666);
	mkfifo(FIFO_OS_INTR, 0666);
	mkfifo(FIFO_KEYBOARD_OUT, 0666);
	mkfifo(FIFO_KEYBOARD_INTR, 0666);
	mkfifo(FIFO_SENSOR, 0666);
	mkfifo(FIFO_SERIAL_OUT_OUT, 0666);
	mkfifo(FIFO_SERIAL_OUT_IN, 0666);
	mkfifo(FIFO_SERIAL_OUT_INTR, 0666);
	mkfifo(FIFO_STORAGE_OUT, 0666);
	mkfifo(FIFO_STORAGE_IN, 0666);
	mkfifo(FIFO_STORAGE_INTR, 0666);
	mkfifo(FIFO_NETWORK_OUT, 0666);
	mkfifo(FIFO_NETWORK_IN, 0666);
	mkfifo(FIFO_NETWORK_INTR, 0666);
	mkfifo(FIFO_RUNTIME1_OUT, 0666);
	mkfifo(FIFO_RUNTIME1_IN, 0666);
	mkfifo(FIFO_RUNTIME1_INTR, 0666);
	mkfifo(FIFO_RUNTIME2_OUT, 0666);
	mkfifo(FIFO_RUNTIME2_IN, 0666);
	mkfifo(FIFO_RUNTIME2_INTR, 0666);
	mkfifo(FIFO_UNTRUSTED_OUT, 0666);
	mkfifo(FIFO_UNTRUSTED_IN, 0666);
	mkfifo(FIFO_UNTRUSTED_INTR, 0666);
	mkfifo(FIFO_TPM_OUT, 0666);
	mkfifo(FIFO_TPM_IN, 0666);
	mkfifo(FIFO_TPM_INTR, 0666);

	/* initialize processor objects */
	/* OS processor */
	processors[P_OS].processor_id = P_OS;
	processors[P_OS].send_interrupt = os_send_interrupt;
	processors[P_OS].out_handle = open(FIFO_OS_OUT, O_RDWR);
	processors[P_OS].in_handle = open(FIFO_OS_IN, O_RDWR);
	processors[P_OS].intr_handle = open(FIFO_OS_INTR, O_RDWR);

	/* keyboard processor */
	processors[P_KEYBOARD].processor_id = P_KEYBOARD;
	processors[P_KEYBOARD].send_interrupt = keyboard_send_interrupt;
	processors[P_KEYBOARD].out_handle = open(FIFO_KEYBOARD_OUT, O_RDWR);
	processors[P_KEYBOARD].in_handle = -1; /* not needed */
	processors[P_KEYBOARD].intr_handle = open(FIFO_KEYBOARD_INTR, O_RDWR);

	/* sensor processor */
	processors[P_SENSOR].processor_id = P_SENSOR;
	processors[P_SENSOR].send_interrupt = sensor_send_interrupt;
	processors[P_SENSOR].out_handle = open(FIFO_SENSOR, O_RDWR);
	processors[P_SENSOR].in_handle = open(FIFO_SENSOR_INTR, O_RDWR);

	/* serial output processor */
	processors[P_SERIAL_OUT].processor_id = P_SERIAL_OUT;
	processors[P_SERIAL_OUT].send_interrupt = serial_out_send_interrupt;
	processors[P_SERIAL_OUT].out_handle = open(FIFO_SERIAL_OUT_OUT, O_RDWR);
	processors[P_SERIAL_OUT].in_handle = open(FIFO_SERIAL_OUT_IN, O_RDWR);
	processors[P_SERIAL_OUT].intr_handle = open(FIFO_SERIAL_OUT_INTR, O_RDWR);

	/* storage processor */
	processors[P_STORAGE].processor_id = P_STORAGE;
	processors[P_STORAGE].send_interrupt = storage_send_interrupt;
	processors[P_STORAGE].out_handle = open(FIFO_STORAGE_OUT, O_RDWR);
	processors[P_STORAGE].in_handle = open(FIFO_STORAGE_IN, O_RDWR);
	processors[P_STORAGE].intr_handle = open(FIFO_STORAGE_INTR, O_RDWR);

	/* network processor */
	processors[P_NETWORK].processor_id = P_NETWORK;
	processors[P_NETWORK].send_interrupt = network_send_interrupt;
	processors[P_NETWORK].out_handle = open(FIFO_NETWORK_OUT, O_RDWR);
	processors[P_NETWORK].in_handle = open(FIFO_NETWORK_IN, O_RDWR);
	processors[P_NETWORK].intr_handle = open(FIFO_NETWORK_INTR, O_RDWR);

	/* runtime1 processor */
	processors[P_RUNTIME1].processor_id = P_RUNTIME1;
	processors[P_RUNTIME1].send_interrupt = runtime1_send_interrupt;
	processors[P_RUNTIME1].out_handle = open(FIFO_RUNTIME1_OUT, O_RDWR);
	processors[P_RUNTIME1].in_handle = open(FIFO_RUNTIME1_IN, O_RDWR);
	processors[P_RUNTIME1].intr_handle = open(FIFO_RUNTIME1_INTR, O_RDWR);

	/* runtime2 processor */
	processors[P_RUNTIME2].processor_id = P_RUNTIME2;
	processors[P_RUNTIME2].send_interrupt = runtime2_send_interrupt;
	processors[P_RUNTIME2].out_handle = open(FIFO_RUNTIME2_OUT, O_RDWR);
	processors[P_RUNTIME2].in_handle = open(FIFO_RUNTIME2_IN, O_RDWR);
	processors[P_RUNTIME2].intr_handle = open(FIFO_RUNTIME2_INTR, O_RDWR);

	/* untrusted processor */
	processors[P_UNTRUSTED].processor_id = P_UNTRUSTED;
	processors[P_UNTRUSTED].send_interrupt = untrusted_send_interrupt;
	processors[P_UNTRUSTED].out_handle = open(FIFO_UNTRUSTED_OUT, O_RDWR);
	processors[P_UNTRUSTED].in_handle = open(FIFO_UNTRUSTED_IN, O_RDWR);
	processors[P_UNTRUSTED].intr_handle = open(FIFO_UNTRUSTED_INTR, O_RDWR);

	/* tpm processor */
	processors[P_TPM].processor_id = P_TPM;
	processors[P_TPM].send_interrupt = tpm_send_interrupt;
	processors[P_TPM].out_handle = open(FIFO_TPM_OUT, O_RDWR);
	processors[P_TPM].in_handle = open(FIFO_TPM_IN, O_RDWR);
	processors[P_TPM].intr_handle = open(FIFO_TPM_INTR, O_RDWR);
}

static void close_processors(void)
{
	close(processors[P_OS].out_handle);
	close(processors[P_OS].in_handle);
	close(processors[P_OS].intr_handle);
	close(processors[P_KEYBOARD].out_handle);
	close(processors[P_KEYBOARD].intr_handle);
	close(processors[P_SERIAL_OUT].out_handle);
	close(processors[P_SERIAL_OUT].in_handle);
	close(processors[P_SERIAL_OUT].intr_handle);
	close(processors[P_STORAGE].out_handle);
	close(processors[P_STORAGE].in_handle);
	close(processors[P_STORAGE].intr_handle);
	close(processors[P_NETWORK].out_handle);
	close(processors[P_NETWORK].in_handle);
	close(processors[P_NETWORK].intr_handle);
	close(processors[P_RUNTIME1].out_handle);
	close(processors[P_RUNTIME1].in_handle);
	close(processors[P_RUNTIME1].intr_handle);
	close(processors[P_RUNTIME2].out_handle);
	close(processors[P_RUNTIME2].in_handle);
	close(processors[P_RUNTIME2].intr_handle);
	close(processors[P_UNTRUSTED].out_handle);
	close(processors[P_UNTRUSTED].in_handle);
	close(processors[P_UNTRUSTED].intr_handle);
	close(processors[P_TPM].out_handle);
	close(processors[P_TPM].in_handle);
	close(processors[P_TPM].intr_handle);

	remove(FIFO_OS_OUT);
	remove(FIFO_OS_IN);
	remove(FIFO_OS_INTR);
	remove(FIFO_KEYBOARD_OUT);
	remove(FIFO_KEYBOARD_INTR);
	remove(FIFO_SERIAL_OUT_OUT);
	remove(FIFO_SERIAL_OUT_IN);
	remove(FIFO_SERIAL_OUT_INTR);
	remove(FIFO_STORAGE_OUT);
	remove(FIFO_STORAGE_IN);
	remove(FIFO_STORAGE_INTR);
	remove(FIFO_NETWORK_OUT);
	remove(FIFO_NETWORK_IN);
	remove(FIFO_NETWORK_INTR);
	remove(FIFO_RUNTIME1_OUT);
	remove(FIFO_RUNTIME1_IN);
	remove(FIFO_RUNTIME1_INTR);
	remove(FIFO_RUNTIME2_OUT);
	remove(FIFO_RUNTIME2_IN);
	remove(FIFO_RUNTIME2_INTR);
	remove(FIFO_UNTRUSTED_OUT);
	remove(FIFO_UNTRUSTED_IN);
	remove(FIFO_UNTRUSTED_INTR);
	remove(FIFO_TPM_OUT);
	remove(FIFO_TPM_IN);
	remove(FIFO_TPM_INTR);
}

static int write_queue(struct queue *queue, int out_handle)
{
	if (queue->counter >= queue->queue_size) {
		/* FIXME: we should communicate that back to the sender processor */
		printf("Error: queue (%d) is full\n", queue->queue_id);
		_exit(-1);
		return -1;
	}

	queue->counter++;
	read(out_handle, queue->messages[queue->tail], queue->msg_size);
	queue->tail = (queue->tail + 1) % queue->queue_size;

	return 0;
}

static int change_back_queue_access(struct queue *queue)
{
	if (queue->prev_owner == 0) {
		printf("Error (%s): invalid call\n", __func__);
		return -1;
	}

	if (queue->queue_type == QUEUE_TYPE_FIXED_READER) {
		queue->writer_id = queue->prev_owner;
		queue->prev_owner = 0;
		processors[(int) queue->writer_id].send_interrupt(queue->queue_id + NUM_QUEUES);
	} else { /* QUEUE_TYPE_FIXED_WRITER */
		queue->reader_id = queue->prev_owner;
		queue->prev_owner = 0;
		processors[(int) queue->reader_id].send_interrupt(queue->queue_id + NUM_QUEUES);
	}

	return 0;
}

static int read_queue(struct queue *queue, int in_handle)
{
	if (queue->counter <= 0) {
		/* FIXME: we should communicate that back to the sender processor */
		printf("Error: queue %d is empty\n", queue->queue_id);
		_exit(-1);
		return -1;
	}

	queue->counter--;
	write(in_handle, queue->messages[queue->head], queue->msg_size);
	queue->head = (queue->head + 1) % queue->queue_size;

	return 0;
}

static uint8_t **allocate_memory_for_queue(int queue_size, int msg_size)
{
	uint8_t **messages = (uint8_t **) malloc(queue_size * sizeof(uint8_t *));
	if (!messages) {
		printf("Error: couldn't allocate memory for a queue\n");
		exit(-1);
	}
	for (int i = 0; i < queue_size; i++) {
		messages[i] = (uint8_t *) malloc(msg_size);
		if (!messages[i]) {
			printf("Error: couldn't allocate memory for a queue\n");
			exit(-1);
		}
	}

	return messages;
}

static void initialize_queues(void)
{
	/* OS queue for runtime1 */
	queues[Q_OS1].queue_id = Q_OS1;
	queues[Q_OS1].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_OS1].head = 0;
	queues[Q_OS1].tail = 0;
	queues[Q_OS1].counter = 0;
	queues[Q_OS1].reader_id = P_OS;
	queues[Q_OS1].writer_id = P_RUNTIME1;
	queues[Q_OS1].access_count = 0;
	queues[Q_OS1].prev_owner = 0;
	queues[Q_OS1].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_OS1].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_OS1].messages = 
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* OS queue for runtime2 */
	queues[Q_OS2].queue_id = Q_OS2;
	queues[Q_OS2].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_OS2].head = 0;
	queues[Q_OS2].tail = 0;
	queues[Q_OS2].counter = 0;
	queues[Q_OS2].reader_id = P_OS;
	queues[Q_OS2].writer_id = P_RUNTIME2;
	queues[Q_OS2].access_count = 0;
	queues[Q_OS2].prev_owner = 0;
	queues[Q_OS2].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_OS2].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_OS2].messages = 
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* keyboard queue */
	queues[Q_KEYBOARD].queue_id = Q_KEYBOARD;
	queues[Q_KEYBOARD].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_KEYBOARD].head = 0;
	queues[Q_KEYBOARD].tail = 0;
	queues[Q_KEYBOARD].counter = 0;
	queues[Q_KEYBOARD].reader_id = P_OS;
	queues[Q_KEYBOARD].writer_id = P_KEYBOARD;
	queues[Q_KEYBOARD].access_count = 0;
	queues[Q_KEYBOARD].prev_owner = 0;
	queues[Q_KEYBOARD].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_KEYBOARD].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_KEYBOARD].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* serial output queue */
	queues[Q_SERIAL_OUT].queue_id = Q_SERIAL_OUT;
	queues[Q_SERIAL_OUT].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_SERIAL_OUT].head = 0;
	queues[Q_SERIAL_OUT].tail = 0;
	queues[Q_SERIAL_OUT].counter = 0;
	queues[Q_SERIAL_OUT].reader_id = P_SERIAL_OUT;
	queues[Q_SERIAL_OUT].writer_id = P_OS;
	queues[Q_SERIAL_OUT].access_count = 0;
	queues[Q_SERIAL_OUT].prev_owner = 0;
	queues[Q_SERIAL_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_SERIAL_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_SERIAL_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* storage queues */
	queues[Q_STORAGE_DATA_IN].queue_id = Q_STORAGE_DATA_IN;
	queues[Q_STORAGE_DATA_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_STORAGE_DATA_IN].head = 0;
	queues[Q_STORAGE_DATA_IN].tail = 0;
	queues[Q_STORAGE_DATA_IN].counter = 0;
	queues[Q_STORAGE_DATA_IN].reader_id = P_STORAGE;
	queues[Q_STORAGE_DATA_IN].writer_id = P_OS;
	queues[Q_STORAGE_DATA_IN].access_count = 0;
	queues[Q_STORAGE_DATA_IN].prev_owner = 0;
	queues[Q_STORAGE_DATA_IN].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_STORAGE_DATA_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_STORAGE_DATA_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE, MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_STORAGE_DATA_OUT].queue_id = Q_STORAGE_DATA_OUT;
	queues[Q_STORAGE_DATA_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_STORAGE_DATA_OUT].head = 0;
	queues[Q_STORAGE_DATA_OUT].tail = 0;
	queues[Q_STORAGE_DATA_OUT].counter = 0;
	queues[Q_STORAGE_DATA_OUT].reader_id = P_OS;
	queues[Q_STORAGE_DATA_OUT].writer_id = P_STORAGE;
	queues[Q_STORAGE_DATA_OUT].access_count = 0;
	queues[Q_STORAGE_DATA_OUT].prev_owner = 0;
	queues[Q_STORAGE_DATA_OUT].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_STORAGE_DATA_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_STORAGE_DATA_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE, MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_STORAGE_CMD_IN].queue_id = Q_STORAGE_CMD_IN;
	queues[Q_STORAGE_CMD_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_STORAGE_CMD_IN].head = 0;
	queues[Q_STORAGE_CMD_IN].tail = 0;
	queues[Q_STORAGE_CMD_IN].counter = 0;
	queues[Q_STORAGE_CMD_IN].reader_id = P_STORAGE;
	queues[Q_STORAGE_CMD_IN].writer_id = P_OS;
	queues[Q_STORAGE_CMD_IN].access_count = 0;
	queues[Q_STORAGE_CMD_IN].prev_owner = 0;
	queues[Q_STORAGE_CMD_IN].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_STORAGE_CMD_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_STORAGE_CMD_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	queues[Q_STORAGE_CMD_OUT].queue_id = Q_STORAGE_CMD_OUT;
	queues[Q_STORAGE_CMD_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_STORAGE_CMD_OUT].head = 0;
	queues[Q_STORAGE_CMD_OUT].tail = 0;
	queues[Q_STORAGE_CMD_OUT].counter = 0;
	queues[Q_STORAGE_CMD_OUT].reader_id = P_OS;
	queues[Q_STORAGE_CMD_OUT].writer_id = P_STORAGE;
	queues[Q_STORAGE_CMD_OUT].access_count = 0;
	queues[Q_STORAGE_CMD_OUT].prev_owner = 0;
	queues[Q_STORAGE_CMD_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_STORAGE_CMD_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_STORAGE_CMD_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* network queues */
	queues[Q_NETWORK_DATA_IN].queue_id = Q_NETWORK_DATA_IN;
	queues[Q_NETWORK_DATA_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_NETWORK_DATA_IN].head = 0;
	queues[Q_NETWORK_DATA_IN].tail = 0;
	queues[Q_NETWORK_DATA_IN].counter = 0;
	queues[Q_NETWORK_DATA_IN].reader_id = P_NETWORK;
	queues[Q_NETWORK_DATA_IN].writer_id = P_OS;
	queues[Q_NETWORK_DATA_IN].access_count = 0;
	queues[Q_NETWORK_DATA_IN].prev_owner = 0;
	queues[Q_NETWORK_DATA_IN].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_NETWORK_DATA_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_NETWORK_DATA_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE, MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_NETWORK_DATA_OUT].queue_id = Q_NETWORK_DATA_OUT;
	queues[Q_NETWORK_DATA_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_NETWORK_DATA_OUT].head = 0;
	queues[Q_NETWORK_DATA_OUT].tail = 0;
	queues[Q_NETWORK_DATA_OUT].counter = 0;
	queues[Q_NETWORK_DATA_OUT].reader_id = P_OS;
	queues[Q_NETWORK_DATA_OUT].writer_id = P_NETWORK;
	queues[Q_NETWORK_DATA_OUT].access_count = 0;
	queues[Q_NETWORK_DATA_OUT].prev_owner = 0;
	queues[Q_NETWORK_DATA_OUT].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_NETWORK_DATA_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_NETWORK_DATA_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE, MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_NETWORK_CMD_IN].queue_id = Q_NETWORK_CMD_IN;
	queues[Q_NETWORK_CMD_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_NETWORK_CMD_IN].head = 0;
	queues[Q_NETWORK_CMD_IN].tail = 0;
	queues[Q_NETWORK_CMD_IN].counter = 0;
	queues[Q_NETWORK_CMD_IN].reader_id = P_NETWORK;
	queues[Q_NETWORK_CMD_IN].writer_id = P_OS;
	queues[Q_NETWORK_CMD_IN].access_count = 0;
	queues[Q_NETWORK_CMD_IN].prev_owner = 0;
	queues[Q_NETWORK_CMD_IN].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_NETWORK_CMD_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_NETWORK_CMD_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	queues[Q_NETWORK_CMD_OUT].queue_id = Q_NETWORK_CMD_OUT;
	queues[Q_NETWORK_CMD_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_NETWORK_CMD_OUT].head = 0;
	queues[Q_NETWORK_CMD_OUT].tail = 0;
	queues[Q_NETWORK_CMD_OUT].counter = 0;
	queues[Q_NETWORK_CMD_OUT].reader_id = P_OS;
	queues[Q_NETWORK_CMD_OUT].writer_id = P_NETWORK;
	queues[Q_NETWORK_CMD_OUT].access_count = 0;
	queues[Q_NETWORK_CMD_OUT].prev_owner = 0;
	queues[Q_NETWORK_CMD_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_NETWORK_CMD_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_NETWORK_CMD_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* runtime1 queue */
	queues[Q_RUNTIME1].queue_id = Q_RUNTIME1;
	queues[Q_RUNTIME1].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_RUNTIME1].head = 0;
	queues[Q_RUNTIME1].tail = 0;
	queues[Q_RUNTIME1].counter = 0;
	queues[Q_RUNTIME1].reader_id = P_RUNTIME1;
	queues[Q_RUNTIME1].writer_id = P_OS;
	queues[Q_RUNTIME1].access_count = 0; /* irrelevant for the RUNTIME1 queue */
	queues[Q_RUNTIME1].prev_owner = 0;
	queues[Q_RUNTIME1].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_RUNTIME1].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_RUNTIME1].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* runtime2 queue */
	queues[Q_RUNTIME2].queue_id = Q_RUNTIME2;
	queues[Q_RUNTIME2].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_RUNTIME2].head = 0;
	queues[Q_RUNTIME2].tail = 0;
	queues[Q_RUNTIME2].counter = 0;
	queues[Q_RUNTIME2].reader_id = P_RUNTIME2;
	queues[Q_RUNTIME2].writer_id = P_OS;
	queues[Q_RUNTIME2].access_count = 0; /* irrelevant for the RUNTIME2 queue */
	queues[Q_RUNTIME2].prev_owner = 0;
	queues[Q_RUNTIME2].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_RUNTIME2].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_RUNTIME2].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* OS queue for untrusted */
	queues[Q_OSU].queue_id = Q_OSU;
	queues[Q_OSU].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_OSU].head = 0;
	queues[Q_OSU].tail = 0;
	queues[Q_OSU].counter = 0;
	queues[Q_OSU].reader_id = P_OS;
	queues[Q_OSU].writer_id = P_UNTRUSTED;
	queues[Q_OSU].access_count = 0;
	queues[Q_OSU].prev_owner = 0;
	queues[Q_OSU].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_OSU].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_OSU].messages = 
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* untrusted queue */
	queues[Q_UNTRUSTED].queue_id = Q_UNTRUSTED;
	queues[Q_UNTRUSTED].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_UNTRUSTED].head = 0;
	queues[Q_UNTRUSTED].tail = 0;
	queues[Q_UNTRUSTED].counter = 0;
	queues[Q_UNTRUSTED].reader_id = P_UNTRUSTED;
	queues[Q_UNTRUSTED].writer_id = P_OS;
	queues[Q_UNTRUSTED].access_count = 0; /* irrelevant for the UNTRUSTED queue */
	queues[Q_UNTRUSTED].prev_owner = 0;
	queues[Q_UNTRUSTED].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_UNTRUSTED].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_UNTRUSTED].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* tpm queue */
	queues[Q_TPM_DATA_IN].queue_id = Q_TPM_DATA_IN;
	queues[Q_TPM_DATA_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_TPM_DATA_IN].head = 0;
	queues[Q_TPM_DATA_IN].tail = 0;
	queues[Q_TPM_DATA_IN].counter = 0;
	queues[Q_TPM_DATA_IN].reader_id = P_TPM;
	queues[Q_TPM_DATA_IN].writer_id = P_OS;
	queues[Q_TPM_DATA_IN].access_count = 0;
	queues[Q_TPM_DATA_IN].prev_owner = 0;
	queues[Q_TPM_DATA_IN].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_TPM_DATA_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_TPM_DATA_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE, MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_TPM_DATA_OUT].queue_id = Q_TPM_DATA_OUT;
	queues[Q_TPM_DATA_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_TPM_DATA_OUT].head = 0;
	queues[Q_TPM_DATA_OUT].tail = 0;
	queues[Q_TPM_DATA_OUT].counter = 0;
	queues[Q_TPM_DATA_OUT].reader_id = P_OS;
	queues[Q_TPM_DATA_OUT].writer_id = P_TPM;
	queues[Q_TPM_DATA_OUT].access_count = 0;
	queues[Q_TPM_DATA_OUT].prev_owner = 0;
	queues[Q_TPM_DATA_OUT].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_TPM_DATA_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_TPM_DATA_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE, MAILBOX_QUEUE_MSG_SIZE_LARGE);
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
	if (proc_has_queue_read_access(queue_id, reader_id)) {
		struct queue *queue = &queues[(int) queue_id];
		read_queue(queue, processors[(int) reader_id].in_handle);
		processors[queue->writer_id].send_interrupt(queue_id);
		if (queue->access_count > 0) {
			queue->access_count--;
			if (queue->access_count == 0)
				change_back_queue_access(queue);
		}
	} else {
		printf("Error: processor %d can't read from queue %d\n", reader_id, queue_id);
	}
}

static void handle_write_queue(uint8_t queue_id, uint8_t writer_id)
{
	if (proc_has_queue_write_access(queue_id, writer_id)) {
		write_queue(&queues[(int) queue_id], processors[(int) writer_id].out_handle);
		processors[(int) queues[(int) queue_id].reader_id].send_interrupt(queue_id);
	} else {
		printf("Error: processor %d can't write to queue %d\n", writer_id, queue_id);
	}
}

static void reset_queue(uint8_t queue_id)
{
	for (int i = 0; i < queues[(int) queue_id].queue_size; i++)
		memset(queues[(int) queue_id].messages[i], 0x0, queues[(int) queue_id].msg_size);

	queues[(int) queue_id].head = 0;
	queues[(int) queue_id].tail = 0;
	queues[(int) queue_id].counter = 0;
}

static void reset_queue_full(uint8_t queue_id)
{
	reset_queue(queue_id);	
	queues[(int) queue_id].access_count = 0;
	queues[(int) queue_id].prev_owner = 0;
}

/* FIXME: we also have a copy of these definitions in syscall.h */
/* access modes */
#define ACCESS_UNLIMITED_REVOCABLE	0
#define ACCESS_LIMITED_IRREVOCABLE	1

static void os_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint8_t count)
{
	bool allowed = false;
	/* sanity checks */
	if (queue_id == Q_SERIAL_OUT && access == WRITE_ACCESS) {
		if (queues[Q_SERIAL_OUT].writer_id == P_OS && 
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2))
			allowed = true;

		if ((queues[Q_SERIAL_OUT].writer_id == P_RUNTIME1 || queues[Q_SERIAL_OUT].writer_id == P_RUNTIME2) &&
		    proc_id == P_OS && queues[Q_SERIAL_OUT].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_KEYBOARD && access == READ_ACCESS) {
		if (queues[Q_KEYBOARD].reader_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2))
			allowed = true;

		if ((queues[Q_KEYBOARD].reader_id == P_RUNTIME1 || queues[Q_KEYBOARD].reader_id == P_RUNTIME2) &&
		    proc_id == P_OS && queues[Q_KEYBOARD].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_STORAGE_CMD_IN && access == WRITE_ACCESS) {
		if (queues[Q_STORAGE_CMD_IN].writer_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2 || proc_id == P_UNTRUSTED))
			allowed = true;

		if ((queues[Q_STORAGE_CMD_IN].writer_id == P_RUNTIME1 || queues[Q_STORAGE_CMD_IN].writer_id == P_RUNTIME2 || queues[Q_STORAGE_CMD_IN].writer_id == P_UNTRUSTED) &&
		    proc_id == P_OS && queues[Q_STORAGE_CMD_IN].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_STORAGE_CMD_OUT && access == READ_ACCESS) {
		if (queues[Q_STORAGE_CMD_OUT].reader_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2 || proc_id == P_UNTRUSTED))
			allowed = true;

		if ((queues[Q_STORAGE_CMD_OUT].reader_id == P_RUNTIME1 || queues[Q_STORAGE_CMD_OUT].reader_id == P_RUNTIME2 || queues[Q_STORAGE_CMD_OUT].reader_id == P_UNTRUSTED) &&
		    proc_id == P_OS &&
		    queues[Q_STORAGE_CMD_OUT].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_STORAGE_DATA_IN && access == WRITE_ACCESS) {
		if (queues[Q_STORAGE_DATA_IN].writer_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2 || proc_id == P_UNTRUSTED))
			allowed = true;

		if ((queues[Q_STORAGE_DATA_IN].writer_id == P_RUNTIME1 || queues[Q_STORAGE_DATA_IN].writer_id == P_RUNTIME2 || queues[Q_STORAGE_DATA_IN].writer_id == P_UNTRUSTED) &&
		    proc_id == P_OS && queues[Q_STORAGE_DATA_IN].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_STORAGE_DATA_OUT && access == READ_ACCESS) {
		if (queues[Q_STORAGE_DATA_OUT].reader_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2 || proc_id == P_UNTRUSTED))
			allowed = true;

		if ((queues[Q_STORAGE_DATA_OUT].reader_id == P_RUNTIME1 || queues[Q_STORAGE_DATA_OUT].reader_id == P_RUNTIME2 || queues[Q_STORAGE_DATA_OUT].reader_id == P_UNTRUSTED) &&
		    proc_id == P_OS &&
		    queues[Q_STORAGE_DATA_OUT].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_NETWORK_DATA_IN && access == WRITE_ACCESS) {
		if (queues[Q_NETWORK_DATA_IN].writer_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2 || proc_id == P_UNTRUSTED))
			allowed = true;

		if ((queues[Q_NETWORK_DATA_IN].writer_id == P_RUNTIME1 || queues[Q_NETWORK_DATA_IN].writer_id == P_RUNTIME2 || queues[Q_NETWORK_DATA_IN].writer_id == P_UNTRUSTED) &&
		    proc_id == P_OS && queues[Q_NETWORK_DATA_IN].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_NETWORK_DATA_OUT && access == READ_ACCESS) {
		if (queues[Q_NETWORK_DATA_OUT].reader_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2 || proc_id == P_UNTRUSTED))
			allowed = true;

		if ((queues[Q_NETWORK_DATA_OUT].reader_id == P_RUNTIME1 || queues[Q_NETWORK_DATA_OUT].reader_id == P_RUNTIME2 || queues[Q_NETWORK_DATA_OUT].reader_id == P_UNTRUSTED) &&
		    proc_id == P_OS &&
		    queues[Q_NETWORK_DATA_OUT].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_RUNTIME1 && access == WRITE_ACCESS) {
		if (queues[Q_RUNTIME1].writer_id == P_OS &&
		    (proc_id == P_RUNTIME2))
			allowed = true;

		if ((queues[Q_RUNTIME1].writer_id == P_RUNTIME2) &&
		    proc_id == P_OS &&
		    queues[Q_RUNTIME1].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_RUNTIME2 && access == WRITE_ACCESS) {
		if (queues[Q_RUNTIME2].writer_id == P_OS &&
		    (proc_id == P_RUNTIME1))
			allowed = true;

		if ((queues[Q_RUNTIME2].writer_id == P_RUNTIME1) &&
		    proc_id == P_OS &&
		    queues[Q_RUNTIME2].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_TPM_DATA_IN && access == WRITE_ACCESS) {
		if (queues[Q_TPM_DATA_IN].writer_id == P_OS &&
			(proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2 ||
				proc_id == P_KEYBOARD || proc_id == P_STORAGE ||
				proc_id == P_SERIAL_OUT))
			allowed = true;

		if ((queues[Q_TPM_DATA_IN].writer_id == P_RUNTIME1 ||
			 queues[Q_TPM_DATA_IN].writer_id == P_RUNTIME2 ||
			 queues[Q_TPM_DATA_IN].writer_id == P_KEYBOARD ||
			 queues[Q_TPM_DATA_IN].writer_id == P_STORAGE ||
			 queues[Q_TPM_DATA_IN].writer_id == P_SERIAL_OUT) &&
			proc_id == P_OS && queues[Q_TPM_DATA_IN].access_count == 0)
			allowed = true;
	}

	if (!allowed) {		
		printf("Error: invalid config option by os\n");
		return;
	}

	reset_queue(queue_id);	

	if (access == READ_ACCESS) {
		queues[(int) queue_id].prev_owner = queues[(int) queue_id].reader_id;
		queues[(int) queue_id].reader_id = proc_id;
	} else { /* access == WRITER_ACCESS */
		queues[(int) queue_id].prev_owner = queues[(int) queue_id].writer_id;
		queues[(int) queue_id].writer_id = proc_id;
	}

	queues[(int) queue_id].access_count = count;

	/* FIXME: This is a hack. We need to properly distinguish the interrupts. */
	processors[proc_id].send_interrupt(queue_id + NUM_QUEUES);
}

static void runtime_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint8_t requesting_proc_id)
{
	bool allowed = false;
	/* sanity checks */
	if (queue_id == Q_SERIAL_OUT && access == WRITE_ACCESS &&
	    (queues[Q_SERIAL_OUT].writer_id == P_RUNTIME1 || queues[Q_SERIAL_OUT].writer_id == P_RUNTIME2) &&
	    queues[Q_SERIAL_OUT].writer_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_KEYBOARD && access == READ_ACCESS &&
		 (queues[Q_KEYBOARD].reader_id == P_RUNTIME1 || queues[Q_KEYBOARD].reader_id == P_RUNTIME2) &&
		 queues[Q_KEYBOARD].reader_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_STORAGE_CMD_IN && access == WRITE_ACCESS && 
		 (queues[Q_STORAGE_CMD_IN].writer_id == P_RUNTIME1 || queues[Q_STORAGE_CMD_IN].writer_id == P_RUNTIME2 || queues[Q_STORAGE_CMD_IN].writer_id == P_UNTRUSTED) &&
		 queues[Q_STORAGE_CMD_IN].writer_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_STORAGE_CMD_OUT && access == READ_ACCESS &&
		 (queues[Q_STORAGE_CMD_OUT].reader_id == P_RUNTIME1 || queues[Q_STORAGE_CMD_OUT].reader_id == P_RUNTIME2 || queues[Q_STORAGE_CMD_OUT].reader_id == P_UNTRUSTED) &&
		 queues[Q_STORAGE_CMD_OUT].reader_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_STORAGE_DATA_IN && access == WRITE_ACCESS && 
		 (queues[Q_STORAGE_DATA_IN].writer_id == P_RUNTIME1 || queues[Q_STORAGE_DATA_IN].writer_id == P_RUNTIME2 || queues[Q_STORAGE_DATA_IN].writer_id == P_UNTRUSTED) &&
		 queues[Q_STORAGE_DATA_IN].writer_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_STORAGE_DATA_OUT && access == READ_ACCESS &&
		 (queues[Q_STORAGE_DATA_OUT].reader_id == P_RUNTIME1 || queues[Q_STORAGE_DATA_OUT].reader_id == P_RUNTIME2 || queues[Q_STORAGE_DATA_OUT].reader_id == P_UNTRUSTED) &&
		 queues[Q_STORAGE_DATA_OUT].reader_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_NETWORK_DATA_IN && access == WRITE_ACCESS && 
		 (queues[Q_NETWORK_DATA_IN].writer_id == P_RUNTIME1 || queues[Q_NETWORK_DATA_IN].writer_id == P_RUNTIME2 || queues[Q_NETWORK_DATA_IN].writer_id == P_UNTRUSTED) &&
		 queues[Q_NETWORK_DATA_IN].writer_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_NETWORK_DATA_OUT && access == READ_ACCESS &&
		 (queues[Q_NETWORK_DATA_OUT].reader_id == P_RUNTIME1 || queues[Q_NETWORK_DATA_OUT].reader_id == P_RUNTIME2 || queues[Q_NETWORK_DATA_OUT].reader_id == P_UNTRUSTED) &&
		 queues[Q_NETWORK_DATA_OUT].reader_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_RUNTIME1 && access == WRITE_ACCESS &&
		 (queues[Q_RUNTIME1].writer_id == P_RUNTIME1 || queues[Q_RUNTIME1].writer_id == P_RUNTIME2) &&
		 queues[Q_RUNTIME1].writer_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_RUNTIME1 && access == WRITE_ACCESS &&
		 requesting_proc_id == P_RUNTIME1 && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_RUNTIME2 && access == WRITE_ACCESS &&
		 (queues[Q_RUNTIME2].writer_id == P_RUNTIME1 || queues[Q_RUNTIME2].writer_id == P_RUNTIME2) &&
		 queues[Q_RUNTIME2].writer_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_RUNTIME2 && access == WRITE_ACCESS &&
		 requesting_proc_id == P_RUNTIME2 && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_TPM_DATA_IN && access == WRITE_ACCESS &&
			 (queues[Q_TPM_DATA_IN].writer_id == P_RUNTIME1 || queues[Q_TPM_DATA_IN].writer_id == P_RUNTIME2) &&
			 queues[Q_TPM_DATA_IN].writer_id == requesting_proc_id && proc_id == P_OS)
		allowed = true;
	
	if (!allowed) {
		printf("Error: invalid config option by runtime (might not be an error in case of secure IPC)\n");
		return;
	}

	reset_queue(queue_id);	

	if (access == READ_ACCESS) {
		queues[(int) queue_id].prev_owner = queues[(int) queue_id].reader_id;
		queues[(int) queue_id].reader_id = proc_id;
	} else { /* access == WRITER_ACCESS */
		queues[(int) queue_id].prev_owner = queues[(int) queue_id].writer_id;
		queues[(int) queue_id].writer_id = proc_id;
	}

	/* FIXME: interrupt proc_id so that it knows it has access now? */

	queues[(int) queue_id].access_count = 0; /* irrelevant in this case */

	/* FIXME: This is a hack. We need to properly distinguish the interrupts. */
	processors[proc_id].send_interrupt(queue_id + NUM_QUEUES);
}

static uint8_t runtime_attest_queue_access(uint8_t queue_id, uint8_t access, uint8_t count, uint8_t requesting_proc_id)
{
	if (queue_id == Q_KEYBOARD && access == READ_ACCESS) {
		if (queues[(int) queue_id].reader_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_SERIAL_OUT && access == WRITE_ACCESS) {
		if (queues[(int) queue_id].writer_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_STORAGE_CMD_OUT && access == READ_ACCESS) {
		if (queues[(int) queue_id].reader_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_STORAGE_CMD_IN && access == WRITE_ACCESS) {
		if (queues[(int) queue_id].writer_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_STORAGE_DATA_OUT && access == READ_ACCESS) {
		if (queues[(int) queue_id].reader_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_STORAGE_DATA_IN && access == WRITE_ACCESS) {
		if (queues[(int) queue_id].writer_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_NETWORK_DATA_OUT && access == READ_ACCESS) {
		if (queues[(int) queue_id].reader_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_NETWORK_DATA_IN && access == WRITE_ACCESS) {
		if (queues[(int) queue_id].writer_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_RUNTIME1 && access == WRITE_ACCESS) {
		if (queues[(int) queue_id].writer_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_RUNTIME2 && access == WRITE_ACCESS) {
		if (queues[(int) queue_id].writer_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	}

	return 0;
}

static void *run_timer(void *data)
{
	while (1) {
		sleep(1);
		processors[P_OS].send_interrupt(0);
	}
}

int main(int argc, char **argv)
{
	uint8_t opcode[2], writer_id, reader_id, queue_id;
	pthread_t timer_thread;

	initialize_processors();
	/* FIXME: release memory allocated for queues on exit */
	initialize_queues();

	fd_set listen_fds;
	int nfds;
	
	FD_ZERO(&listen_fds);

	nfds = processors[P_KEYBOARD].out_handle;
	if (processors[P_OS].out_handle > nfds)
		nfds = processors[P_OS].out_handle;
	if (processors[P_SERIAL_OUT].out_handle > nfds)
		nfds = processors[P_SERIAL_OUT].out_handle;
	if (processors[P_STORAGE].out_handle > nfds)
		nfds = processors[P_STORAGE].out_handle;
	if (processors[P_NETWORK].out_handle > nfds)
		nfds = processors[P_NETWORK].out_handle;
	if (processors[P_RUNTIME1].out_handle > nfds)
		nfds = processors[P_RUNTIME1].out_handle;
	if (processors[P_RUNTIME2].out_handle > nfds)
		nfds = processors[P_RUNTIME2].out_handle;
	if (processors[P_UNTRUSTED].out_handle > nfds)
		nfds = processors[P_UNTRUSTED].out_handle;
	if (processors[P_TPM].out_handle > nfds)
		nfds = processors[P_TPM].out_handle;

	int pret = pthread_create(&timer_thread, NULL, run_timer, NULL);
	if (pret) {
		printf("Error: couldn't launch the timer thread\n");
		return -1;
	}

	while(1) {
		FD_SET(processors[P_OS].out_handle, &listen_fds);
		FD_SET(processors[P_KEYBOARD].out_handle, &listen_fds);
		FD_SET(processors[P_SERIAL_OUT].out_handle, &listen_fds);
		FD_SET(processors[P_STORAGE].out_handle, &listen_fds);
		FD_SET(processors[P_NETWORK].out_handle, &listen_fds);
		FD_SET(processors[P_RUNTIME1].out_handle, &listen_fds);
		FD_SET(processors[P_RUNTIME2].out_handle, &listen_fds);
		FD_SET(processors[P_UNTRUSTED].out_handle, &listen_fds);
		FD_SET(processors[P_TPM].out_handle, &listen_fds);

		if (select(nfds + 1, &listen_fds, NULL, NULL, NULL) < 0) {
			printf("Error: select\n");
			break;
		}

		if (FD_ISSET(processors[P_OS].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[P_OS].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = P_OS;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = P_OS;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else if (opcode[0] == MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS) {
				uint8_t opcode_rest[3];
				memset(opcode_rest, 0x0, 3);
				read(processors[P_OS].out_handle, opcode_rest, 3);
				os_change_queue_access(opcode[1], opcode_rest[0], opcode_rest[1], opcode_rest[2]);				
			} else {
				printf("Error: invalid opcode from OS\n");
			}
		}

		if (FD_ISSET(processors[P_KEYBOARD].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[P_KEYBOARD].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = P_KEYBOARD;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else {
				printf("Error: invalid opcode from keyboard\n");
			}
		}		

		if (FD_ISSET(processors[P_SERIAL_OUT].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[P_SERIAL_OUT].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = P_SERIAL_OUT;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = P_SERIAL_OUT;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else {
				printf("Error: invalid opcode from serial_out\n");
			}
		}

		if (FD_ISSET(processors[P_RUNTIME1].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[P_RUNTIME1].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = P_RUNTIME1;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = P_RUNTIME1;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else if (opcode[0] == MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS) {
				uint8_t opcode_rest[2];
				memset(opcode_rest, 0x0, 2);
				read(processors[P_RUNTIME1].out_handle, opcode_rest, 2);
				runtime_change_queue_access(opcode[1], opcode_rest[0], opcode_rest[1], P_RUNTIME1);				
			} else if (opcode[0] == MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS) {
				uint8_t opcode_rest[2];
				memset(opcode_rest, 0x0, 2);
				read(processors[P_RUNTIME1].out_handle, opcode_rest, 2);
				uint8_t ret = runtime_attest_queue_access(opcode[1], opcode_rest[0], opcode_rest[1], P_RUNTIME1);				
				write(processors[P_RUNTIME1].in_handle, &ret, 1);
			/* FIXME: This should be triggered by the power management unit. */
			} else if (opcode[0] == MAILBOX_OPCODE_RESET) {
				close(processors[P_RUNTIME1].out_handle);
				close(processors[P_RUNTIME1].in_handle);
				close(processors[P_RUNTIME1].intr_handle);
				remove(FIFO_RUNTIME1_OUT);
				remove(FIFO_RUNTIME1_IN);
				remove(FIFO_RUNTIME1_INTR);
				
				reset_queue_full(Q_RUNTIME1);
				reset_queue_full(Q_OS1);

				mkfifo(FIFO_RUNTIME1_OUT, 0666);
				mkfifo(FIFO_RUNTIME1_IN, 0666);
				mkfifo(FIFO_RUNTIME1_INTR, 0666);
				processors[P_RUNTIME1].out_handle = open(FIFO_RUNTIME1_OUT, O_RDWR);
				processors[P_RUNTIME1].in_handle = open(FIFO_RUNTIME1_IN, O_RDWR);
				processors[P_RUNTIME1].intr_handle = open(FIFO_RUNTIME1_INTR, O_RDWR);
			} else {
				printf("Error: invalid opcode from runtime\n");
			}
		}

		if (FD_ISSET(processors[P_RUNTIME2].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[P_RUNTIME2].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = P_RUNTIME2;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = P_RUNTIME2;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else if (opcode[0] == MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS) {
				uint8_t opcode_rest[2];
				memset(opcode_rest, 0x0, 2);
				read(processors[P_RUNTIME2].out_handle, opcode_rest, 2);
				runtime_change_queue_access(opcode[1], opcode_rest[0], opcode_rest[1], P_RUNTIME2);				
			} else if (opcode[0] == MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS) {
				uint8_t opcode_rest[2];
				memset(opcode_rest, 0x0, 2);
				read(processors[P_RUNTIME2].out_handle, opcode_rest, 2);
				uint8_t ret = runtime_attest_queue_access(opcode[1], opcode_rest[0], opcode_rest[1], P_RUNTIME2);				
				write(processors[P_RUNTIME2].in_handle, &ret, 1);
			/* FIXME: This should be triggered by the power management unit. */
			} else if (opcode[0] == MAILBOX_OPCODE_RESET) {
				close(processors[P_RUNTIME2].out_handle);
				close(processors[P_RUNTIME2].in_handle);
				close(processors[P_RUNTIME2].intr_handle);
				remove(FIFO_RUNTIME2_OUT);
				remove(FIFO_RUNTIME2_IN);
				remove(FIFO_RUNTIME2_INTR);
				
				reset_queue_full(Q_RUNTIME2);
				reset_queue_full(Q_OS2);

				mkfifo(FIFO_RUNTIME2_OUT, 0666);
				mkfifo(FIFO_RUNTIME2_IN, 0666);
				mkfifo(FIFO_RUNTIME2_INTR, 0666);
				processors[P_RUNTIME2].out_handle = open(FIFO_RUNTIME2_OUT, O_RDWR);
				processors[P_RUNTIME2].in_handle = open(FIFO_RUNTIME2_IN, O_RDWR);
				processors[P_RUNTIME2].intr_handle = open(FIFO_RUNTIME2_INTR, O_RDWR);
			} else {
				printf("Error: invalid opcode from runtime\n");
			}
		}

		if (FD_ISSET(processors[P_STORAGE].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[P_STORAGE].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = P_STORAGE;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = P_STORAGE;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else {
				printf("Error: invalid opcode from storage\n");
			}
		}

		if (FD_ISSET(processors[P_NETWORK].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[P_NETWORK].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = P_NETWORK;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = P_NETWORK;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else {
				printf("Error: invalid opcode from storage\n");
			}
		}
		
		if (FD_ISSET(processors[P_UNTRUSTED].out_handle, &listen_fds)) {
			memset(opcode, 0x0, 2);
			read(processors[P_UNTRUSTED].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE) {
				reader_id = P_UNTRUSTED;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			} else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE) {
				writer_id = P_UNTRUSTED;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			} else if (opcode[0] == MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS) {
				uint8_t opcode_rest[2];
				memset(opcode_rest, 0x0, 2);
				read(processors[P_UNTRUSTED].out_handle, opcode_rest, 2);
				runtime_change_queue_access(opcode[1], opcode_rest[0], opcode_rest[1], P_UNTRUSTED);				
			} else if (opcode[0] == MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS) {
				uint8_t opcode_rest[2];
				memset(opcode_rest, 0x0, 2);
				read(processors[P_UNTRUSTED].out_handle, opcode_rest, 2);
				uint8_t ret = runtime_attest_queue_access(opcode[1], opcode_rest[0], opcode_rest[1], P_UNTRUSTED);				
				write(processors[P_UNTRUSTED].in_handle, &ret, 1);
			} else {
				printf("Error: invalid opcode from untrusted\n");
			}
		}

		if (FD_ISSET(processors[P_TPM].out_handle, &listen_fds))
		{
			memset(opcode, 0x0, 2);
			read(processors[P_TPM].out_handle, opcode, 2);
			if (opcode[0] == MAILBOX_OPCODE_READ_QUEUE)
			{
				reader_id = P_TPM;
				queue_id = opcode[1];
				writer_id = INVALID_PROCESSOR;
				handle_read_queue(queue_id, reader_id);
			}
			else if (opcode[0] == MAILBOX_OPCODE_WRITE_QUEUE)
			{
				writer_id = P_TPM;
				queue_id = opcode[1];
				reader_id = INVALID_PROCESSOR;
				handle_write_queue(queue_id, writer_id);
			}
			else
			{
				printf("Error: invalid opcode from tpm\n");
			}
		}
	}	

	pthread_cancel(timer_thread);
	pthread_join(timer_thread, NULL);

	close_processors();
}
