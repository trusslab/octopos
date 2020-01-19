/* octopos mailbox */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
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
};

struct processor processors[NUM_PROCESSORS];
struct queue queues[NUM_QUEUES];

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
	printf("%s [1]: queue_id = %d\n", __func__, queue_id);
	send_interrupt(&processors[P_OS], queue_id);
}

/* dummy */
static void keyboard_send_interrupt(uint8_t queue_id)
{
}

static void serial_out_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_SERIAL_OUT], queue_id);
}

static void runtime1_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_RUNTIME1], queue_id);
}

static void runtime2_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_RUNTIME2], queue_id);
}

static void storage_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_STORAGE], queue_id);
}

static void initialize_processors(void)
{
	/* initialize connections to the processors */
	mkfifo(FIFO_OS_OUT, 0666);
	mkfifo(FIFO_OS_IN, 0666);
	mkfifo(FIFO_OS_INTR, 0666);
	mkfifo(FIFO_KEYBOARD, 0666);
	mkfifo(FIFO_SENSOR, 0666);
	mkfifo(FIFO_SERIAL_OUT_OUT, 0666);
	mkfifo(FIFO_SERIAL_OUT_IN, 0666);
	mkfifo(FIFO_SERIAL_OUT_INTR, 0666);
	mkfifo(FIFO_RUNTIME1_OUT, 0666);
	mkfifo(FIFO_RUNTIME1_IN, 0666);
	mkfifo(FIFO_RUNTIME1_INTR, 0666);
	mkfifo(FIFO_RUNTIME2_OUT, 0666);
	mkfifo(FIFO_RUNTIME2_IN, 0666);
	mkfifo(FIFO_RUNTIME2_INTR, 0666);
	mkfifo(FIFO_STORAGE_OUT, 0666);
	mkfifo(FIFO_STORAGE_IN, 0666);
	mkfifo(FIFO_STORAGE_INTR, 0666);

	/* initialize processor objects */
	/* OS processor */
	processors[P_OS].processor_id = P_OS;
	processors[P_OS].send_interrupt = os_send_interrupt;
	processors[P_OS].out_handle = open(FIFO_OS_OUT, O_RDWR);
	processors[P_OS].in_handle = open(FIFO_OS_IN, O_RDWR);
	processors[P_OS].intr_handle = open(FIFO_OS_INTR, O_RDWR);

	/* keyboard processor */
	processors[P_KEYBOARD].processor_id = P_KEYBOARD;
	processors[P_KEYBOARD].send_interrupt = keyboard_send_interrupt; /* dummy */
	processors[P_KEYBOARD].out_handle = open(FIFO_KEYBOARD, O_RDWR);
	processors[P_KEYBOARD].in_handle = -1; /* not needed */

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

	/* storage processor */
	processors[P_STORAGE].processor_id = P_STORAGE;
	processors[P_STORAGE].send_interrupt = storage_send_interrupt;
	processors[P_STORAGE].out_handle = open(FIFO_STORAGE_OUT, O_RDWR);
	processors[P_STORAGE].in_handle = open(FIFO_STORAGE_IN, O_RDWR);
	processors[P_STORAGE].intr_handle = open(FIFO_STORAGE_INTR, O_RDWR);
}

static void close_processors(void)
{
	close(processors[P_OS].out_handle);
	close(processors[P_OS].in_handle);
	close(processors[P_OS].intr_handle);
	close(processors[P_KEYBOARD].out_handle);
	close(processors[P_SERIAL_OUT].out_handle);
	close(processors[P_SERIAL_OUT].in_handle);
	close(processors[P_SERIAL_OUT].intr_handle);
	close(processors[P_RUNTIME1].out_handle);
	close(processors[P_RUNTIME1].in_handle);
	close(processors[P_RUNTIME1].intr_handle);
	close(processors[P_RUNTIME2].out_handle);
	close(processors[P_RUNTIME2].in_handle);
	close(processors[P_RUNTIME2].intr_handle);
	close(processors[P_STORAGE].out_handle);
	close(processors[P_STORAGE].in_handle);
	close(processors[P_STORAGE].intr_handle);

	remove(FIFO_OS_OUT);
	remove(FIFO_OS_IN);
	remove(FIFO_OS_INTR);
	remove(FIFO_KEYBOARD);
	remove(FIFO_SERIAL_OUT_OUT);
	remove(FIFO_SERIAL_OUT_IN);
	remove(FIFO_SERIAL_OUT_INTR);
	remove(FIFO_RUNTIME1_OUT);
	remove(FIFO_RUNTIME1_IN);
	remove(FIFO_RUNTIME1_INTR);
	remove(FIFO_RUNTIME2_OUT);
	remove(FIFO_RUNTIME2_IN);
	remove(FIFO_RUNTIME2_INTR);
	remove(FIFO_STORAGE_OUT);
	remove(FIFO_STORAGE_IN);
	remove(FIFO_STORAGE_INTR);
}

static int write_queue(struct queue *queue, int out_handle)
{
	if (queue->counter >= queue->queue_size) {
		/* FIXME: we should communicate that back to the sender processor */
		printf("Error: queue (%d) is full\n", queue->queue_id);
		/* FIXME: remove */
		sleep(10);
		_exit(-1);
		return -1;
	}

	queue->counter++;
	read(out_handle, queue->messages[queue->tail], queue->msg_size);
	queue->tail = (queue->tail + 1) % queue->queue_size;

	if (queue->access_count > 0)
		queue->access_count--;

	return 0;
}

static int read_queue(struct queue *queue, int in_handle)
{
	if (queue->counter <= 0) {
		/* FIXME: we should communicate that back to the sender processor */
		printf("Error: queue %d is empty\n", queue->queue_id);
		/* FIXME: remove */
		sleep(10);
		_exit(-1);
		return -1;
	}

	queue->counter--;
	write(in_handle, queue->messages[queue->head], queue->msg_size);
	queue->head = (queue->head + 1) % queue->queue_size;

	if (queue->access_count > 0)
		queue->access_count--;

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
	queues[Q_OS1].head = 0;
	queues[Q_OS1].tail = 0;
	queues[Q_OS1].counter = 0;
	queues[Q_OS1].reader_id = P_OS;
	queues[Q_OS1].writer_id = P_RUNTIME1;
	queues[Q_OS1].access_count = 0; /* irrelevant for the OS queue */
	queues[Q_OS1].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_OS1].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_OS1].messages = 
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* OS queue for runtime1 */
	queues[Q_OS2].queue_id = Q_OS2;
	queues[Q_OS2].head = 0;
	queues[Q_OS2].tail = 0;
	queues[Q_OS2].counter = 0;
	queues[Q_OS2].reader_id = P_OS;
	queues[Q_OS2].writer_id = P_RUNTIME2;
	queues[Q_OS2].access_count = 0; /* irrelevant for the OS queue */
	queues[Q_OS2].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_OS2].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_OS2].messages = 
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* keyboard queue */
	queues[Q_KEYBOARD].queue_id = Q_KEYBOARD;
	queues[Q_KEYBOARD].head = 0;
	queues[Q_KEYBOARD].tail = 0;
	queues[Q_KEYBOARD].counter = 0;
	queues[Q_KEYBOARD].reader_id = P_OS;
	queues[Q_KEYBOARD].writer_id = P_KEYBOARD;
	queues[Q_KEYBOARD].access_count = 0; /* irrelevant when OS is reader */
	queues[Q_KEYBOARD].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_KEYBOARD].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_KEYBOARD].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* serial output queue */
	queues[Q_SERIAL_OUT].queue_id = Q_SERIAL_OUT;
	queues[Q_SERIAL_OUT].head = 0;
	queues[Q_SERIAL_OUT].tail = 0;
	queues[Q_SERIAL_OUT].counter = 0;
	queues[Q_SERIAL_OUT].reader_id = P_SERIAL_OUT;
	queues[Q_SERIAL_OUT].writer_id = P_OS;
	queues[Q_SERIAL_OUT].access_count = 0; /* irrelevant when OS is writer */
	queues[Q_SERIAL_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_SERIAL_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_SERIAL_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* runtime1 queue */
	queues[Q_RUNTIME1].queue_id = Q_RUNTIME1;
	queues[Q_RUNTIME1].head = 0;
	queues[Q_RUNTIME1].tail = 0;
	queues[Q_RUNTIME1].counter = 0;
	queues[Q_RUNTIME1].reader_id = P_RUNTIME1;
	queues[Q_RUNTIME1].writer_id = P_OS;
	queues[Q_RUNTIME1].access_count = 0; /* irrelevant for the RUNTIME1 queue */
	queues[Q_RUNTIME1].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_RUNTIME1].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_RUNTIME1].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* runtime2 queue */
	queues[Q_RUNTIME2].queue_id = Q_RUNTIME2;
	queues[Q_RUNTIME2].head = 0;
	queues[Q_RUNTIME2].tail = 0;
	queues[Q_RUNTIME2].counter = 0;
	queues[Q_RUNTIME2].reader_id = P_RUNTIME2;
	queues[Q_RUNTIME2].writer_id = P_OS;
	queues[Q_RUNTIME2].access_count = 0; /* irrelevant for the RUNTIME2 queue */
	queues[Q_RUNTIME2].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_RUNTIME2].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_RUNTIME2].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	/* storage queues */
	queues[Q_STORAGE_DATA_IN].queue_id = Q_STORAGE_DATA_IN;
	queues[Q_STORAGE_DATA_IN].head = 0;
	queues[Q_STORAGE_DATA_IN].tail = 0;
	queues[Q_STORAGE_DATA_IN].counter = 0;
	queues[Q_STORAGE_DATA_IN].reader_id = P_STORAGE;
	queues[Q_STORAGE_DATA_IN].writer_id = P_OS;
	queues[Q_STORAGE_DATA_IN].access_count = 0; /* irrelevant for main STORAGE queues */
	queues[Q_STORAGE_DATA_IN].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_STORAGE_DATA_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_STORAGE_DATA_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE, MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_STORAGE_DATA_OUT].queue_id = Q_STORAGE_DATA_OUT;
	queues[Q_STORAGE_DATA_OUT].head = 0;
	queues[Q_STORAGE_DATA_OUT].tail = 0;
	queues[Q_STORAGE_DATA_OUT].counter = 0;
	queues[Q_STORAGE_DATA_OUT].reader_id = P_OS;
	queues[Q_STORAGE_DATA_OUT].writer_id = P_STORAGE;
	queues[Q_STORAGE_DATA_OUT].access_count = 0; /* irrelevant for main STORAGE queues */
	queues[Q_STORAGE_DATA_OUT].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_STORAGE_DATA_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_STORAGE_DATA_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE, MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_STORAGE_CMD_IN].queue_id = Q_STORAGE_CMD_IN;
	queues[Q_STORAGE_CMD_IN].head = 0;
	queues[Q_STORAGE_CMD_IN].tail = 0;
	queues[Q_STORAGE_CMD_IN].counter = 0;
	queues[Q_STORAGE_CMD_IN].reader_id = P_STORAGE;
	queues[Q_STORAGE_CMD_IN].writer_id = P_OS;
	queues[Q_STORAGE_CMD_IN].access_count = 0; /* irrelevant for main STORAGE queues */
	queues[Q_STORAGE_CMD_IN].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_STORAGE_CMD_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_STORAGE_CMD_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	queues[Q_STORAGE_CMD_OUT].queue_id = Q_STORAGE_CMD_OUT;
	queues[Q_STORAGE_CMD_OUT].head = 0;
	queues[Q_STORAGE_CMD_OUT].tail = 0;
	queues[Q_STORAGE_CMD_OUT].counter = 0;
	queues[Q_STORAGE_CMD_OUT].reader_id = P_OS;
	queues[Q_STORAGE_CMD_OUT].writer_id = P_STORAGE;
	queues[Q_STORAGE_CMD_OUT].access_count = 0; /* irrelevant for main STORAGE queues */
	queues[Q_STORAGE_CMD_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_STORAGE_CMD_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_STORAGE_CMD_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	queues[Q_STORAGE_IN_2].queue_id = Q_STORAGE_IN_2;
	queues[Q_STORAGE_IN_2].head = 0;
	queues[Q_STORAGE_IN_2].tail = 0;
	queues[Q_STORAGE_IN_2].counter = 0;
	queues[Q_STORAGE_IN_2].reader_id = P_STORAGE;
	queues[Q_STORAGE_IN_2].writer_id = P_OS;
	queues[Q_STORAGE_IN_2].access_count = 0; /* irrelevant when OS is writer */
	queues[Q_STORAGE_IN_2].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_STORAGE_IN_2].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_STORAGE_IN_2].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);

	queues[Q_STORAGE_OUT_2].queue_id = Q_STORAGE_OUT_2;
	queues[Q_STORAGE_OUT_2].head = 0;
	queues[Q_STORAGE_OUT_2].tail = 0;
	queues[Q_STORAGE_OUT_2].counter = 0;
	queues[Q_STORAGE_OUT_2].reader_id = P_OS;
	queues[Q_STORAGE_OUT_2].writer_id = P_STORAGE;
	queues[Q_STORAGE_OUT_2].access_count = 0; /* irrelevant when OS is reader */
	queues[Q_STORAGE_OUT_2].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_STORAGE_OUT_2].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_STORAGE_OUT_2].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);
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
	printf("%s [1]: queue_id = %d, reader_id = %d\n", __func__, queue_id, reader_id);
	if (proc_has_queue_read_access(queue_id, reader_id)) {
		read_queue(&queues[(int) queue_id], processors[(int) reader_id].in_handle);
		printf("%s [2]: writer_id = %d\n", __func__, queues[queue_id].writer_id);
		processors[(int) queues[(int) queue_id].writer_id].send_interrupt(queue_id);
	} else {
		printf("Error: processor %d can't read from queue %d\n", reader_id, queue_id);
	}
}

static void handle_write_queue(uint8_t queue_id, uint8_t writer_id)
{
	printf("%s [1]: queue_id = %d, writer_id = %d\n", __func__, queue_id, writer_id);
	if (proc_has_queue_write_access(queue_id, writer_id)) {
		write_queue(&queues[(int) queue_id], processors[(int) writer_id].out_handle);
		printf("%s [2]: reader_id = %d\n", __func__, queues[queue_id].reader_id);
		processors[(int) queues[(int) queue_id].reader_id].send_interrupt(queue_id);
	} else {
		printf("Error: processor %d can't write to queue %d\n", writer_id, queue_id);
	}
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
	} else if (queue_id == Q_STORAGE_IN_2 && access == WRITE_ACCESS) {
		if (queues[Q_STORAGE_IN_2].writer_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2))
			allowed = true;

		if ((queues[Q_STORAGE_IN_2].writer_id == P_RUNTIME1 || queues[Q_STORAGE_IN_2].writer_id == P_RUNTIME2) &&
		    proc_id == P_OS && queues[Q_STORAGE_IN_2].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_STORAGE_OUT_2 && access == READ_ACCESS) {
		if (queues[Q_STORAGE_OUT_2].reader_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2))
			allowed = true;

		if ((queues[Q_STORAGE_OUT_2].reader_id == P_RUNTIME1 || queues[Q_STORAGE_OUT_2].reader_id == P_RUNTIME2) &&
		    proc_id == P_OS &&
		    queues[Q_STORAGE_OUT_2].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_STORAGE_DATA_IN && access == WRITE_ACCESS) {
		if (queues[Q_STORAGE_DATA_IN].writer_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2))
			allowed = true;

		if ((queues[Q_STORAGE_DATA_IN].writer_id == P_RUNTIME1 || queues[Q_STORAGE_DATA_IN].writer_id == P_RUNTIME2) &&
		    proc_id == P_OS && queues[Q_STORAGE_DATA_IN].access_count == 0)
			allowed = true;
	} else if (queue_id == Q_STORAGE_DATA_OUT && access == READ_ACCESS) {
		if (queues[Q_STORAGE_DATA_OUT].reader_id == P_OS &&
		    (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2))
			allowed = true;

		if ((queues[Q_STORAGE_DATA_OUT].reader_id == P_RUNTIME1 || queues[Q_STORAGE_DATA_OUT].reader_id == P_RUNTIME2) &&
		    proc_id == P_OS &&
		    queues[Q_STORAGE_DATA_OUT].access_count == 0)
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
	}
	
	if (!allowed) {		
		printf("Error: invalid config option by os\n");
		return;
	}

	/* FIXME: do we need to zero out the queue? */

	if (access == READ_ACCESS)
		queues[(int) queue_id].reader_id = proc_id;
	else /* access == WRITER_ACCESS */
		queues[(int) queue_id].writer_id = proc_id;

	queues[(int) queue_id].access_count = count;

	/* FIXME: This is a hack. We need to properly distinguish the interrupts. */
	if (queue_id == Q_RUNTIME1 || queue_id == Q_RUNTIME2)
		processors[(int) queues[(int) queue_id].reader_id].send_interrupt(queue_id + NUM_QUEUES);
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
	else if (queue_id == Q_STORAGE_IN_2 && access == WRITE_ACCESS && 
		 (queues[Q_STORAGE_IN_2].writer_id == P_RUNTIME1 || queues[Q_STORAGE_IN_2].writer_id == P_RUNTIME2) &&
		 queues[Q_STORAGE_IN_2].writer_id == requesting_proc_id && proc_id == P_OS)
			allowed = true;
	else if (queue_id == Q_STORAGE_OUT_2 && access == READ_ACCESS &&
		 (queues[Q_STORAGE_OUT_2].reader_id == P_RUNTIME1 || queues[Q_STORAGE_OUT_2].reader_id == P_RUNTIME2) &&
		 queues[Q_STORAGE_OUT_2].reader_id == requesting_proc_id && proc_id == P_OS)
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
	
	if (!allowed) {		
		printf("Error: invalid config option by runtime (might not be an error in case of secure IPC)\n");
		return;
	}

	/* FIXME: do we need to zero out the queue? */

	if (access == READ_ACCESS)
		queues[(int) queue_id].reader_id = proc_id;
	else /* access == WRITER_ACCESS */
		queues[(int) queue_id].writer_id = proc_id;

	/* FIXME: interrupt proc_id so that it knows it has access now? */

	queues[(int) queue_id].access_count = 0; /* irrelevant in this case */
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
	} else if (queue_id == Q_STORAGE_OUT_2 && access == READ_ACCESS) {
		if (queues[(int) queue_id].reader_id == requesting_proc_id &&
		    queues[(int) queue_id].access_count == count)
			return 1;
		else
			return 0;
	} else if (queue_id == Q_STORAGE_IN_2 && access == WRITE_ACCESS) {
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

int main(int argc, char **argv)
{
	uint8_t opcode[2], writer_id, reader_id, queue_id;

	initialize_processors();
	initialize_queues();

	fd_set listen_fds;
	int nfds;
	
	FD_ZERO(&listen_fds);

	nfds = processors[P_KEYBOARD].out_handle;
	if (processors[P_OS].out_handle > nfds)
		nfds = processors[P_OS].out_handle;
	if (processors[P_SERIAL_OUT].out_handle > nfds)
		nfds = processors[P_SERIAL_OUT].out_handle;
	if (processors[P_RUNTIME1].out_handle > nfds)
		nfds = processors[P_RUNTIME1].out_handle;
	if (processors[P_RUNTIME2].out_handle > nfds)
		nfds = processors[P_RUNTIME2].out_handle;
	if (processors[P_STORAGE].out_handle > nfds)
		nfds = processors[P_STORAGE].out_handle;

	while(1) {
		FD_SET(processors[P_OS].out_handle, &listen_fds);
		FD_SET(processors[P_KEYBOARD].out_handle, &listen_fds);
		FD_SET(processors[P_SERIAL_OUT].out_handle, &listen_fds);
		FD_SET(processors[P_RUNTIME1].out_handle, &listen_fds);
		FD_SET(processors[P_RUNTIME2].out_handle, &listen_fds);
		FD_SET(processors[P_STORAGE].out_handle, &listen_fds);

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
	}	

	close_processors();
}
