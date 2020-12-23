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
#include <arch/mailbox.h>
#include <arch/pmu.h>

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
#define QUEUE_TYPE_SIMPLE		2
	uint8_t **messages;
	int queue_size;
	int msg_size;
	int head;
	int tail;
	int counter;
	/* access control */
	/* For SIMPLE queues, fixed_proc is the reader and owner is the writer.
	 * ALso, for SIMPLE queues, connections, limit, timeout, and prev_owner are not used. */
	uint8_t fixed_proc;
	uint8_t connections[NUM_PROCESSORS + 1]; /* All procs connected to the non-fixed end of the mailbox */
	/* state register */
	mailbox_state_reg_t state_reg;
#define OWNER	state_reg.owner
#define LIMIT	state_reg.limit
#define TIMEOUT	state_reg.timeout
	uint8_t prev_owner;
	int delegation_disabled;
};

struct processor processors[NUM_PROCESSORS + 1];
struct queue queues[NUM_QUEUES + 1];

int delegation_allowed = 1;

static void send_interrupt(struct processor *proc, uint8_t queue_id)
{
	write(proc->intr_handle, &queue_id, 1);
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

static void bluetooth_send_interrupt(uint8_t queue_id)
{
	send_interrupt(&processors[P_BLUETOOTH], queue_id);
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
	mkfifo(FIFO_KEYBOARD_IN, 0666);
	mkfifo(FIFO_KEYBOARD_INTR, 0666);
	mkfifo(FIFO_SERIAL_OUT_OUT, 0666);
	mkfifo(FIFO_SERIAL_OUT_IN, 0666);
	mkfifo(FIFO_SERIAL_OUT_INTR, 0666);
	mkfifo(FIFO_STORAGE_OUT, 0666);
	mkfifo(FIFO_STORAGE_IN, 0666);
	mkfifo(FIFO_STORAGE_INTR, 0666);
	mkfifo(FIFO_NETWORK_OUT, 0666);
	mkfifo(FIFO_NETWORK_IN, 0666);
	mkfifo(FIFO_NETWORK_INTR, 0666);
	mkfifo(FIFO_BLUETOOTH_OUT, 0666);
	mkfifo(FIFO_BLUETOOTH_IN, 0666);
	mkfifo(FIFO_BLUETOOTH_INTR, 0666);
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
	processors[P_KEYBOARD].in_handle = open(FIFO_KEYBOARD_IN, O_RDWR);
	processors[P_KEYBOARD].intr_handle = open(FIFO_KEYBOARD_INTR, O_RDWR);

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

	/* bluetooth processor */
	processors[P_BLUETOOTH].processor_id = P_BLUETOOTH;
	processors[P_BLUETOOTH].send_interrupt = bluetooth_send_interrupt;
	processors[P_BLUETOOTH].out_handle = open(FIFO_BLUETOOTH_OUT, O_RDWR);
	processors[P_BLUETOOTH].in_handle = open(FIFO_BLUETOOTH_IN, O_RDWR);
	processors[P_BLUETOOTH].intr_handle = open(FIFO_BLUETOOTH_INTR, O_RDWR);

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
	close(processors[P_KEYBOARD].in_handle);
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
	close(processors[P_BLUETOOTH].out_handle);
	close(processors[P_BLUETOOTH].in_handle);
	close(processors[P_BLUETOOTH].intr_handle);
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
	remove(FIFO_KEYBOARD_IN);
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

	queue->OWNER = queue->prev_owner;
	queue->prev_owner = 0;
	queue->LIMIT = MAILBOX_NO_LIMIT_VAL;
	queue->TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	processors[queue->OWNER].send_interrupt(queue->queue_id + NUM_QUEUES);

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

/* Must only be called on queues that support delegation */
static int is_queue_securely_delegated(uint8_t queue_id)
{
	return (queues[queue_id].OWNER != P_OS);
}

static int any_secure_delegations(void)
{
	return (is_queue_securely_delegated(Q_KEYBOARD) ||
		is_queue_securely_delegated(Q_SERIAL_OUT) ||
		is_queue_securely_delegated(Q_STORAGE_DATA_IN) ||
		is_queue_securely_delegated(Q_STORAGE_DATA_OUT) ||
		is_queue_securely_delegated(Q_STORAGE_CMD_IN) ||
		is_queue_securely_delegated(Q_STORAGE_CMD_OUT) ||
		is_queue_securely_delegated(Q_NETWORK_DATA_IN) ||
		is_queue_securely_delegated(Q_NETWORK_DATA_OUT) ||
		is_queue_securely_delegated(Q_NETWORK_CMD_IN) ||
		is_queue_securely_delegated(Q_NETWORK_CMD_OUT) ||
		is_queue_securely_delegated(Q_BLUETOOTH_DATA_IN) ||
		is_queue_securely_delegated(Q_BLUETOOTH_DATA_OUT) ||
		is_queue_securely_delegated(Q_BLUETOOTH_CMD_IN) ||
		is_queue_securely_delegated(Q_BLUETOOTH_CMD_OUT) ||
		is_queue_securely_delegated(Q_RUNTIME1) ||
		is_queue_securely_delegated(Q_RUNTIME2));
}

static int does_proc_have_secure_io(uint8_t proc_id)
{
	return ((queues[Q_KEYBOARD].OWNER == proc_id) ||
		(queues[Q_SERIAL_OUT].OWNER == proc_id) ||
		(queues[Q_STORAGE_DATA_IN].OWNER == proc_id) ||
		(queues[Q_STORAGE_DATA_OUT].OWNER == proc_id) ||
		(queues[Q_STORAGE_CMD_IN].OWNER == proc_id) ||
		(queues[Q_STORAGE_CMD_OUT].OWNER == proc_id) ||
		(queues[Q_NETWORK_DATA_IN].OWNER == proc_id) ||
		(queues[Q_NETWORK_DATA_OUT].OWNER == proc_id) ||
		(queues[Q_NETWORK_CMD_IN].OWNER == proc_id) ||
		(queues[Q_NETWORK_CMD_OUT].OWNER == proc_id) ||
		(queues[Q_BLUETOOTH_DATA_IN].OWNER == proc_id) ||
		(queues[Q_BLUETOOTH_DATA_OUT].OWNER == proc_id) ||
		(queues[Q_BLUETOOTH_CMD_IN].OWNER == proc_id) ||
		(queues[Q_BLUETOOTH_CMD_OUT].OWNER == proc_id));
}

static int does_proc_have_secure_delegatation(uint8_t proc_id)
{
	switch(proc_id) {
	case P_KEYBOARD:
		return is_queue_securely_delegated(Q_KEYBOARD);

	case P_SERIAL_OUT:
		return is_queue_securely_delegated(Q_SERIAL_OUT);

	case P_STORAGE:
		return (is_queue_securely_delegated(Q_STORAGE_DATA_IN) ||
			is_queue_securely_delegated(Q_STORAGE_DATA_OUT) ||
			is_queue_securely_delegated(Q_STORAGE_CMD_IN) ||
			is_queue_securely_delegated(Q_STORAGE_CMD_OUT));

	case P_NETWORK:
		return (is_queue_securely_delegated(Q_NETWORK_DATA_IN) ||
			is_queue_securely_delegated(Q_NETWORK_DATA_OUT) ||
			is_queue_securely_delegated(Q_NETWORK_CMD_IN) ||
			is_queue_securely_delegated(Q_NETWORK_CMD_OUT));

	case P_BLUETOOTH:
		return (is_queue_securely_delegated(Q_BLUETOOTH_DATA_IN) ||
			is_queue_securely_delegated(Q_BLUETOOTH_DATA_OUT) ||
			is_queue_securely_delegated(Q_BLUETOOTH_CMD_IN) ||
			is_queue_securely_delegated(Q_BLUETOOTH_CMD_OUT));

	case P_RUNTIME1:
		return (is_queue_securely_delegated(Q_RUNTIME1) ||
			does_proc_have_secure_io(P_RUNTIME1) ||
			/* secure IPC */
			(queues[Q_RUNTIME2].OWNER == P_RUNTIME1));

	case P_RUNTIME2:
		return (is_queue_securely_delegated(Q_RUNTIME2) ||
			does_proc_have_secure_io(P_RUNTIME2) ||
			/* secure IPC */
			(queues[Q_RUNTIME1].OWNER == P_RUNTIME2));

	default:
		printf("Error: %s: invalid processor ID (%d)\n", __func__, proc_id);
		return 0;
	}
}

static void initialize_queues(void)
{
	memset(queues, 0x0, sizeof(struct queue) * (NUM_QUEUES + 1)); 

	/* OS queue for runtime1 */
	queues[Q_OS1].queue_id = Q_OS1;
	queues[Q_OS1].queue_type = QUEUE_TYPE_SIMPLE;
	queues[Q_OS1].fixed_proc = P_OS;
	queues[Q_OS1].OWNER = P_RUNTIME1;
	queues[Q_OS1].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_OS1].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_OS1].messages = 
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* OS queue for runtime2 */
	queues[Q_OS2].queue_id = Q_OS2;
	queues[Q_OS2].queue_type = QUEUE_TYPE_SIMPLE;
	queues[Q_OS2].fixed_proc = P_OS;
	queues[Q_OS2].OWNER = P_RUNTIME2;
	queues[Q_OS2].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_OS2].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_OS2].messages = 
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* keyboard queue */
	queues[Q_KEYBOARD].queue_id = Q_KEYBOARD;
	queues[Q_KEYBOARD].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_KEYBOARD].fixed_proc = P_KEYBOARD;
	queues[Q_KEYBOARD].OWNER = P_OS;
	queues[Q_KEYBOARD].connections[P_OS] = 1;
	queues[Q_KEYBOARD].connections[P_RUNTIME1] = 1;
	queues[Q_KEYBOARD].connections[P_RUNTIME2] = 1;
	queues[Q_KEYBOARD].connections[P_UNTRUSTED] = 1;
	queues[Q_KEYBOARD].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_KEYBOARD].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_KEYBOARD].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_KEYBOARD].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_KEYBOARD].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* serial output queue */
	queues[Q_SERIAL_OUT].queue_id = Q_SERIAL_OUT;
	queues[Q_SERIAL_OUT].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_SERIAL_OUT].fixed_proc = P_SERIAL_OUT;
	queues[Q_SERIAL_OUT].OWNER = P_OS;
	queues[Q_SERIAL_OUT].connections[P_OS] = 1;
	queues[Q_SERIAL_OUT].connections[P_RUNTIME1] = 1;
	queues[Q_SERIAL_OUT].connections[P_RUNTIME2] = 1;
	queues[Q_SERIAL_OUT].connections[P_UNTRUSTED] = 1;
	queues[Q_SERIAL_OUT].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_SERIAL_OUT].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_SERIAL_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_SERIAL_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_SERIAL_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* storage queues */
	queues[Q_STORAGE_DATA_IN].queue_id = Q_STORAGE_DATA_IN;
	queues[Q_STORAGE_DATA_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_STORAGE_DATA_IN].fixed_proc = P_STORAGE;
	queues[Q_STORAGE_DATA_IN].OWNER = P_OS;
	queues[Q_STORAGE_DATA_IN].connections[P_OS] = 1;
	queues[Q_STORAGE_DATA_IN].connections[P_RUNTIME1] = 1;
	queues[Q_STORAGE_DATA_IN].connections[P_RUNTIME2] = 1;
	queues[Q_STORAGE_DATA_IN].connections[P_UNTRUSTED] = 1;
	queues[Q_STORAGE_DATA_IN].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_STORAGE_DATA_IN].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_STORAGE_DATA_IN].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_STORAGE_DATA_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_STORAGE_DATA_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE,
					  MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_STORAGE_DATA_OUT].queue_id = Q_STORAGE_DATA_OUT;
	queues[Q_STORAGE_DATA_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_STORAGE_DATA_OUT].fixed_proc = P_STORAGE;
	queues[Q_STORAGE_DATA_OUT].OWNER = P_OS;
	/* This queue is connected to all other procs.
	 * This is needed in the booting process, where each
	 * proc needs to read its image from the storage service.
	 */
	queues[Q_STORAGE_DATA_OUT].connections[P_OS] = 1;
	queues[Q_STORAGE_DATA_OUT].connections[P_RUNTIME1] = 1;
	queues[Q_STORAGE_DATA_OUT].connections[P_RUNTIME2] = 1;
	queues[Q_STORAGE_DATA_OUT].connections[P_UNTRUSTED] = 1;
	queues[Q_STORAGE_DATA_OUT].connections[P_KEYBOARD] = 1;
	queues[Q_STORAGE_DATA_OUT].connections[P_SERIAL_OUT] = 1;
	queues[Q_STORAGE_DATA_OUT].connections[P_NETWORK] = 1;
	queues[Q_STORAGE_DATA_OUT].connections[P_BLUETOOTH] = 1;
	queues[Q_STORAGE_DATA_OUT].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_STORAGE_DATA_OUT].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_STORAGE_DATA_OUT].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_STORAGE_DATA_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_STORAGE_DATA_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE,
					  MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_STORAGE_CMD_IN].queue_id = Q_STORAGE_CMD_IN;
	queues[Q_STORAGE_CMD_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_STORAGE_CMD_IN].fixed_proc = P_STORAGE;
	queues[Q_STORAGE_CMD_IN].OWNER = P_OS;
	queues[Q_STORAGE_CMD_IN].connections[P_OS] = 1;
	queues[Q_STORAGE_CMD_IN].connections[P_RUNTIME1] = 1;
	queues[Q_STORAGE_CMD_IN].connections[P_RUNTIME2] = 1;
	queues[Q_STORAGE_CMD_IN].connections[P_UNTRUSTED] = 1;
	queues[Q_STORAGE_CMD_IN].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_STORAGE_CMD_IN].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_STORAGE_CMD_IN].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_STORAGE_CMD_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_STORAGE_CMD_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	queues[Q_STORAGE_CMD_OUT].queue_id = Q_STORAGE_CMD_OUT;
	queues[Q_STORAGE_CMD_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_STORAGE_CMD_OUT].fixed_proc = P_STORAGE;
	queues[Q_STORAGE_CMD_OUT].OWNER = P_OS;
	queues[Q_STORAGE_CMD_OUT].connections[P_OS] = 1;
	queues[Q_STORAGE_CMD_OUT].connections[P_RUNTIME1] = 1;
	queues[Q_STORAGE_CMD_OUT].connections[P_RUNTIME2] = 1;
	queues[Q_STORAGE_CMD_OUT].connections[P_UNTRUSTED] = 1;
	queues[Q_STORAGE_CMD_OUT].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_STORAGE_CMD_OUT].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_STORAGE_CMD_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_STORAGE_CMD_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_STORAGE_CMD_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* network queues */
	queues[Q_NETWORK_DATA_IN].queue_id = Q_NETWORK_DATA_IN;
	queues[Q_NETWORK_DATA_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_NETWORK_DATA_IN].fixed_proc = P_NETWORK;
	queues[Q_NETWORK_DATA_IN].OWNER = P_OS;
	queues[Q_NETWORK_DATA_IN].connections[P_OS] = 1;
	queues[Q_NETWORK_DATA_IN].connections[P_RUNTIME1] = 1;
	queues[Q_NETWORK_DATA_IN].connections[P_RUNTIME2] = 1;
	queues[Q_NETWORK_DATA_IN].connections[P_UNTRUSTED] = 1;
	queues[Q_NETWORK_DATA_IN].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_NETWORK_DATA_IN].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_NETWORK_DATA_IN].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_NETWORK_DATA_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_NETWORK_DATA_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE,
					  MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_NETWORK_DATA_OUT].queue_id = Q_NETWORK_DATA_OUT;
	queues[Q_NETWORK_DATA_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_NETWORK_DATA_OUT].fixed_proc = P_NETWORK;
	queues[Q_NETWORK_DATA_OUT].OWNER = P_OS;
	queues[Q_NETWORK_DATA_OUT].connections[P_OS] = 1;
	queues[Q_NETWORK_DATA_OUT].connections[P_RUNTIME1] = 1;
	queues[Q_NETWORK_DATA_OUT].connections[P_RUNTIME2] = 1;
	queues[Q_NETWORK_DATA_OUT].connections[P_UNTRUSTED] = 1;
	queues[Q_NETWORK_DATA_OUT].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_NETWORK_DATA_OUT].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_NETWORK_DATA_OUT].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_NETWORK_DATA_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_NETWORK_DATA_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE,
					  MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_NETWORK_CMD_IN].queue_id = Q_NETWORK_CMD_IN;
	queues[Q_NETWORK_CMD_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_NETWORK_CMD_IN].fixed_proc = P_NETWORK;
	queues[Q_NETWORK_CMD_IN].OWNER = P_OS;
	/* FIXME: use a SIMPLE queue if only one connection */
	queues[Q_NETWORK_CMD_IN].connections[P_OS] = 1;
	queues[Q_NETWORK_CMD_IN].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_NETWORK_CMD_IN].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_NETWORK_CMD_IN].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_NETWORK_CMD_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_NETWORK_CMD_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	queues[Q_NETWORK_CMD_OUT].queue_id = Q_NETWORK_CMD_OUT;
	queues[Q_NETWORK_CMD_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_NETWORK_CMD_OUT].fixed_proc = P_NETWORK;
	queues[Q_NETWORK_CMD_OUT].OWNER = P_OS;
	/* FIXME: use a SIMPLE queue if only one connection */
	queues[Q_NETWORK_CMD_OUT].connections[P_OS] = 1;
	queues[Q_NETWORK_CMD_OUT].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_NETWORK_CMD_OUT].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_NETWORK_CMD_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_NETWORK_CMD_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_NETWORK_CMD_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* bluetooth queues */
	queues[Q_BLUETOOTH_DATA_IN].queue_id = Q_BLUETOOTH_DATA_IN;
	queues[Q_BLUETOOTH_DATA_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_BLUETOOTH_DATA_IN].fixed_proc = P_BLUETOOTH;
	queues[Q_BLUETOOTH_DATA_IN].OWNER = P_OS;
	queues[Q_BLUETOOTH_DATA_IN].connections[P_OS] = 1;
	queues[Q_BLUETOOTH_DATA_IN].connections[P_RUNTIME1] = 1;
	queues[Q_BLUETOOTH_DATA_IN].connections[P_RUNTIME2] = 1;
	queues[Q_BLUETOOTH_DATA_IN].connections[P_UNTRUSTED] = 1;
	queues[Q_BLUETOOTH_DATA_IN].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_BLUETOOTH_DATA_IN].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_BLUETOOTH_DATA_IN].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_BLUETOOTH_DATA_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_BLUETOOTH_DATA_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE,
					  MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_BLUETOOTH_DATA_OUT].queue_id = Q_BLUETOOTH_DATA_OUT;
	queues[Q_BLUETOOTH_DATA_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_BLUETOOTH_DATA_OUT].fixed_proc = P_BLUETOOTH;
	queues[Q_BLUETOOTH_DATA_OUT].OWNER = P_OS;
	queues[Q_BLUETOOTH_DATA_OUT].connections[P_OS] = 1;
	queues[Q_BLUETOOTH_DATA_OUT].connections[P_RUNTIME1] = 1;
	queues[Q_BLUETOOTH_DATA_OUT].connections[P_RUNTIME2] = 1;
	queues[Q_BLUETOOTH_DATA_OUT].connections[P_UNTRUSTED] = 1;
	queues[Q_BLUETOOTH_DATA_OUT].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_BLUETOOTH_DATA_OUT].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_BLUETOOTH_DATA_OUT].queue_size = MAILBOX_QUEUE_SIZE_LARGE;
	queues[Q_BLUETOOTH_DATA_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE_LARGE;
	queues[Q_BLUETOOTH_DATA_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE_LARGE,
					  MAILBOX_QUEUE_MSG_SIZE_LARGE);

	queues[Q_BLUETOOTH_CMD_IN].queue_id = Q_BLUETOOTH_CMD_IN;
	queues[Q_BLUETOOTH_CMD_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_BLUETOOTH_CMD_IN].fixed_proc = P_BLUETOOTH;
	queues[Q_BLUETOOTH_CMD_IN].OWNER = P_OS;
	queues[Q_BLUETOOTH_CMD_IN].connections[P_OS] = 1;
	queues[Q_BLUETOOTH_CMD_IN].connections[P_RUNTIME1] = 1;
	queues[Q_BLUETOOTH_CMD_IN].connections[P_RUNTIME2] = 1;
	queues[Q_BLUETOOTH_CMD_IN].connections[P_UNTRUSTED] = 1;
	queues[Q_BLUETOOTH_CMD_IN].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_BLUETOOTH_CMD_IN].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_BLUETOOTH_CMD_IN].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_BLUETOOTH_CMD_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_BLUETOOTH_CMD_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	queues[Q_BLUETOOTH_CMD_OUT].queue_id = Q_BLUETOOTH_CMD_OUT;
	queues[Q_BLUETOOTH_CMD_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_BLUETOOTH_CMD_OUT].fixed_proc = P_BLUETOOTH;
	queues[Q_BLUETOOTH_CMD_OUT].OWNER = P_OS;
	queues[Q_BLUETOOTH_CMD_OUT].connections[P_OS] = 1;
	queues[Q_BLUETOOTH_CMD_OUT].connections[P_RUNTIME1] = 1;
	queues[Q_BLUETOOTH_CMD_OUT].connections[P_RUNTIME2] = 1;
	queues[Q_BLUETOOTH_CMD_OUT].connections[P_UNTRUSTED] = 1;
	queues[Q_BLUETOOTH_CMD_OUT].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_BLUETOOTH_CMD_OUT].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_BLUETOOTH_CMD_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_BLUETOOTH_CMD_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_BLUETOOTH_CMD_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* runtime1 queue */
	queues[Q_RUNTIME1].queue_id = Q_RUNTIME1;
	queues[Q_RUNTIME1].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_RUNTIME1].fixed_proc = P_RUNTIME1;
	queues[Q_RUNTIME1].OWNER = P_OS;
	queues[Q_RUNTIME1].connections[P_OS] = 1;
	queues[Q_RUNTIME1].connections[P_RUNTIME2] = 1;
	queues[Q_RUNTIME1].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_RUNTIME1].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_RUNTIME1].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_RUNTIME1].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_RUNTIME1].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* runtime2 queue */
	queues[Q_RUNTIME2].queue_id = Q_RUNTIME2;
	queues[Q_RUNTIME2].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_RUNTIME2].fixed_proc = P_RUNTIME2;
	queues[Q_RUNTIME2].OWNER = P_OS;
	queues[Q_RUNTIME2].connections[P_OS] = 1;
	queues[Q_RUNTIME2].connections[P_RUNTIME1] = 1;
	queues[Q_RUNTIME2].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_RUNTIME2].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_RUNTIME2].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_RUNTIME2].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_RUNTIME2].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* OS queue for untrusted */
	queues[Q_OSU].queue_id = Q_OSU;
	queues[Q_OSU].queue_type = QUEUE_TYPE_SIMPLE;
	queues[Q_OSU].fixed_proc = P_OS;
	queues[Q_OSU].OWNER = P_UNTRUSTED;
	queues[Q_OSU].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_OSU].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_OSU].messages = 
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* untrusted queue */
	queues[Q_UNTRUSTED].queue_id = Q_UNTRUSTED;
	queues[Q_UNTRUSTED].queue_type = QUEUE_TYPE_SIMPLE;
	queues[Q_UNTRUSTED].fixed_proc = P_UNTRUSTED;
	queues[Q_UNTRUSTED].OWNER = P_OS;
	queues[Q_UNTRUSTED].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_UNTRUSTED].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_UNTRUSTED].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	/* TPM queue */
	queues[Q_TPM_IN].queue_id = Q_TPM_IN;
	queues[Q_TPM_IN].queue_type = QUEUE_TYPE_FIXED_READER;
	queues[Q_TPM_IN].fixed_proc = P_TPM;
	queues[Q_TPM_IN].OWNER = P_OS;
	/* This queue is connected to most other procs.
	 * This is needed in the booting process, where
	 * each proc needs to send its measurement to TPM.
	 */
	queues[Q_TPM_IN].connections[P_OS] = 1;
	queues[Q_TPM_IN].connections[P_RUNTIME1] = 1;
	queues[Q_TPM_IN].connections[P_RUNTIME2] = 1;
	queues[Q_TPM_IN].connections[P_KEYBOARD] = 1;
	queues[Q_TPM_IN].connections[P_SERIAL_OUT] = 1;
	queues[Q_TPM_IN].connections[P_STORAGE] = 1;
	queues[Q_TPM_IN].connections[P_NETWORK] = 1;
	queues[Q_TPM_IN].connections[P_BLUETOOTH] = 1;
	queues[Q_TPM_IN].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_TPM_IN].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_TPM_IN].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_TPM_IN].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_TPM_IN].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);

	queues[Q_TPM_OUT].queue_id = Q_TPM_OUT;
	queues[Q_TPM_OUT].queue_type = QUEUE_TYPE_FIXED_WRITER;
	queues[Q_TPM_OUT].fixed_proc = P_TPM;
	queues[Q_TPM_OUT].OWNER = P_OS;
	queues[Q_TPM_OUT].connections[P_OS] = 1;
	queues[Q_TPM_OUT].connections[P_RUNTIME1] = 1;
	queues[Q_TPM_OUT].connections[P_RUNTIME2] = 1;
	queues[Q_TPM_OUT].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[Q_TPM_OUT].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;
	queues[Q_TPM_OUT].queue_size = MAILBOX_QUEUE_SIZE;
	queues[Q_TPM_OUT].msg_size = MAILBOX_QUEUE_MSG_SIZE;
	queues[Q_TPM_OUT].messages =
		allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
					  MAILBOX_QUEUE_MSG_SIZE);
}

static bool proc_has_queue_read_access(uint8_t queue_id, uint8_t proc_id)
{
	if (queues[queue_id].queue_type == QUEUE_TYPE_FIXED_READER &&
	    queues[queue_id].fixed_proc == proc_id)
		return true;
	else if (queues[queue_id].queue_type == QUEUE_TYPE_FIXED_WRITER &&
	    queues[queue_id].OWNER == proc_id)
		return true;
	else if (queues[queue_id].queue_type == QUEUE_TYPE_SIMPLE &&
	    queues[queue_id].fixed_proc == proc_id)
		return true;

	return false;
}

static bool proc_has_queue_write_access(uint8_t queue_id, uint8_t proc_id)
{
	if (queues[queue_id].queue_type == QUEUE_TYPE_FIXED_READER &&
	    queues[queue_id].OWNER == proc_id)
		return true;
	else if (queues[queue_id].queue_type == QUEUE_TYPE_FIXED_WRITER &&
	    queues[queue_id].fixed_proc == proc_id)
		return true;
	else if (queues[queue_id].queue_type == QUEUE_TYPE_SIMPLE &&
	    queues[queue_id].OWNER == proc_id)
		return true;

	return false;
}

static void handle_read_queue(uint8_t queue_id, uint8_t reader_id)
{
	//if (queue_id != Q_STORAGE_DATA_OUT) printf("%s [1]: queue_id = %d, reader_id = %d\n", __func__, queue_id, reader_id);
	if (proc_has_queue_read_access(queue_id, reader_id)) {
		struct queue *queue = &queues[queue_id];
		read_queue(queue, processors[reader_id].in_handle);
		/* send interrupt to writer */
		if (queues[queue_id].queue_type == QUEUE_TYPE_FIXED_WRITER)
			processors[queue->fixed_proc].send_interrupt(queue_id);
		else /* QUEUE_TYPE_FIXED_READER or QUEUE_TYPE_SIMPLE */
			processors[queue->OWNER].send_interrupt(queue_id);
		/* We don't decrement if the original owner is using the queue. */
		if (queue->LIMIT > 0 && queue->LIMIT != MAILBOX_NO_LIMIT_VAL) {
			queue->LIMIT--;
			if (queue->LIMIT == 0)
				change_back_queue_access(queue);
		}
	} else {
		printf("Error: processor %d can't read from queue %d\n", reader_id, queue_id);
	}
}

static void handle_write_queue(uint8_t queue_id, uint8_t writer_id)
{
	//if (queue_id != Q_STORAGE_DATA_OUT) printf("%s [1]: queue_id = %d, writer_id = %d\n", __func__, queue_id, writer_id);
	if (proc_has_queue_write_access(queue_id, writer_id)) {
		write_queue(&queues[queue_id], processors[writer_id].out_handle);
		/* send interrupt to reader */
		if (queues[queue_id].queue_type == QUEUE_TYPE_FIXED_WRITER)
			processors[queues[queue_id].OWNER].send_interrupt(queue_id);
		else /* QUEUE_TYPE_FIXED_READER or QUEUE_TYPE_SIMPLE */
			processors[queues[queue_id].fixed_proc].send_interrupt(queue_id);
	} else {
		printf("Error: processor %d can't write to queue %d\n", writer_id, queue_id);
	}
}

static void reset_queue(uint8_t queue_id)
{
	for (int i = 0; i < queues[queue_id].queue_size; i++)
		memset(queues[queue_id].messages[i], 0x0, queues[queue_id].msg_size);

	queues[queue_id].head = 0;
	queues[queue_id].tail = 0;
	queues[queue_id].counter = 0;
}

static int reset_queue_full(uint8_t queue_id)
{
	if (queues[queue_id].queue_type == QUEUE_TYPE_SIMPLE) {
		reset_queue(queue_id);	
		return 0;
	}

	if (is_queue_securely_delegated(queue_id))
	    return -1;

	reset_queue(queue_id);	
	queues[queue_id].LIMIT = 0;
	queues[queue_id].TIMEOUT = 0;
	if (queues[queue_id].prev_owner)
		queues[queue_id].OWNER = queues[queue_id].prev_owner;
	queues[queue_id].prev_owner = 0;
	queues[queue_id].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[queue_id].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;

	return 0;
}

/* FIXME: we also have a copy of these definitions in syscall.h */
/* access modes */
#define ACCESS_UNLIMITED_REVOCABLE	0
#define ACCESS_LIMITED_IRREVOCABLE	1

static void delegate_queue_access(uint8_t queue_id, uint8_t requester,
				  mailbox_state_reg_t new_state)
{
	if (new_state.limit == 0) {
		printf("Error: %s: limit can't be 0\n", __func__);
		return;
	}

	if (new_state.timeout == 0) {
		printf("Error: %s: timeout can't be 0\n", __func__);
		return;
	}

	if (queues[queue_id].queue_type == QUEUE_TYPE_SIMPLE) {
		printf("Error: %s: SIMPLE queues don't support delegation (%d).\n",
		       __func__, queue_id);
		return;
	}

	if (requester != queues[queue_id].OWNER) { 
		printf("Error: %s: Only the owner can perform delegation (%d, %d, %d).\n",
		       __func__, queue_id, requester, queues[queue_id].OWNER);
		return;
	}

	if (requester == new_state.owner)
		/* no op */
		return;

	if (queues[queue_id].connections[new_state.owner] == 0) {
		printf("Error: %s: proc %d is not connected to queue %d.\n",
		       __func__, new_state.owner, queue_id);
		return;
	}

	if (queues[queue_id].prev_owner) {
		printf("Error: %s: nested delegation not supported (%d).\n",
		       __func__, queue_id);
		return;
	}

	if (queues[queue_id].LIMIT != MAILBOX_NO_LIMIT_VAL) {
		printf("Error: %s: unexpected limit val (%d, %d).\n",
		       __func__, queue_id, queues[queue_id].LIMIT);
		return;
	}

	if (queues[queue_id].TIMEOUT != MAILBOX_NO_TIMEOUT_VAL) {
		printf("Error: %s: unexpected timeout val (%d, %d).\n",
		       __func__, queue_id, queues[queue_id].TIMEOUT);
		return;
	}

	reset_queue(queue_id);	

	queues[queue_id].prev_owner = queues[queue_id].OWNER;
	queues[queue_id].state_reg = new_state;

	/* FIXME: This is a hack. We need to properly distinguish the interrupts. */
	processors[new_state.owner].send_interrupt(queue_id + NUM_QUEUES);
}

static void yield_queue_access(uint8_t queue_id, uint8_t requester)
{
	if (queues[queue_id].queue_type == QUEUE_TYPE_SIMPLE) {
		printf("Error: %s: SIMPLE queues don't support delegation (%d).\n",
		       __func__, queue_id);
		return;
	}

	if (requester != queues[queue_id].OWNER) {
		/* We label this a warning since it (currently) happens in normal execution. */
		printf("Warning: %s: Only the owner can yield (%d, %d, %d).\n",
		       __func__, queue_id, requester, queues[queue_id].OWNER);
		return;
	}

	if (queues[queue_id].prev_owner == 0) {
		printf("Error: %s: the queue hasn't been delegated (%d).\n",
		       __func__, queue_id);
		return;
	}

	if (queues[queue_id].LIMIT == MAILBOX_NO_LIMIT_VAL) {
		printf("Error: %s: unexpected limit val (%d, %d).\n",
		       __func__, queue_id, queues[queue_id].LIMIT);
		return;
	}

	if (queues[queue_id].TIMEOUT == MAILBOX_NO_TIMEOUT_VAL) {
		printf("Error: %s: unexpected timeout val (%d, %d).\n",
		       __func__, queue_id, queues[queue_id].TIMEOUT);
		return;
	}

	if (queues[queue_id].LIMIT == 0)
		/* No op: queue access automatically goes back to prev_owner */
		return;

	if (queues[queue_id].TIMEOUT == 0)
		/* No op: queue access automatically goes back to prev_owner */
		return;

	reset_queue(queue_id);	

	queues[queue_id].OWNER = queues[queue_id].prev_owner;
	queues[queue_id].prev_owner = 0;
	queues[queue_id].LIMIT = MAILBOX_NO_LIMIT_VAL;
	queues[queue_id].TIMEOUT = MAILBOX_NO_TIMEOUT_VAL;

	/* FIXME: This is a hack. We need to properly distinguish the interrupts. */
	processors[queues[queue_id].OWNER].send_interrupt(queue_id + NUM_QUEUES);
}

static mailbox_state_reg_t attest_queue_access(uint8_t queue_id,
					       uint8_t requester)
{
	mailbox_state_reg_t MAILBOX_STATE_REG_INVALID =
		{.owner = 0x00, .limit = 0x000, .timeout = 0x000};

	if (queues[queue_id].queue_type == QUEUE_TYPE_SIMPLE) {
		printf("Error: %s: SIMPLE queues don't support attestation "
		       "(%d).\n", __func__, queue_id);
		return MAILBOX_STATE_REG_INVALID;
	}

	if (requester != queues[queue_id].OWNER &&
	    requester != queues[queue_id].fixed_proc &&
	    /* TPM can read the state register of any of the queues. */
	    requester != P_TPM) { 
		printf("Error: %s: Only fixed_proc, owner, and TPM proc can "
		       "check the mailbox state (%d, %d, %d).\n", __func__,
		       queue_id, requester, queues[queue_id].OWNER);
		return MAILBOX_STATE_REG_INVALID;
	}

	return queues[queue_id].state_reg;
}

/*
 * If requester == 0, it means the request is from PMU
 */
static void disable_queue_delegation(uint8_t queue_id, uint8_t requester)
{
	if (queues[queue_id].queue_type == QUEUE_TYPE_SIMPLE) {
		printf("Error: %s: SIMPLE queues don't support delegation (%d).\n",
		       __func__, queue_id);
		return;
	}

	if (requester != 0 &&
	    requester != queues[queue_id].fixed_proc) { 
		printf("Error: %s: Only fixed_proc and PMU can disable delegation (%d, %d).\n",
		       __func__, queue_id, requester);
		return;
	}

	queues[queue_id].delegation_disabled = 1;
}

/*
 * If requester == 0, it means the request is from PMU
 */
static void enable_queue_delegation(uint8_t queue_id, uint8_t requester)
{
	if (queues[queue_id].queue_type == QUEUE_TYPE_SIMPLE) {
		printf("Error: %s: SIMPLE queues don't support delegation (%d).\n",
		       __func__, queue_id);
		return;
	}

	if (requester != 0 &&
	    requester != queues[queue_id].fixed_proc) { 
		printf("Error: %s: Only fixed_proc and PMU can enable delegation (%d, %d).\n",
		       __func__, queue_id, requester);
		return;
	}

	queues[queue_id].delegation_disabled = 0;
}

static void handle_proc_request(uint8_t requester)
{
	uint8_t opcode[2], queue_id;

	memset(opcode, 0x0, 2);

	read(processors[requester].out_handle, opcode, 2);
	queue_id = opcode[1];

	switch (opcode[0]) {
	case MAILBOX_OPCODE_READ_QUEUE:
		handle_read_queue(queue_id, requester);
		break;

	case MAILBOX_OPCODE_WRITE_QUEUE:
		handle_write_queue(queue_id, requester);
		break;

	case MAILBOX_OPCODE_DELEGATE_QUEUE_ACCESS:
		if (delegation_allowed && !queues[queue_id].delegation_disabled) {
			mailbox_state_reg_t state;
			memset(&state, 0x0, sizeof(mailbox_state_reg_t));
			read(processors[requester].out_handle, &state, sizeof(mailbox_state_reg_t));
			delegate_queue_access(queue_id, requester, state);
		} else {
			printf("Error: %s: delegation disabled for queue %d.\n", __func__, queue_id);
		}
		break;

	case MAILBOX_OPCODE_YIELD_QUEUE_ACCESS:
		if (delegation_allowed && !queues[queue_id].delegation_disabled) {
			yield_queue_access(queue_id, requester);				
		} else {
			printf("Error: %s: delegation (and hence yielding) disabled for queue %d.\n",
			       __func__, queue_id);
		}
		break;

	case MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS: {
		mailbox_state_reg_t state = attest_queue_access(queue_id, requester);				
		write(processors[requester].in_handle, &state, sizeof(mailbox_state_reg_t));
		break;
		}

	case MAILBOX_OPCODE_DISABLE_QUEUE_DELEGATION:
		disable_queue_delegation(queue_id, requester);
		break;

	case MAILBOX_OPCODE_ENABLE_QUEUE_DELEGATION:
		enable_queue_delegation(queue_id, requester);
		break;

	default:
		printf("Error: %s: invalid opcode from %d\n", __func__, requester);
		break;
	}
}

static void decrement_timeouts(void)
{
	for (int i = 1; i <= NUM_QUEUES; i++) {
		if (queues[i].queue_type == QUEUE_TYPE_SIMPLE ||
		    /* FIXME: when can this happen? If it does, doesn't it
		     * imply a bug? */
		    queues[i].TIMEOUT == 0 ||
		    /* True if the original owner is using the mailbox. */
		    queues[i].TIMEOUT == MAILBOX_NO_TIMEOUT_VAL)
			continue;

		queues[i].TIMEOUT--;
		printf("%s [1]: queue_id = %d, timeout = %d\n", __func__,
		       i, queues[i].TIMEOUT);
		if (queues[i].TIMEOUT == 0) {
			printf("%s: queue %d timed out\n", __func__, i);
			change_back_queue_access(&queues[i]);
		}
	}
}

static void *run_timer(void *data)
{
	while (1) {
		sleep(1);
		processors[P_OS].send_interrupt(0);
		processors[P_RUNTIME1].send_interrupt(0);
		processors[P_RUNTIME2].send_interrupt(0);
		decrement_timeouts();
	}
}

int main(int argc, char **argv)
{
	pthread_t timer_thread;
	int fd_pmu_to_mailbox, fd_pmu_from_mailbox;

	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: mailbox init\n", __func__);

	initialize_processors();
	/* FIXME: release memory allocated for queues on exit */
	initialize_queues();

	/* channel to PMU */
	mkfifo(FIFO_PMU_TO_MAILBOX, 0666);
	mkfifo(FIFO_PMU_FROM_MAILBOX, 0666);
	fd_pmu_to_mailbox = open(FIFO_PMU_TO_MAILBOX, O_RDONLY);
	fd_pmu_from_mailbox = open(FIFO_PMU_FROM_MAILBOX, O_WRONLY);

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
	if (processors[P_BLUETOOTH].out_handle > nfds)
		nfds = processors[P_BLUETOOTH].out_handle;
	if (processors[P_RUNTIME1].out_handle > nfds)
		nfds = processors[P_RUNTIME1].out_handle;
	if (processors[P_RUNTIME2].out_handle > nfds)
		nfds = processors[P_RUNTIME2].out_handle;
	if (processors[P_UNTRUSTED].out_handle > nfds)
		nfds = processors[P_UNTRUSTED].out_handle;
	if (processors[P_TPM].out_handle > nfds)
		nfds = processors[P_TPM].out_handle;
	if (fd_pmu_to_mailbox > nfds)
		nfds = fd_pmu_to_mailbox;

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
		FD_SET(processors[P_BLUETOOTH].out_handle, &listen_fds);
		FD_SET(processors[P_RUNTIME1].out_handle, &listen_fds);
		FD_SET(processors[P_RUNTIME2].out_handle, &listen_fds);
		FD_SET(processors[P_UNTRUSTED].out_handle, &listen_fds);
		FD_SET(processors[P_TPM].out_handle, &listen_fds);
		FD_SET(fd_pmu_to_mailbox, &listen_fds);

		if (select(nfds + 1, &listen_fds, NULL, NULL, NULL) < 0) {
			printf("Error: select\n");
			break;
		}

		if (FD_ISSET(processors[P_OS].out_handle, &listen_fds))
			handle_proc_request(P_OS);

		if (FD_ISSET(processors[P_KEYBOARD].out_handle, &listen_fds))
			handle_proc_request(P_KEYBOARD);

		if (FD_ISSET(processors[P_SERIAL_OUT].out_handle, &listen_fds))
			handle_proc_request(P_SERIAL_OUT);
			
		if (FD_ISSET(processors[P_STORAGE].out_handle, &listen_fds))
			handle_proc_request(P_STORAGE);
			
		if (FD_ISSET(processors[P_NETWORK].out_handle, &listen_fds))
			handle_proc_request(P_NETWORK);

		if (FD_ISSET(processors[P_BLUETOOTH].out_handle, &listen_fds))
			handle_proc_request(P_BLUETOOTH);
					
		if (FD_ISSET(processors[P_RUNTIME1].out_handle, &listen_fds))
			handle_proc_request(P_RUNTIME1);

		if (FD_ISSET(processors[P_RUNTIME2].out_handle, &listen_fds))
			handle_proc_request(P_RUNTIME2);

		if (FD_ISSET(processors[P_UNTRUSTED].out_handle, &listen_fds))
			handle_proc_request(P_UNTRUSTED);
			
		if (FD_ISSET(processors[P_TPM].out_handle, &listen_fds))
			handle_proc_request(P_TPM);
			
		if (FD_ISSET(fd_pmu_to_mailbox, &listen_fds)) {
			uint8_t pmu_mailbox_buf[PMU_MAILBOX_BUF_SIZE];
			int len = read(fd_pmu_to_mailbox, pmu_mailbox_buf, PMU_MAILBOX_BUF_SIZE);
			if (len != PMU_MAILBOX_BUF_SIZE) {
				printf("Error: %s: invalid command size from the PMU (%d)\n",
				       __func__, len);
				continue;
			}

			if (pmu_mailbox_buf[0] == PMU_MAILBOX_CMD_PAUSE_DELEGATION) {
				uint32_t cmd_ret = 0;
				delegation_allowed = 0;
				write(fd_pmu_from_mailbox, &cmd_ret, 4);
			} else if (pmu_mailbox_buf[0] == PMU_MAILBOX_CMD_RESUME_DELEGATION) {
				uint32_t cmd_ret = 0;
				delegation_allowed = 1;
				write(fd_pmu_from_mailbox, &cmd_ret, 4);
			} else if (pmu_mailbox_buf[0] == PMU_MAILBOX_CMD_TERMINATE_CHECK) {
				uint32_t cmd_ret = (uint32_t) any_secure_delegations();
				write(fd_pmu_from_mailbox, &cmd_ret, 4);
			} else if (pmu_mailbox_buf[0] == PMU_MAILBOX_CMD_RESET_QUEUE) {
				uint32_t cmd_ret = (uint32_t) reset_queue_full(pmu_mailbox_buf[1]);
				write(fd_pmu_from_mailbox, &cmd_ret, 4);
			} else if (pmu_mailbox_buf[0] == PMU_MAILBOX_CMD_RESET_PROC_CHECK) {
				uint32_t cmd_ret =
					(uint32_t) does_proc_have_secure_delegatation(pmu_mailbox_buf[1]);
				write(fd_pmu_from_mailbox, &cmd_ret, 4);
			} else {
				printf("Error: %s: invalid command from the PMU (%d)\n",
				       __func__, pmu_mailbox_buf[0]);
			}
		}
	}	

	pthread_cancel(timer_thread);
	pthread_join(timer_thread, NULL);

	close(fd_pmu_from_mailbox);
	close(fd_pmu_to_mailbox);
	remove(FIFO_PMU_FROM_MAILBOX);
	remove(FIFO_PMU_TO_MAILBOX);
	
	close_processors();

	return 0;
}
