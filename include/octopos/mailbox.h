enum mailbox_opcodes {
	MAILBOX_OPCODE_READ_QUEUE = 0,
	MAILBOX_OPCODE_WRITE_QUEUE = 1
};

enum processors {
	OS = 0,
	KEYBOARD = 1,
	SERIAL_OUT = 2,
	RUNTIME = 3
};

#define NUM_PROCESSORS		4
#define ALL_PROCESSORS		4
#define INVALID_PROCESSOR	5

#define MAILBOX_QUEUE_SIZE	4
#define MAILBOX_QUEUE_MSG_SIZE	64

#define FIFO_OS_OUT		"/tmp/octopos_mailbox_os_out"
#define FIFO_OS_IN		"/tmp/octopos_mailbox_os_in"
#define FIFO_OS_INTR		"/tmp/octopos_mailbox_os_intr"
#define FIFO_KEYBOARD		"/tmp/octopos_mailbox_keyboard"
#define FIFO_SERIAL_OUT_OUT	"/tmp/octopos_mailbox_serial_out_out"
#define FIFO_SERIAL_OUT_IN	"/tmp/octopos_mailbox_serial_out_in"
#define FIFO_SERIAL_OUT_INTR	"/tmp/octopos_mailbox_serial_out_intr"
#define FIFO_RUNTIME_OUT	"/tmp/octopos_mailbox_runtime_out"
#define FIFO_RUNTIME_IN		"/tmp/octopos_mailbox_runtime_in"
#define FIFO_RUNTIME_INTR	"/tmp/octopos_mailbox_runtime_intr"
