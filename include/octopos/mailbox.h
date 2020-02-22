#include <arch/defines.h>

/* mailbox opcodes */
#define	MAILBOX_OPCODE_READ_QUEUE		0
#define	MAILBOX_OPCODE_WRITE_QUEUE		1
#define	MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS	2
#define	MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS	3
#define	MAILBOX_OPCODE_RESET			4

/* processor IDs */
#define	P_OS			1
#define	P_KEYBOARD		2
#define	P_SERIAL_OUT		3
#define	P_STORAGE		4
#define	P_NETWORK		5
#define	P_SENSOR		6
#define	P_RUNTIME1		7
#define	P_RUNTIME2		8
#define NUM_PROCESSORS		8
#define ALL_PROCESSORS		9
#define INVALID_PROCESSOR	10

#ifdef ARCH_SEC_HW
#define NUM_RUNTIME_PROCS	1
#else
#define NUM_RUNTIME_PROCS	2
#endif

/* queue IDs */
#define	Q_OS1			1
#define	Q_OS2			2
#define	Q_KEYBOARD		3
#define	Q_SERIAL_OUT		4
#define	Q_STORAGE_DATA_IN	5
#define	Q_STORAGE_DATA_OUT	6
#define	Q_STORAGE_CMD_IN	7
#define	Q_STORAGE_CMD_OUT	8
#define	Q_STORAGE_IN_2		9
#define	Q_STORAGE_OUT_2		10
#define	Q_NETWORK_DATA_IN	11
#define	Q_NETWORK_DATA_OUT	12
#define	Q_NETWORK_CMD_IN	13
#define	Q_NETWORK_CMD_OUT	14
#define Q_SENSOR		15
#define	Q_RUNTIME1		16
#define	Q_RUNTIME2		17
#define NUM_QUEUES		17

#define MAILBOX_QUEUE_SIZE		4
#define MAILBOX_QUEUE_MSG_SIZE		64

#define MAILBOX_QUEUE_SIZE_LARGE	8
#define MAILBOX_QUEUE_MSG_SIZE_LARGE	512

#define FIFO_OS_OUT		"/tmp/octopos_mailbox_os_out"
#define FIFO_OS_IN		"/tmp/octopos_mailbox_os_in"
#define FIFO_OS_INTR		"/tmp/octopos_mailbox_os_intr"
#define FIFO_KEYBOARD_OUT	"/tmp/octopos_mailbox_keyboard_out"
#define FIFO_KEYBOARD_INTR	"/tmp/octopos_mailbox_keyboard_intr"
#define FIFO_SENSOR		"/tmp/octopos_mailbox_sensor"
#define FIFO_SENSOR_INTR	"/tmp/octopos_mailbox_sensor_intr"
#define FIFO_SERIAL_OUT_OUT	"/tmp/octopos_mailbox_serial_out_out"
#define FIFO_SERIAL_OUT_IN	"/tmp/octopos_mailbox_serial_out_in"
#define FIFO_SERIAL_OUT_INTR	"/tmp/octopos_mailbox_serial_out_intr"
#define FIFO_STORAGE_OUT	"/tmp/octopos_mailbox_storage_out"
#define FIFO_STORAGE_IN		"/tmp/octopos_mailbox_storage_in"
#define FIFO_STORAGE_INTR	"/tmp/octopos_mailbox_storage_intr"
#define FIFO_NETWORK_OUT	"/tmp/octopos_mailbox_network_out"
#define FIFO_NETWORK_IN		"/tmp/octopos_mailbox_network_in"
#define FIFO_NETWORK_INTR	"/tmp/octopos_mailbox_network_intr"
#define FIFO_RUNTIME1_OUT	"/tmp/octopos_mailbox_runtime1_out"
#define FIFO_RUNTIME1_IN	"/tmp/octopos_mailbox_runtime1_in"
#define FIFO_RUNTIME1_INTR	"/tmp/octopos_mailbox_runtime1_intr"
#define FIFO_RUNTIME2_OUT	"/tmp/octopos_mailbox_runtime2_out"
#define FIFO_RUNTIME2_IN	"/tmp/octopos_mailbox_runtime2_in"
#define FIFO_RUNTIME2_INTR	"/tmp/octopos_mailbox_runtime2_intr"

#define READ_ACCESS		0
#define WRITE_ACCESS		1
