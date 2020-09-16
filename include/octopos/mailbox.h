#ifndef UNTRUSTED_DOMAIN
#include <arch/defines.h>
#endif

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
#define P_UNTRUSTED		9
#define P_TPM           10
#define NUM_PROCESSORS  10
#define ALL_PROCESSORS  11
#define INVALID_PROCESSOR   12

#define NUM_RUNTIME_PROCS	3 /* includes the untrusted domain */

/* queue IDs */
#define	Q_OS1			1
#define	Q_OS2			2
#define	Q_KEYBOARD		3
#define	Q_SERIAL_OUT		4
#define	Q_STORAGE_DATA_IN	5
#define	Q_STORAGE_DATA_OUT	6
#define	Q_STORAGE_CMD_IN	7
#define	Q_STORAGE_CMD_OUT	8
#define	Q_NETWORK_DATA_IN	9
#define	Q_NETWORK_DATA_OUT	10
#define	Q_NETWORK_CMD_IN	11
#define	Q_NETWORK_CMD_OUT	12
#define Q_SENSOR		13
#define	Q_RUNTIME1		14
#define	Q_RUNTIME2		15
#define	Q_OSU			16
#define	Q_UNTRUSTED		17
#define Q_TPM_DATA_IN   18
#define Q_TPM_DATA_OUT  19
#define NUM_QUEUES		19

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
#define FIFO_UNTRUSTED_OUT	"/tmp/octopos_mailbox_untrusted_out"
#define FIFO_UNTRUSTED_IN	"/tmp/octopos_mailbox_untrusted_in"
#define FIFO_UNTRUSTED_INTR	"/tmp/octopos_mailbox_untrusted_intr"
#define FIFO_TPM_OUT        "/tmp/octopos_mailbox_tpm_out"
#define FIFO_TPM_IN         "/tmp/octopos_mailbox_tpm_in"
#define FIFO_TPM_INTR       "/tmp/octopos_mailbox_tpm_intr"

#define READ_ACCESS		0
#define WRITE_ACCESS		1

/* FIXME: move somewhere else */
#ifdef UNTRUSTED_DOMAIN
void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id);
int mailbox_attest_queue_access(uint8_t queue_id, uint8_t access, uint8_t count);
void reset_queue_sync(uint8_t queue_id, int init_val);
#endif
