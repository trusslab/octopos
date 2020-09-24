#ifndef UNTRUSTED_DOMAIN
#include <arch/defines.h>
#endif

/* mailbox opcodes */
#define	MAILBOX_OPCODE_READ_QUEUE		0
#define	MAILBOX_OPCODE_WRITE_QUEUE		1
#define	MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS	2
#define	MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS	3
//#define	MAILBOX_OPCODE_RESET			4

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
#define NUM_PROCESSORS		9
#define ALL_PROCESSORS		10
#define INVALID_PROCESSOR	11

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
#define NUM_QUEUES		17

#define MAILBOX_QUEUE_SIZE		4
#define MAILBOX_QUEUE_MSG_SIZE		64

#ifdef ARCH_SEC_HW
#define MAILBOX_QUEUE_SIZE_LARGE	MAILBOX_QUEUE_SIZE
#define MAILBOX_QUEUE_MSG_SIZE_LARGE	MAILBOX_QUEUE_MSG_SIZE
#else
#define MAILBOX_QUEUE_SIZE_LARGE	8
#define MAILBOX_QUEUE_MSG_SIZE_LARGE	512
#endif

#define READ_ACCESS		0
#define WRITE_ACCESS		1

/* FIXME: move somewhere else */
#ifdef UNTRUSTED_DOMAIN
void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id);
int mailbox_attest_queue_access(uint8_t queue_id, uint8_t access, uint8_t count);
void reset_queue_sync(uint8_t queue_id, int init_val);
#endif
