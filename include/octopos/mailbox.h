#ifndef _OCTOPOS_MAILBOX_H_
#define _OCTOPOS_MAILBOX_H_

#ifndef UNTRUSTED_DOMAIN
#include <arch/defines.h>
#endif

/* mailbox opcodes */
#define	MAILBOX_OPCODE_READ_QUEUE		0
#define	MAILBOX_OPCODE_WRITE_QUEUE		1
#define	MAILBOX_OPCODE_DELEGATE_QUEUE_ACCESS	2
#define	MAILBOX_OPCODE_YIELD_QUEUE_ACCESS	3
#define	MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS	4
#define	MAILBOX_OPCODE_DISABLE_QUEUE_DELEGATION	5
#define	MAILBOX_OPCODE_ENABLE_QUEUE_DELEGATION	6

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
#define P_TPM			10
#define NUM_PROCESSORS		10
#define ALL_PROCESSORS		11
#define INVALID_PROCESSOR	12

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
#define Q_TPM_IN		18
#define Q_TPM_OUT		19
#define NUM_QUEUES		19

#define MAILBOX_QUEUE_SIZE		4
#define MAILBOX_QUEUE_MSG_SIZE		64

#ifdef ARCH_SEC_HW
#define MAILBOX_QUEUE_SIZE_LARGE	MAILBOX_QUEUE_SIZE
#define MAILBOX_QUEUE_MSG_SIZE_LARGE	MAILBOX_QUEUE_MSG_SIZE
#else
#define MAILBOX_QUEUE_SIZE_LARGE	8
#define MAILBOX_QUEUE_MSG_SIZE_LARGE	512
#endif

typedef struct {
	unsigned owner:8; /* Proc with current access to the non-fixed end of a queue. */
	unsigned limit:12;
	unsigned timeout:12;
} mailbox_state_reg_t;

/* FIXME: these are also defined in octopos/runtime.h */
typedef uint32_t limit_t;
typedef uint32_t timeout_t;

#define MAILBOX_NO_LIMIT_VAL	0xFFF
#define MAILBOX_NO_TIMEOUT_VAL	0xFFF
/* FIXME: these are also defined in octopos/runtime.h */
#define MAILBOX_MAX_LIMIT_VAL	0xFFE
#define MAILBOX_MAX_TIMEOUT_VAL	0xFFE

/* FIXME: move somewhere else */
#ifdef UNTRUSTED_DOMAIN
void mailbox_yield_to_previous_owner(uint8_t queue_id);
int mailbox_attest_queue_access(uint8_t queue_id, limit_t count);
void reset_queue_sync(uint8_t queue_id, int init_val);
#endif

#endif /* _OCTOPOS_MAILBOX_H_ */
