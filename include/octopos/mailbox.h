#ifndef _OCTOPOS_MAILBOX_H_
#define _OCTOPOS_MAILBOX_H_

#if !defined(UNTRUSTED_DOMAIN) && !defined(APPLICATION)
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
#define	P_BLUETOOTH		6
#define	P_RUNTIME1		7
#define	P_RUNTIME2		8
#define P_UNTRUSTED		9
#define NUM_PROCESSORS		9
#define ALL_PROCESSORS		10
/* FIXME: just used for using the TPM API in PMU. */
#define P_PMU			10
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
#define Q_BLUETOOTH_DATA_IN	13
#define Q_BLUETOOTH_DATA_OUT	14
#define Q_BLUETOOTH_CMD_IN	15
#define Q_BLUETOOTH_CMD_OUT	16
#define	Q_RUNTIME1		17
#define	Q_RUNTIME2		18
#define	Q_OSU			19
#define	Q_UNTRUSTED		20
#define NUM_QUEUES		20

#define MAILBOX_QUEUE_SIZE		4
#define MAILBOX_QUEUE_MSG_SIZE		64

#ifdef ARCH_SEC_HW
#define MAILBOX_QUEUE_SIZE_LARGE	4
#else
#define MAILBOX_QUEUE_SIZE_LARGE	8
#endif
#define MAILBOX_QUEUE_MSG_SIZE_LARGE	512

typedef struct __attribute__((__packed__)) {
#ifdef ARCH_SEC_HW
	unsigned timeout:12;
	unsigned limit:12;
	unsigned owner:8; /* Proc with current access to the non-fixed end of a queue. */
#else
	unsigned owner:8; /* Proc with current access to the non-fixed end of a queue. */
	unsigned limit:12;
	unsigned timeout:12;
#endif
} mailbox_state_reg_t;

/* FIXME: these are also defined in octopos/runtime.h */
typedef uint32_t limit_t;
typedef uint32_t timeout_t;

#define MAILBOX_NO_LIMIT_VAL			0xFFF
#define MAILBOX_NO_TIMEOUT_VAL			0xFFF
/* FIXME: these are also defined in octopos/runtime.h */
#define MAILBOX_MAX_LIMIT_VAL			0xFFE
#define MAILBOX_MAX_TIMEOUT_VAL			0xFFE
#ifndef ARCH_SEC_HW
#define MAILBOX_MIN_PRACTICAL_TIMEOUT_VAL	2
#define MAILBOX_DEFAULT_TIMEOUT_VAL		6
#else
#define MAILBOX_MIN_PRACTICAL_TIMEOUT_VAL	20
#define MAILBOX_DEFAULT_TIMEOUT_VAL		60
#endif

/* FIXME: move somewhere else */
#ifdef UNTRUSTED_DOMAIN
void mailbox_yield_to_previous_owner(uint8_t queue_id);
int mailbox_attest_queue_access(uint8_t queue_id, limit_t limit,
				timeout_t timeout);
void reset_queue_sync(uint8_t queue_id, int init_val);
limit_t get_queue_limit(uint8_t queue_id);
timeout_t get_queue_timeout(uint8_t queue_id);
void decrement_queue_limit(uint8_t queue_id, limit_t count);
void register_timeout_update_callback(uint8_t queue_id,
				      void (*callback)(uint8_t, timeout_t));
#endif

#endif /* _OCTOPOS_MAILBOX_H_ */
