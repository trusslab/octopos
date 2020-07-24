#ifndef OCTOPOS_SYSCALL_H_
#define OCTOPOS_SYSCALL_H_

#ifndef UNTRUSTED_DOMAIN
#include "arch/syscall.h"
#endif

/* syscall numbers */
#define SYSCALL_REQUEST_SECURE_SERIAL_OUT	0
#define SYSCALL_REQUEST_SECURE_KEYBOARD		1
#define SYSCALL_INFORM_OS_OF_TERMINATION	2
#define SYSCALL_INFORM_OS_OF_PAUSE		3
#define SYSCALL_INFORM_OS_RUNTIME_READY		4
#define SYSCALL_WRITE_TO_SHELL			5
#define SYSCALL_READ_FROM_SHELL			6
#define SYSCALL_OPEN_FILE			7
#define SYSCALL_WRITE_TO_FILE			8
#define SYSCALL_READ_FROM_FILE			9
#define SYSCALL_WRITE_FILE_BLOCKS		10
#define SYSCALL_READ_FILE_BLOCKS		11
#define SYSCALL_CLOSE_FILE			12
#define SYSCALL_REMOVE_FILE			13
#define SYSCALL_REQUEST_SECURE_STORAGE_CREATION	14
#define SYSCALL_REQUEST_SECURE_STORAGE_ACCESS	15
#define SYSCALL_DELETE_SECURE_STORAGE		16
#define SYSCALL_REQUEST_SECURE_IPC		17
#define SYSCALL_ALLOCATE_SOCKET			18
#define SYSCALL_REQUEST_NETWORK_ACCESS		19
#define SYSCALL_CLOSE_SOCKET			20
#define SYSCALL_DEBUG_OUTPUTS		21
#define NUM_SYSCALLS				22

/* FIXME: move somewhere else */
/* defines for SYSCALL_ALLOCATE_SOCKET_PORT */
#define TCP_SOCKET	0

#ifndef UNTRUSTED_DOMAIN
#define SYSCALL_SET_ZERO_ARGS(syscall_nr)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	SERIALIZE_16(syscall_nr, &buf[0])			\

#define SYSCALL_SET_ONE_ARG(syscall_nr, arg0)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	SERIALIZE_16(syscall_nr, &buf[0])			\
	SERIALIZE_32(arg0, &buf[2])					\

#define SYSCALL_SET_TWO_ARGS(syscall_nr, arg0, arg1)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	SERIALIZE_16(syscall_nr, &buf[0])			\
	SERIALIZE_32(arg0, &buf[2])					\
	SERIALIZE_32(arg1, &buf[6])					\

#define SYSCALL_SET_THREE_ARGS(syscall_nr, arg0, arg1, arg2)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_16(syscall_nr, &buf[0])			\
	SERIALIZE_32(arg0, &buf[2])					\
	SERIALIZE_32(arg1, &buf[6])					\
	SERIALIZE_32(arg2, &buf[10])				\

#define SYSCALL_SET_FOUR_ARGS(syscall_nr, arg0, arg1, arg2, arg3)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];				\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);			\
	SERIALIZE_16(syscall_nr, &buf[0])			\
	SERIALIZE_32(arg0, &buf[2])					\
	SERIALIZE_32(arg1, &buf[6])					\
	SERIALIZE_32(arg2, &buf[10])				\
	SERIALIZE_32(arg3, &buf[14])				\

#define SYSCALL_SET_ONE_RET(ret0)			\
	buf[0] = RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG;	\
	SERIALIZE_32(ret0, &buf[1])					\

#define SYSCALL_SET_TWO_RETS(ret0, ret1)		\
	buf[0] = RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG;	\
	SERIALIZE_32(ret0, &buf[1])					\
	SERIALIZE_32(ret1, &buf[5])					\

/* FIXME: when calling this one, we need to allocate a ret_buf. Can we avoid that? */
#define SYSCALL_SET_ONE_RET_DATA(ret0, data, size)		\
	buf[0] = RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG;		\
	SERIALIZE_32(ret0, &buf[1])							\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 6;		\
	if (max_size < 256 && size <= ((int) max_size)) {	\
		buf[5] = (uint8_t) size;			\
		memcpy(&buf[6], data, size);			\
	} else {						\
		printf("Error: invalid max_size or size\n");	\
		buf[5] = 0;					\
	}							\

#define SYSCALL_GET_ONE_ARG		\
	uint32_t arg0;			\
	arg0 = *((uint32_t *) &buf[2]); \

#define SYSCALL_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	arg0 = *((uint32_t *) &buf[2]); \
	arg1 = *((uint32_t *) &buf[6]); \

#define SYSCALL_GET_THREE_ARGS		\
	uint32_t arg0, arg1, arg2;	\
	arg0 = *((uint32_t *) &buf[2]); \
	arg1 = *((uint32_t *) &buf[6]); \
	arg2 = *((uint32_t *) &buf[10]);\

#define SYSCALL_GET_FOUR_ARGS			\
	uint32_t arg0, arg1, arg2, arg3;	\
	arg0 = *((uint32_t *) &buf[2]);		\
	arg1 = *((uint32_t *) &buf[6]);		\
	arg2 = *((uint32_t *) &buf[10]);	\
	arg3 = *((uint32_t *) &buf[14]);	\

#endif /* UNTRUSTED_DOMAIN */
#endif /* OCTOPOS_SYSCALL_H_ */
