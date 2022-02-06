#ifndef OCTOPOS_SYSCALL_H_
#define OCTOPOS_SYSCALL_H_

#include <octopos/runtime.h>
#include <octopos/error.h>
#ifndef UNTRUSTED_DOMAIN
#include "arch/syscall.h"
#else

#ifdef CONFIG_ARM64
#include <octopos/syscall_sechw.h>
#else 
#include <octopos/syscall_umode.h>
#endif

#define printf printk
#define assert(cond) BUG_ON(!(cond))
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
#define SYSCALL_GET_FILE_SIZE			12
#define SYSCALL_CLOSE_FILE			13
#define SYSCALL_REMOVE_FILE			14
#define SYSCALL_REQUEST_SECURE_STORAGE_CREATION	15
#define SYSCALL_REQUEST_SECURE_STORAGE_ACCESS	16
#define SYSCALL_REQUEST_SECURE_IPC		17
#define SYSCALL_ALLOCATE_SOCKET			18
#define SYSCALL_REQUEST_NETWORK_ACCESS		19
#define SYSCALL_CLOSE_SOCKET			20
#define SYSCALL_REQUEST_BLUETOOTH_ACCESS	21
#define SYSCALL_DEBUG_OUTPUTS			22
#define NUM_SYSCALLS				23

/* FIXME: move somewhere else */
/* defines for SYSCALL_ALLOCATE_SOCKET_PORT */
#define TCP_SOCKET	0

#define SYSCALL_SET_ZERO_ARGS(syscall_nr)		\
	ALLOC_MAILBOX_MESSAGE_BUF			\
	assert(2 <= MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_16(syscall_nr, &buf[0])		\

#define SYSCALL_SET_ONE_ARG(syscall_nr, arg0)		\
	ALLOC_MAILBOX_MESSAGE_BUF			\
	assert(2 <= MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_16(syscall_nr, &buf[0])		\
	SET_MAILBOX_MESSAGE_ONE_ARG(2, arg0)		\

#define SYSCALL_SET_TWO_ARGS(syscall_nr, arg0, arg1)	\
	ALLOC_MAILBOX_MESSAGE_BUF			\
	assert(2 <= MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_16(syscall_nr, &buf[0])		\
	SET_MAILBOX_MESSAGE_TWO_ARGS(2, arg0, arg1)	\

#define SYSCALL_SET_THREE_ARGS(syscall_nr, arg0, arg1, arg2)	\
	ALLOC_MAILBOX_MESSAGE_BUF				\
	assert(2 <= MAILBOX_QUEUE_MSG_SIZE);			\
	SERIALIZE_16(syscall_nr, &buf[0])			\
	SET_MAILBOX_MESSAGE_THREE_ARGS(2, arg0, arg1, arg2)	\

#define SYSCALL_SET_FOUR_ARGS(syscall_nr, arg0, arg1, arg2, arg3)	\
	ALLOC_MAILBOX_MESSAGE_BUF					\
	assert(2 <= MAILBOX_QUEUE_MSG_SIZE);				\
	SERIALIZE_16(syscall_nr, &buf[0])				\
	SET_MAILBOX_MESSAGE_FOUR_ARGS(2, arg0, arg1, arg2, arg3)	\

#define SYSCALL_SET_ZERO_ARGS_DATA(syscall_nr, data, size)	\
	ALLOC_MAILBOX_MESSAGE_BUF				\
	assert(2 <= MAILBOX_QUEUE_MSG_SIZE);			\
	SERIALIZE_16(syscall_nr, &buf[0])			\
	SET_MAILBOX_MESSAGE_ZERO_ARGS_DATA(2, data, size,	\
					   return ERR_INVALID)	\

#define SYSCALL_SET_ONE_ARG_DATA(syscall_nr, arg0, data, size)	\
	ALLOC_MAILBOX_MESSAGE_BUF				\
	assert(2 <= MAILBOX_QUEUE_MSG_SIZE);			\
	SERIALIZE_16(syscall_nr, &buf[0])			\
	SET_MAILBOX_MESSAGE_ONE_ARG_DATA(2, arg0, data, size,	\
					 return ERR_INVALID)	\

#define SYSCALL_SET_TWO_ARGS_DATA(syscall_nr, arg0, arg1, data, size)	\
	ALLOC_MAILBOX_MESSAGE_BUF					\
	assert(2 <= MAILBOX_QUEUE_MSG_SIZE);				\
	SERIALIZE_16(syscall_nr, &buf[0])				\
	SET_MAILBOX_MESSAGE_TWO_ARGS_DATA(2, arg0, arg1, data, size,	\
					  return ERR_INVALID)		\

#define SYSCALL_SET_THREE_ARGS_DATA(syscall_nr, arg0, arg1, arg2, data, size)	\
	ALLOC_MAILBOX_MESSAGE_BUF						\
	assert(2 <= MAILBOX_QUEUE_MSG_SIZE);					\
	SERIALIZE_16(syscall_nr, &buf[0])					\
	SET_MAILBOX_MESSAGE_THREE_ARGS_DATA(2, arg0, arg1, arg2, data, size,	\
					  return ERR_INVALID)			\
	
#define SYSCALL_SET_ONE_RET(ret0)				\
	assert(5 <= MAILBOX_QUEUE_MSG_SIZE);			\
	SERIALIZE_8(RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG, &buf[0])\
	SET_MAILBOX_MESSAGE_ONE_ARG(1, ret0)			\

#define SYSCALL_SET_TWO_RETS(ret0, ret1)			\
	assert(9 <= MAILBOX_QUEUE_MSG_SIZE);			\
	SERIALIZE_8(RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG, &buf[0])\
	SET_MAILBOX_MESSAGE_TWO_ARGS(1, ret0, ret1)		\

#define SYSCALL_SET_ONE_RET_DATA(ret0, data, size)		\
	assert(1 <= MAILBOX_QUEUE_MSG_SIZE);			\
	SERIALIZE_8(RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG, &buf[0])\
	SET_MAILBOX_MESSAGE_ONE_ARG_DATA(1, ret0, data, size,)	\

#define SYSCALL_GET_ONE_ARG			\
	uint32_t arg0;				\
	GET_MAILBOX_MESSAGE_ONE_ARG(2, arg0)	\

#define SYSCALL_GET_TWO_ARGS				\
	uint32_t arg0, arg1;				\
	GET_MAILBOX_MESSAGE_TWO_ARGS(2, arg0, arg1)	\

#define SYSCALL_GET_THREE_ARGS					\
	uint32_t arg0, arg1, arg2;				\
	GET_MAILBOX_MESSAGE_THREE_ARGS(2, arg0, arg1, arg2)	\

#define SYSCALL_GET_FOUR_ARGS						\
	uint32_t arg0, arg1, arg2, arg3;				\
	GET_MAILBOX_MESSAGE_FOUR_ARGS(2, arg0, arg1, arg2, arg3)	\

#define SYSCALL_GET_ZERO_ARGS_DATA					\
	uint8_t data_size, *data;					\
	GET_MAILBOX_MESSAGE_ZERO_ARGS_DATA(2, data, data_size,		\
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
			break)						\

#define SYSCALL_GET_ONE_ARG_DATA					\
	uint32_t arg0;							\
	uint8_t data_size, *data;					\
	GET_MAILBOX_MESSAGE_ONE_ARG_DATA(2, arg0, data, data_size,	\
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
			break)						\

#define SYSCALL_GET_TWO_ARGS_DATA						\
	uint32_t arg0, arg1;							\
	uint8_t data_size, *data;						\
	GET_MAILBOX_MESSAGE_TWO_ARGS_DATA(2, arg0, arg1, data, data_size,	\
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)		\
			break)							\

#define SYSCALL_GET_THREE_ARGS_DATA						\
	uint32_t arg0, arg1, arg2;						\
	uint8_t data_size, *data;						\
	GET_MAILBOX_MESSAGE_THREE_ARGS_DATA(2, arg0, arg1, arg2, data,		\
			data_size, SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
			break)							\

#define SYSCALL_GET_ONE_RET				\
	uint32_t ret0;					\
	GET_MAILBOX_MESSAGE_ONE_ARG(1, ret0)		\

#define SYSCALL_GET_TWO_RETS				\
	uint32_t ret0, ret1;				\
	GET_MAILBOX_MESSAGE_TWO_ARGS(1, ret0, ret1)	\

#define SYSCALL_GET_ONE_RET_DATA				\
	uint32_t ret0;						\
	uint8_t _size, *_data;					\
	GET_MAILBOX_MESSAGE_ONE_ARG_DATA(1, ret0, _data, _size,	\
					 return ERR_INVALID)	\

#endif /* OCTOPOS_SYSCALL_H_ */
