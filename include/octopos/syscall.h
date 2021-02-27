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
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	SERIALIZE_16(syscall_nr, &buf[0])		\

#define SYSCALL_SET_ONE_ARG(syscall_nr, arg0)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	SERIALIZE_16(syscall_nr, &buf[0])		\
	SERIALIZE_32(arg0, &buf[2])			\

#define SYSCALL_SET_TWO_ARGS(syscall_nr, arg0, arg1)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	SERIALIZE_16(syscall_nr, &buf[0])		\
	SERIALIZE_32(arg0, &buf[2])			\
	SERIALIZE_32(arg1, &buf[6])			\

#define SYSCALL_SET_THREE_ARGS(syscall_nr, arg0, arg1, arg2)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_16(syscall_nr, &buf[0])			\
	SERIALIZE_32(arg0, &buf[2])				\
	SERIALIZE_32(arg1, &buf[6])				\
	SERIALIZE_32(arg2, &buf[10])				\

#define SYSCALL_SET_FOUR_ARGS(syscall_nr, arg0, arg1, arg2, arg3)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];				\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);			\
	SERIALIZE_16(syscall_nr, &buf[0])				\
	SERIALIZE_32(arg0, &buf[2])					\
	SERIALIZE_32(arg1, &buf[6])					\
	SERIALIZE_32(arg2, &buf[10])					\
	SERIALIZE_32(arg3, &buf[14])					\

#define SYSCALL_SET_ZERO_ARGS_DATA(syscall_nr, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 3;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	SERIALIZE_16(syscall_nr, &buf[0])					\
	buf[2] = size;								\
	memcpy(&buf[3], (uint8_t *) data, size);				\

#define SYSCALL_SET_ONE_ARG_DATA(syscall_nr, arg0, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 7;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	SERIALIZE_16(syscall_nr, &buf[0])					\
	SERIALIZE_32(arg0, &buf[2])						\
	buf[6] = size;								\
	memcpy(&buf[7], (uint8_t *) data, size);				\

#define SYSCALL_SET_TWO_ARGS_DATA(syscall_nr, arg0, arg1, data, size)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 11;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	SERIALIZE_16(syscall_nr, &buf[0])					\
	SERIALIZE_32(arg0, &buf[2])						\
	SERIALIZE_32(arg1, &buf[6])						\
	buf[10] = size;								\
	memcpy(&buf[11], (uint8_t *) data, size);				\

#define SYSCALL_SET_THREE_ARGS_DATA(syscall_nr, arg0, arg1, arg2, data, size)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 15;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	SERIALIZE_16(syscall_nr, &buf[0])					\
	SERIALIZE_32(arg0, &buf[2])						\
	SERIALIZE_32(arg1, &buf[6])						\
	SERIALIZE_32(arg2, &buf[10])						\
	buf[14] = size;								\
	memcpy(&buf[15], (uint8_t *) data, size);				\

#define SYSCALL_SET_ONE_RET(ret0)			\
	buf[0] = RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG;	\
	SERIALIZE_32(ret0, &buf[1])			\

#define SYSCALL_SET_TWO_RETS(ret0, ret1)		\
	buf[0] = RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG;	\
	SERIALIZE_32(ret0, &buf[1])			\
	SERIALIZE_32(ret1, &buf[5])			\

/* FIXME: when calling this one, we need to allocate a ret_buf. Can we avoid that? */
/* FIXME: use SERIALIZE_XXX */
#define SYSCALL_SET_ONE_RET_DATA(ret0, data, size)		\
	buf[0] = RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG;		\
	SERIALIZE_32(ret0, &buf[1])				\
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
	DESERIALIZE_32(&arg0, &buf[2]);	\

#define SYSCALL_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	DESERIALIZE_32(&arg0, &buf[2]);	\
	DESERIALIZE_32(&arg1, &buf[6]);	\

#define SYSCALL_GET_THREE_ARGS		\
	uint32_t arg0, arg1, arg2;	\
	DESERIALIZE_32(&arg0, &buf[2]);	\
	DESERIALIZE_32(&arg1, &buf[6]);	\
	DESERIALIZE_32(&arg2, &buf[10]);	\

#define SYSCALL_GET_FOUR_ARGS			\
	uint32_t arg0, arg1, arg2, arg3;	\
	DESERIALIZE_32(&arg0, &buf[2]);	\
	DESERIALIZE_32(&arg1, &buf[6]);	\
	DESERIALIZE_32(&arg2, &buf[10]);	\
	DESERIALIZE_32(&arg3, &buf[14]);	\

#define SYSCALL_GET_ONE_RET				\
	uint32_t ret0;					\
	DESERIALIZE_32(&ret0, &buf[1]);			\

#define SYSCALL_GET_TWO_RETS				\
	uint32_t ret0, ret1;				\
	DESERIALIZE_32(&ret0, &buf[1]);			\
	DESERIALIZE_32(&ret1, &buf[5]);			\

/* FIXME: are we sure data is big enough for the memcpy here? */
#define SYSCALL_GET_ONE_RET_DATA(data)						\
	uint32_t ret0;								\
	uint8_t _size, _max_size = MAILBOX_QUEUE_MSG_SIZE - 6;			\
	ret0 = *((uint32_t *) &buf[1]);						\
	if (_max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	_size = buf[5];								\
	if (_size > _max_size) {						\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	memcpy(data, &buf[6], _size);						\

#endif /* OCTOPOS_SYSCALL_H_ */
