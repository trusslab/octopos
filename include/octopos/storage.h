#ifndef _OCTOPOS_STORAGE_H_
#define _OCTOPOS_STORAGE_H_

#include <octopos/mailbox.h>

#if defined(ARCH_SEC_HW) && !defined(PROJ_CPP)
#define bool _Bool
#define true 1
#define false 0
#endif

#ifdef ARCH_SEC_HW
#define STORAGE_BLOCK_SIZE	64  /* bytes */
#else
#define STORAGE_BLOCK_SIZE	512  /* bytes */
#endif

#ifdef ARCH_SEC_HW
#define STORAGE_BOOT_PARTITION_SIZE			16384
#define STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE	32768
#else
#define STORAGE_BOOT_PARTITION_SIZE			200000
#define STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE	4000000
#endif

/* Macros for sending/receiving storage messages and their responses. */
#define STORAGE_SET_ONE_ARG(arg0)		\
	ALLOC_MAILBOX_MESSAGE_BUF		\
	SET_MAILBOX_MESSAGE_ONE_ARG(1, arg0)	\

#define STORAGE_SET_TWO_ARGS(arg0, arg1)		\
	ALLOC_MAILBOX_MESSAGE_BUF			\
	SET_MAILBOX_MESSAGE_TWO_ARGS(1, arg0, arg1)	\

#define STORAGE_SET_THREE_ARGS(arg0, arg1, arg2)		\
	ALLOC_MAILBOX_MESSAGE_BUF				\
	SET_MAILBOX_MESSAGE_THREE_ARGS(1, arg0, arg1, arg2)	\

#define STORAGE_SET_ZERO_ARGS_DATA(data, size)			\
	ALLOC_MAILBOX_MESSAGE_BUF				\
	SET_MAILBOX_MESSAGE_ZERO_ARGS_DATA(1, data, size,	\
					   return ERR_INVALID)	\

#define STORAGE_SET_ONE_ARG_DATA(arg0, data, size)		\
	ALLOC_MAILBOX_MESSAGE_BUF				\
	SET_MAILBOX_MESSAGE_ONE_ARG_DATA(1, arg0, data, size,	\
					   return ERR_INVALID)	\

#define STORAGE_SET_ONE_RET(ret0)		\
	SET_MAILBOX_MESSAGE_ONE_ARG(0, ret0)	\

#define STORAGE_SET_TWO_RETS(ret0, ret1)		\
	SET_MAILBOX_MESSAGE_TWO_ARGS(0, ret0, ret1)	\

#define STORAGE_SET_ONE_RET_DATA(ret0, data, size)		\
	SET_MAILBOX_MESSAGE_ONE_ARG_DATA(0, ret0, data, size,)	\

#define STORAGE_GET_ONE_ARG			\
	uint32_t arg0;				\
	GET_MAILBOX_MESSAGE_ONE_ARG(1, arg0)	\

#define STORAGE_GET_TWO_ARGS				\
	uint32_t arg0, arg1;				\
	GET_MAILBOX_MESSAGE_TWO_ARGS(1, arg0, arg1)	\

#define STORAGE_GET_THREE_ARGS					\
	uint32_t arg0, arg1, arg2;				\
	GET_MAILBOX_MESSAGE_THREE_ARGS(1, arg0, arg1, arg2)	\

#define STORAGE_GET_ZERO_ARGS_DATA				\
	uint8_t data_size, *data;					\
	GET_MAILBOX_MESSAGE_ZERO_ARGS_DATA(1, data, data_size,		\
			STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
			return)						\

#define STORAGE_GET_ONE_ARG_DATA					\
	uint32_t arg0;							\
	uint8_t data_size, *data;					\
	GET_MAILBOX_MESSAGE_ONE_ARG_DATA(1, arg0, data, data_size,	\
			STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
			return)						\

#define STORAGE_GET_ONE_RET				\
	uint32_t ret0;					\
	GET_MAILBOX_MESSAGE_ONE_ARG(0, ret0)		\

#define STORAGE_GET_TWO_RETS				\
	uint32_t ret0, ret1;				\
	GET_MAILBOX_MESSAGE_TWO_ARGS(0, ret0, ret1)	\

#define STORAGE_GET_ONE_RET_DATA				\
	uint32_t ret0;						\
	uint8_t _size, *_data;					\
	GET_MAILBOX_MESSAGE_ONE_ARG_DATA(0, ret0, _data, _size,	\
					 return ERR_INVALID)	\

#endif /* _OCTOPOS_STORAGE_H_ */
