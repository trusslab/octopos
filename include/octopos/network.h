#ifndef _OCTOPOS_NETWORK_H_
#define _OCTOPOS_NETWORK_H_

#include <octopos/mailbox.h>

/* Macros for sending/receiving storage messages and their responses. */
#define NETWORK_SET_FOUR_ARGS(arg0, arg1, arg2, arg3)			\
	ALLOC_MAILBOX_MESSAGE_BUF					\
	SET_MAILBOX_MESSAGE_FOUR_ARGS(0, arg0, arg1, arg2, arg3)	\

#define NETWORK_SET_ZERO_ARGS_DATA(data, size)				\
	ALLOC_MAILBOX_MESSAGE_BUF_LARGE					\
	SET_MAILBOX_MESSAGE_LARGE_ZERO_ARGS_DATA(0, data, size,	return)	\

#define NETWORK_SET_ONE_RET(ret0)		\
	SET_MAILBOX_MESSAGE_ONE_ARG(0, ret0)	\

#define NETWORK_SET_ZERO_RETS_DATA(data, size)				\
	ALLOC_MAILBOX_MESSAGE_BUF_LARGE					\
	SET_MAILBOX_MESSAGE_LARGE_ZERO_ARGS_DATA(0, data, size, return)	\

#define NETWORK_GET_FOUR_ARGS						\
	uint32_t arg0, arg1, arg2, arg3;				\
	GET_MAILBOX_MESSAGE_FOUR_ARGS(0, arg0, arg1, arg2, arg3)	\

#define NETWORK_GET_ZERO_ARGS_DATA						\
	uint8_t *data;								\
	uint16_t data_size;							\
	GET_MAILBOX_MESSAGE_LARGE_ZERO_ARGS_DATA(0, data, data_size, return)	\

#define NETWORK_GET_ONE_RET			\
	uint32_t ret0;				\
	GET_MAILBOX_MESSAGE_ONE_ARG(0, ret0)	\

#define NETWORK_GET_ZERO_RETS_DATA					\
	uint8_t *data;							\
	uint16_t data_size;						\
	GET_MAILBOX_MESSAGE_LARGE_ZERO_ARGS_DATA(0, data, data_size,	\
						 return NULL)		\

#endif /* _OCTOPOS_NETWORK_H_ */
