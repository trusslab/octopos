#ifndef _OCTOPOS_BLUETOOTH_H_
#define _OCTOPOS_BLUETOOTH_H_

/* FIXME: for definitions of DE/SERIALIZE_XXX */
#if !defined(UNTRUSTED_DOMAIN) && !defined(APPLICATION)
#include "arch/syscall.h"
#endif

/* BD_ADDR is 48 bits */
#define BD_ADDR_LEN	6

/* FIXME: repeatitions */
#define BLUETOOTH_SET_ONE_RET(ret0)				\
	SERIALIZE_32(ret0, &buf[0])

/* FIXME: when calling this one, we need to allocate a ret_buf. Can we avoid that? */
#define BLUETOOTH_SET_ONE_RET_DATA(ret0, data, size)		\
	*((uint32_t *) &buf[0]) = ret0;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 5;		\
	if (max_size < 256 && size <= ((int) max_size)) {	\
		buf[4] = (uint8_t) size;			\
		memcpy(&buf[5], data, size);			\
	} else {						\
		printf("Error: invalid max_size or size\n");	\
		buf[4] = 0;					\
	}

#define BLUETOOTH_GET_ONE_RET					\
	uint32_t ret0;						\
	DESERIALIZE_32(&ret0, &buf[1]);				\

/* FIXME: are we sure data is big enough for the memcpy here? */
/* Note: this is different from similar GET_ONE_RET_DATA macros.
 * It simply returns the address for data, rather than copying to a data
 * buffer.
 */
#define BLUETOOTH_GET_ONE_RET_DATA						\
	uint32_t ret0;								\
	uint8_t *data;								\
	uint8_t _size, max_size = MAILBOX_QUEUE_MSG_SIZE - 5;			\
	ret0 = *((uint32_t *) &buf[0]);						\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	_size = buf[4];								\
	if (_size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	data = &buf[5];								\


#endif
