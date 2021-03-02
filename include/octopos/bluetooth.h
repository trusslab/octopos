#ifndef _OCTOPOS_BLUETOOTH_H_
#define _OCTOPOS_BLUETOOTH_H_

/* FIXME: for definitions of DE/SERIALIZE_XXX */
#if !defined(UNTRUSTED_DOMAIN) && !defined(APPLICATION)
#include "arch/syscall.h"
#endif
#include <octopos/error.h>

/* BD_ADDR is 48 bits */
#define BD_ADDR_LEN	6

/* FIXME: repetition */
#define BLUETOOTH_SET_ZERO_ARGS(op)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	buf[0] = (uint8_t) op;				\

#define BLUETOOTH_SET_ONE_ARG(op, arg0)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	buf[0] = (uint8_t) op;				\
	SERIALIZE_32(arg0, &buf[1])			\

#define BLUETOOTH_SET_ONE_ARG_DATA(op, arg0, data, size)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	buf[0] = (uint8_t) op;					\
	SERIALIZE_32(arg0, &buf[1])				\
	uint8_t _max_size = MAILBOX_QUEUE_MSG_SIZE - 6;		\
	if (_max_size < 256 && size <= ((int) _max_size)) {	\
		buf[5] = (uint8_t) size;			\
		memcpy(&buf[6], data, size);			\
	} else {						\
		printf("Error: invalid max_size or size\n");	\
		buf[6] = 0;					\
	}

#define BLUETOOTH_GET_ONE_ARG				\
	uint32_t arg0;					\
	DESERIALIZE_32(&arg0, &buf[1]);			\

#define BLUETOOTH_GET_ONE_ARG_DATA						\
	uint32_t arg0;								\
	DESERIALIZE_32(&arg0, &buf[1]);						\
	uint8_t *data;								\
	uint8_t _size, _max_size = MAILBOX_QUEUE_MSG_SIZE - 6;			\
	if (_max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		char dummy;							\
		BLUETOOTH_SET_ONE_RET_DATA(ERR_INVALID, &dummy, 0)		\
		return;								\
	}									\
	_size = buf[5];								\
	if (_size > _max_size) {						\
		printf("Error (%s): size not supported\n", __func__);		\
		char dummy;							\
		BLUETOOTH_SET_ONE_RET_DATA(ERR_INVALID, &dummy, 0)		\
		return;								\
	}									\
	data = &buf[6];								\

/* FIXME: why don't we zero the buf in set_ret funcs? */
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
	DESERIALIZE_32(&ret0, &buf[0]);				\

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

struct bt_header {
	uint8_t am_addr:3;
	uint8_t type:4;
	uint8_t flow:1;
	uint8_t arqn:1;
	uint8_t seqn:1;
	uint8_t hec;
} __attribute__((packed));

#define BTPACKET_FIXED_DATA_SIZE	32

/* Bluetooth packet
 * This is not accurate in the following ways:
 * - Ignoring the byte/bit endianness of a bluetooth packet
 * - Fixed data size
 */
struct btpacket {
	/* Access code */
        uint8_t preamble:4;
        uint16_t sync_word;
        uint8_t trailer:4;
	/* Header: 18 bit pattern repeated three times */
	struct bt_header header1;
	struct bt_header header2;
	struct bt_header header3;
	/* Payload */
	uint8_t payload_header;
	uint32_t l_ch:2;
	uint8_t flow:1;
	uint8_t length:5;
        uint8_t data[BTPACKET_FIXED_DATA_SIZE];
	uint16_t crc;
} __attribute__((packed));
