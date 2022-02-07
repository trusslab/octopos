#ifndef _OCTOPOS_BLUETOOTH_H_
#define _OCTOPOS_BLUETOOTH_H_

/* FIXME: for definitions of DE/SERIALIZE_XXX */
#if !defined(UNTRUSTED_DOMAIN) && !defined(APPLICATION)
#include "arch/syscall.h"
#endif
#include <octopos/error.h>

/* BD_ADDR is 48 bits */
#define BD_ADDR_LEN	6

/* Macros for sending/receiving bluetooth messages and their responses. */
#define BLUETOOTH_SET_ZERO_ARGS(op)		\
	ALLOC_MAILBOX_MESSAGE_BUF		\
	assert(1 <= MAILBOX_QUEUE_MSG_SIZE);	\
	SERIALIZE_8(op, &buf[0])		\

#define BLUETOOTH_SET_ONE_ARG(op, arg0)		\
	ALLOC_MAILBOX_MESSAGE_BUF		\
	assert(1 <= MAILBOX_QUEUE_MSG_SIZE);	\
	SERIALIZE_8(op, &buf[0])		\
	SET_MAILBOX_MESSAGE_ONE_ARG(1, arg0)	\
	
#define BLUETOOTH_SET_ONE_ARG_DATA(op, arg0, data, size)	\
	ALLOC_MAILBOX_MESSAGE_BUF				\
	assert(1 <= MAILBOX_QUEUE_MSG_SIZE);			\
	SERIALIZE_8(op, &buf[0])				\
	SET_MAILBOX_MESSAGE_ONE_ARG_DATA(1, arg0, data, size,	\
					 return ERR_INVALID)	\

#define BLUETOOTH_SET_ONE_RET(ret0)		\
	SET_MAILBOX_MESSAGE_ONE_ARG(0, ret0)	\

#define BLUETOOTH_SET_ONE_RET_DATA(ret0, data, size)		\
	SET_MAILBOX_MESSAGE_ONE_ARG_DATA(0, ret0, data, size,)	\

#define BLUETOOTH_GET_ONE_ARG			\
	uint32_t arg0;				\
	GET_MAILBOX_MESSAGE_ONE_ARG(1, arg0)	\

#define BLUETOOTH_GET_ONE_ARG_DATA						\
	uint32_t arg0;								\
	uint8_t _size, *data;							\
	GET_MAILBOX_MESSAGE_ONE_ARG_DATA(1, arg0, data, _size, char dummy;	\
			BLUETOOTH_SET_ONE_RET_DATA(ERR_INVALID, &dummy, 0)	\
			return)							\

#define BLUETOOTH_GET_ONE_RET			\
	uint32_t ret0;				\
	GET_MAILBOX_MESSAGE_ONE_ARG(0, ret0)	\

#define BLUETOOTH_GET_ONE_RET_DATA				\
	uint32_t ret0;						\
	uint8_t _size, *data;					\
	GET_MAILBOX_MESSAGE_ONE_ARG_DATA(0, ret0, data, _size,	\
					 return ERR_INVALID)	\

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
