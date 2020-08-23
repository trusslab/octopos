#ifndef __STORAGE_OCTOPOS_CORE_H_
#define __STORAGE_OCTOPOS_CORE_H_

#include <arch/syscall.h>

#ifdef ARCH_SEC_HW
#define bool _Bool
#define true 1
#define false 0
#endif

#define STORAGE_KEY_SIZE	32  /* bytes */

#define STORAGE_OP_WRITE			0
#define STORAGE_OP_READ				1
#define STORAGE_OP_SET_KEY			2
#define STORAGE_OP_UNLOCK			3
#define STORAGE_OP_LOCK				4
#define STORAGE_OP_WIPE				5
#define STORAGE_OP_CREATE_SECURE_PARTITION	6
#define STORAGE_OP_DELETE_SECURE_PARTITION	7
#define STORAGE_OP_SET_CONFIG_KEY		8
#define STORAGE_OP_UNLOCK_CONFIG		9
#define STORAGE_OP_LOCK_CONFIG			10

#ifdef ARCH_SEC_HW
#define STORAGE_BLOCK_SIZE	64  /* bytes */
#else
#define STORAGE_BLOCK_SIZE	512  /* bytes */
#endif

#define STORAGE_SET_ONE_RET(ret0)	\
	SERIALIZE_32(ret0, &buf[0])

#define STORAGE_SET_TWO_RETS(ret0, ret1)	\
	SERIALIZE_32(ret0, &buf[0])				\
	SERIALIZE_32(ret1, &buf[4])

/* FIXME: when calling this one, we need to allocate a ret_buf. Can we avoid that? */
#define STORAGE_SET_ONE_RET_DATA(ret0, data, size)		\
	*((uint32_t *) &buf[0]) = ret0;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 5;		\
	if (max_size < 256 && size <= ((int) max_size)) {	\
		buf[4] = (uint8_t) size;			\
		memcpy(&buf[5], data, size);			\
	} else {						\
		printf("Error: invalid max_size or size\n");	\
		buf[4] = 0;					\
	}

#define STORAGE_GET_ONE_ARG		\
	uint32_t arg0;			\
	arg0 = *((uint32_t *) &buf[1]); \

#define STORAGE_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	arg0 = *((uint32_t *) &buf[1]); \
	arg1 = *((uint32_t *) &buf[5]); \

#define STORAGE_GET_THREE_ARGS		\
	uint32_t arg0, arg1, arg2;	\
	arg0 = *((uint32_t *) &buf[1]); \
	arg1 = *((uint32_t *) &buf[5]); \
	arg2 = *((uint32_t *) &buf[9]);\

#define STORAGE_GET_ZERO_ARGS_DATA				\
	uint8_t data_size, *data;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 2;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data_size = buf[1];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data = &buf[2];					\

#define STORAGE_GET_ONE_ARG_DATA				\
	uint32_t arg0;						\
	uint8_t data_size, *data;				\
	arg0 = *((uint32_t *) &buf[1]);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 6;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data_size = buf[5];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		STORAGE_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data = &buf[6];


/* partition information */
struct partition {
	uint32_t size; /* in blocks */
	char data_name[256];
	char create_name[256];
	char lock_name[256];
	bool is_created;
	bool is_locked;
};

//#define STORAGE_MAIN_PARTITION_SIZE	1000  /* num blocks */
//#define STORAGE_SECURE_PARTITION_SIZE	100  /* num blocks */
#define NUM_PARTITIONS		5


#endif /* __STORAGE_OCTOPOS_CORE_H_ */
