#ifndef _OS_INCLUDE_STORAGE_H_
#define _OS_INCLUDE_STORAGE_H_

#include <tpm/hash.h>
#include <arch/syscall.h>

#define PARTITION_SIZE		1000 /* blocks */

#define STORAGE_SET_ONE_ARG(arg0)				\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_32(arg0, &buf[1])				\

#define STORAGE_SET_TWO_ARGS(arg0, arg1)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_32(arg0, &buf[1])				\
	SERIALIZE_32(arg1, &buf[5])				\

#define STORAGE_SET_THREE_ARGS(arg0, arg1, arg2)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_32(arg0, &buf[1])				\
	SERIALIZE_32(arg1, &buf[5])				\
	SERIALIZE_32(arg2, &buf[9])				\

#define STORAGE_SET_ZERO_ARGS_DATA(data, size)					\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 2;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	buf[1] = size;								\
	memcpy(&buf[2], (uint8_t *) data, size);				\

#define STORAGE_SET_ONE_ARG_DATA(arg0, data, size)				\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 6;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	SERIALIZE_32(arg0, &buf[1])						\
	buf[5] = size;								\
	memcpy(&buf[6], (uint8_t *) data, size);				\

#define STORAGE_GET_ONE_RET				\
	uint32_t ret0;					\
	DESERIALIZE_32(&ret0, &buf[0]);			\

#define STORAGE_GET_TWO_RETS				\
	uint32_t ret0, ret1;				\
	DESERIALIZE_32(&ret0, &buf[0]);			\
	DESERIALIZE_32(&ret1, &buf[4]);			\

#define STORAGE_GET_ONE_RET_DATA(data)						\
	uint32_t ret0;								\
	uint8_t _size, max_size = MAILBOX_QUEUE_MSG_SIZE - 5;			\
	DESERIALIZE_32(&ret0, &buf[0]);	\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	_size = buf[4];								\
	if (_size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	memcpy(data, &buf[5], _size);						\

struct partition {
	uint32_t partition_id;
	uint32_t size;
	uint8_t is_created;
	uint8_t key[TPM_EXTEND_HASH_SIZE];
};

/* Status of the storage service */
#define OS_ACCESS	0 /* OS has access but its partition isn't bound. */
#define OS_USE		1 /* OS has access and its partition is bound. */
#define APP_ACCESS	2 /* An app has access. */

void wait_for_storage(void);
int wait_for_storage_for_os_use(void);
void handle_request_secure_storage_creation_syscall(uint8_t runtime_proc_id,
						    uint8_t *buf);
void handle_request_secure_storage_access_syscall(uint8_t runtime_proc_id,
						  uint8_t *buf);
uint32_t initialize_storage(void);

#endif /* _OS_INCLUDE_STORAGE_H_ */
