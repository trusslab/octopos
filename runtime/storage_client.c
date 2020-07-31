/* octopos application runtime */
#ifndef CONFIG_UML /* Linux UML */
#include <arch/defines.h>

#include <stdio.h>
#include <string.h>
#ifdef ARCH_UMODE
#include <fcntl.h>
#endif
#include <unistd.h>
#include <stdint.h>

#ifdef ARCH_UMODE
#include <dlfcn.h>
#endif

#include <stdlib.h>
#include <runtime/runtime.h>
#include <runtime/storage_client.h>
/* FIXME: sock.h is only needed to satisfy the dependencies in other header files */
#include <network/sock.h>
#else /* CONFIG_UML */
#define UNTRUSTED_DOMAIN
#include <linux/module.h>
#include "runtime.h"
#include "storage_client.h"
#endif /* CONFIG_UML */
#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/error.h>
#ifndef UNTRUSTED_DOMAIN
#include <arch/mailbox_runtime.h> 
#endif

#ifdef UNTRUSTED_DOMAIN
#define printf printk
#endif

/* FIXME: there are a lot of repetition in these macros (also see file_system.c) */
#define STORAGE_SET_THREE_ARGS(arg0, arg1, arg2)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	*((uint32_t *) &buf[1]) = arg0;				\
	*((uint32_t *) &buf[5]) = arg1;				\
	*((uint32_t *) &buf[9]) = arg2;				\

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

#define STORAGE_SET_TWO_ARGS_DATA(arg0, arg1, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 10;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	*((uint32_t *) &buf[1]) = arg0;						\
	*((uint32_t *) &buf[5]) = arg1;						\
	buf[9] = size;								\
	memcpy(&buf[10], (uint8_t *) data, size);				\

#define STORAGE_GET_ONE_RET				\
	uint32_t ret0;					\
	ret0 = *((uint32_t *) &buf[0]);			\

#define STORAGE_GET_ONE_RET_DATA(data)						\
	uint32_t ret0;								\
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
	memcpy(data, &buf[5], _size);						\



static int unlock_secure_storage(uint8_t *key)
{
	printf("%s [1]\n", __func__);
	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
	buf[0] = STORAGE_OP_UNLOCK;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int lock_secure_storage(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	buf[0] = STORAGE_OP_LOCK;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int set_secure_storage_key(uint8_t *key)
{
	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
	buf[0] = STORAGE_OP_SET_KEY;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int wipe_secure_storage(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	buf[0] = STORAGE_OP_WIPE;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

uint8_t secure_storage_key[STORAGE_KEY_SIZE];
bool secure_storage_key_set = false;
bool secure_storage_available = false;
bool has_access_to_secure_storage = false;

bool is_secure_storage_key_set(void)
{
	return secure_storage_key_set;
}

/* FIXME: do we need an int return? */
int set_up_secure_storage_key(uint8_t *key)
{
	memcpy(secure_storage_key, key, STORAGE_KEY_SIZE);
	secure_storage_key_set = true;

	return 0;
}

static int request_secure_storage_creation(uint8_t *returned_key)
{
	SYSCALL_SET_ZERO_ARGS(SYSCALL_REQUEST_SECURE_STORAGE_CREATION)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET_DATA(buf)
	if (ret0)
		return (int) ret0;

	if (_size != STORAGE_KEY_SIZE)
		return ERR_INVALID;

	memcpy(returned_key, buf, STORAGE_KEY_SIZE);

	return 0;
}

int yield_secure_storage_access(void)
{
	if (!has_access_to_secure_storage) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return ERR_INVALID;
	}

	/* FIXME: what if lock fails? */
	lock_secure_storage();

	has_access_to_secure_storage = false;

	wait_until_empty(Q_STORAGE_IN_2, MAILBOX_QUEUE_SIZE);

#ifdef ARCH_SEC_HW
	mailbox_yield_to_previous_owner(Q_STORAGE_IN_2);
	mailbox_yield_to_previous_owner(Q_STORAGE_OUT_2);
#else
	mailbox_change_queue_access(Q_STORAGE_IN_2, WRITE_ACCESS, P_OS);
	mailbox_change_queue_access(Q_STORAGE_OUT_2, READ_ACCESS, P_OS);
#endif

	return 0;
}

int request_secure_storage_access(int count)
{
	printf("%s [1]\n", __func__);
	if (!secure_storage_key_set) {
		printf("%s: Error: secure storage key not set.\n", __func__);
		return ERR_INVALID;
	}
	printf("%s [2]\n", __func__);

	reset_queue_sync(Q_STORAGE_IN_2, MAILBOX_QUEUE_SIZE);
	reset_queue_sync(Q_STORAGE_OUT_2, 0);

	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_SECURE_STORAGE_ACCESS, count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;
	printf("%s [3]\n", __func__);

	/* FIXME: if any of the attetations fail, we should yield the other one */
	int attest_ret = mailbox_attest_queue_access(Q_STORAGE_IN_2,
					WRITE_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest secure storage write access\n", __func__);
		return ERR_FAULT;
	}
	printf("%s [4]\n", __func__);

	attest_ret = mailbox_attest_queue_access(Q_STORAGE_OUT_2,
					READ_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest secure storage read access\n", __func__);
		return ERR_FAULT;
	}
	printf("%s [5]\n", __func__);
	has_access_to_secure_storage = true;

	/* unlock the storage (mainly needed to deal with reset-related interruptions.
	 * won't do anything if it's the first time accessing the secure storage) */
	int unlock_ret = unlock_secure_storage(secure_storage_key);
	printf("%s [6]\n", __func__);
	if (unlock_ret == ERR_EXIST) {
		printf("%s [7]\n", __func__);
		uint8_t temp_key[STORAGE_KEY_SIZE];
		int create_ret = request_secure_storage_creation(temp_key);
		if (create_ret) {
			yield_secure_storage_access();
			return create_ret;
		}
		printf("%s [7.1]\n", __func__);
		int unlock_ret_2 = unlock_secure_storage(temp_key);
		if (unlock_ret_2) {
			yield_secure_storage_access();
			return create_ret;
		}
	} else if (unlock_ret) {
		printf("%s [8]\n", __func__);
		yield_secure_storage_access();
		return unlock_ret;
	}
	printf("%s [9]\n", __func__);

	/* if new storage, set the key */
	int set_key_ret = set_secure_storage_key(secure_storage_key);
	if (set_key_ret) {
		yield_secure_storage_access();
		return set_key_ret;
	}
	printf("%s [10]\n", __func__);

	secure_storage_available = true;
	return 0;
}

int delete_and_yield_secure_storage(void)
{
	if (!secure_storage_available || !has_access_to_secure_storage) {
		printf("%s: Error: secure storage has not been set up or there is no access\n", __func__);
		return ERR_INVALID;
	}

	secure_storage_available = false;

	/* wipe storage content */
	wipe_secure_storage();

	has_access_to_secure_storage = false;

	wait_until_empty(Q_STORAGE_IN_2, MAILBOX_QUEUE_SIZE);


	mailbox_change_queue_access(Q_STORAGE_IN_2, WRITE_ACCESS, P_OS);
	mailbox_change_queue_access(Q_STORAGE_OUT_2, READ_ACCESS, P_OS);

	SYSCALL_SET_ZERO_ARGS(SYSCALL_DELETE_SECURE_STORAGE)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	return 0;
}

uint32_t write_to_secure_storage(uint8_t *data, uint32_t block_num,
				 uint32_t block_offset, uint32_t write_size)
{
	if (!secure_storage_available) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return ERR_INVALID;
	}

	STORAGE_SET_TWO_ARGS_DATA(block_num, block_offset, data, write_size)
	buf[0] = STORAGE_OP_WRITE;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

uint32_t read_from_secure_storage(uint8_t *data, uint32_t block_num,
				  uint32_t block_offset, uint32_t read_size)
{
	if (!secure_storage_available) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return ERR_INVALID;
	}

	STORAGE_SET_THREE_ARGS(block_num, block_offset, read_size)
	buf[0] = STORAGE_OP_READ;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET_DATA(data)
	return (int) ret0;
}
