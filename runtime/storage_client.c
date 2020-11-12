/* octopos storage client */
#if !defined(CONFIG_UML) && !defined(CONFIG_ARM64) /* Linux UML or Secure HW */
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
#else /* CONFIG_UML or CONFIG_ARM64*/
#define UNTRUSTED_DOMAIN

#ifdef CONFIG_ARM64
#define ARCH_SEC_HW
#include <linux/delay.h>
#endif

#include <linux/module.h>
#include <octopos/runtime/runtime.h>
#include "storage_client.h"
#endif /* CONFIG_UML or CONFIG_ARM64*/
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

#ifndef UNTRUSTED_DOMAIN
/* FIXME: conslidate with the callback system of the untrusted domain. */
extern limit_t queue_limits[];
extern timeout_t queue_timeouts[];
extern queue_update_callback_t queue_update_callbacks[];
#endif

#if defined(ARCH_SEC_HW) && !defined(CONFIG_ARM64)
extern _Bool async_syscall_mode;
#endif

/* FIXME: there are a lot of repetition in these macros (also see include/os/storage.h) */
#define STORAGE_SET_TWO_ARGS(arg0, arg1)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_32(arg0, &buf[1])				\
	SERIALIZE_32(arg1, &buf[5])				\

#define STORAGE_SET_THREE_ARGS(arg0, arg1, arg2)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_32(arg0, &buf[1])						\
	SERIALIZE_32(arg1, &buf[5])						\
	SERIALIZE_32(arg2, &buf[9])						\

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
	SERIALIZE_32(arg0, &buf[1])						\
	SERIALIZE_32(arg1, &buf[5])						\
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

#if defined(CONFIG_UML) || defined(CONFIG_ARM64)
/* FIXME: move to a header file */
void runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id);
void runtime_send_msg_on_queue(uint8_t *buf, uint8_t queue_id);
void runtime_recv_msg_from_queue_large(uint8_t *buf, uint8_t queue_id);
void runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id);
#endif

int send_msg_to_storage(uint8_t *buf)
{
	runtime_send_msg_on_queue(buf, Q_STORAGE_CMD_IN);
#ifndef UNTRUSTED_DOMAIN
	report_queue_usage(Q_STORAGE_CMD_IN);
#endif

	runtime_recv_msg_from_queue(buf, Q_STORAGE_CMD_OUT);
#ifndef UNTRUSTED_DOMAIN
	report_queue_usage(Q_STORAGE_CMD_OUT);
#endif

	return 0;
}

/* FIXME: the same function is defined in arch/umode/mailbox_interface/mailbox_os.c.
 * Consolidate.
 */
int send_msg_to_storage_no_response(uint8_t *buf)
{
	runtime_send_msg_on_queue(buf, Q_STORAGE_CMD_IN);
#ifndef UNTRUSTED_DOMAIN
	report_queue_usage(Q_STORAGE_CMD_IN);
#endif

	return 0;
}

/* FIXME: the same function is defined in arch/umode/mailbox_interface/mailbox_os.c.
 * Consolidate.
 */
int get_response_from_storage(uint8_t *buf)
{
	runtime_recv_msg_from_queue(buf, Q_STORAGE_CMD_OUT);
#ifndef UNTRUSTED_DOMAIN
	report_queue_usage(Q_STORAGE_CMD_OUT);
#endif

	return 0;
}

/* FIXME: the same function is defined in arch/umode/mailbox_interface/mailbox_os.c.
 * Consolidate.
 */
void read_from_storage_data_queue(uint8_t *buf)
{
	runtime_recv_msg_from_queue_large(buf, Q_STORAGE_DATA_OUT);
#ifndef UNTRUSTED_DOMAIN
	report_queue_usage(Q_STORAGE_DATA_OUT);
#endif
}

/* FIXME: the same function is defined in arch/umode/mailbox_interface/mailbox_os.c.
 * Consolidate.
 */
void write_to_storage_data_queue(uint8_t *buf)
{
	runtime_send_msg_on_queue_large(buf, Q_STORAGE_DATA_IN);
#ifndef UNTRUSTED_DOMAIN
	report_queue_usage(Q_STORAGE_DATA_IN);
#endif
}

static int unlock_secure_storage(uint8_t *key)
{
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

static int request_secure_storage_creation(uint8_t *returned_key, uint32_t size)
{
	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_SECURE_STORAGE_CREATION, size)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET_DATA(buf)
	if (ret0)
		return (int) ret0;

	if (_size != STORAGE_KEY_SIZE)
		return ERR_INVALID;

	memcpy(returned_key, buf, STORAGE_KEY_SIZE);

	return 0;
}

#ifndef UNTRUSTED_DOMAIN
void reset_storage_queues_trackers(void)
{
	/* FIXME: redundant when called from yield_secure_storage_queues_access() */
	has_access_to_secure_storage = false;

	queue_limits[Q_STORAGE_CMD_IN] = 0;
	queue_timeouts[Q_STORAGE_CMD_IN] = 0;
	queue_update_callbacks[Q_STORAGE_CMD_IN] = NULL;

	queue_limits[Q_STORAGE_CMD_OUT] = 0;
	queue_timeouts[Q_STORAGE_CMD_OUT] = 0;
	queue_update_callbacks[Q_STORAGE_CMD_OUT] = NULL;

	queue_limits[Q_STORAGE_DATA_IN] = 0;
	queue_timeouts[Q_STORAGE_DATA_IN] = 0;
	queue_update_callbacks[Q_STORAGE_DATA_IN] = NULL;

	queue_limits[Q_STORAGE_DATA_OUT] = 0;
	queue_timeouts[Q_STORAGE_DATA_OUT] = 0;
	queue_update_callbacks[Q_STORAGE_DATA_OUT] = NULL;
}
#endif

static void yield_secure_storage_queues_access(void)
{
#if defined(ARCH_SEC_HW) && !defined(CONFIG_ARM64)
/* FIXME: remove once we have nested interrupt. Context switch happens 
 * in interrupt context, and subsequent write/read intr will not be 
 * handled.
 */
if (!async_syscall_mode) {
#endif

#ifndef CONFIG_ARM64
	// FIXME: There is a bug preventing semaphore post on Q_STORAGE_DATA_IN
	wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
	wait_until_empty(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
#endif
	
#if defined(ARCH_SEC_HW) && !defined(CONFIG_ARM64)
}
#endif

	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);

#ifndef UNTRUSTED_DOMAIN
	reset_storage_queues_trackers();
#endif
}

int yield_secure_storage_access(void)
{
	if (!has_access_to_secure_storage) {
		return ERR_INVALID;
	}

	if (lock_secure_storage()) {
		printf("%s: Error: fail to lock secure storage\n", __func__);
		return ERR_FAULT;
	}

	has_access_to_secure_storage = false;

	yield_secure_storage_queues_access();

	return 0;
}

/* FIXME: @callback and @expected_pcr can be set by the untrusted domain,
 * but they're no ops.
 */
static int request_secure_storage_queues_access(limit_t limit,
						timeout_t timeout,
						queue_update_callback_t callback,
						uint8_t *expected_pcr)
{
	int ret;

	reset_queue_sync(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
	reset_queue_sync(Q_STORAGE_CMD_OUT, 0);
	reset_queue_sync(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
	reset_queue_sync(Q_STORAGE_DATA_OUT, 0);

	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_SECURE_STORAGE_ACCESS,
			     (uint32_t) limit, (uint32_t) timeout)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	/* FIXME: wait for OS to switch the queue. Microblaze does not have this problem */
#ifdef CONFIG_ARM64
	udelay(100);
#endif

	ret = mailbox_attest_queue_access(Q_STORAGE_CMD_IN, limit, timeout);
	if (!ret) {
		printf("%s: Error: failed to attest secure storage cmd write "
		       "access\n", __func__);
		return ERR_FAULT;
	}

	ret = mailbox_attest_queue_access(Q_STORAGE_CMD_OUT, limit, timeout);
	if (!ret) {
		printf("%s: Error: failed to attest secure storage cmd read "
		       "access\n", __func__);
		wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
		mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
		return ERR_FAULT;
	}

	ret = mailbox_attest_queue_access(Q_STORAGE_DATA_IN, limit, timeout);
	if (!ret) {
		printf("%s: Error: failed to attest secure storage data write "
		       "access\n", __func__);
		wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
		mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
		mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);
		return ERR_FAULT;
	}

	ret = mailbox_attest_queue_access(Q_STORAGE_DATA_OUT, limit, timeout);
	if (!ret) {
		printf("%s: Error: failed to attest secure storage data read "
		       "access\n", __func__);
		wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
		wait_until_empty(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
		mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
		mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);
		mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
		return ERR_FAULT;
	}

#ifndef UNTRUSTED_DOMAIN
	/* Note: we set the limit/timeout values right after attestation and
	 * before we call check_proc_pcr(). This is because that call issues a
	 * syscall, which might take an arbitrary amount of time.
	 */
	queue_limits[Q_STORAGE_CMD_IN] = limit;
	queue_timeouts[Q_STORAGE_CMD_IN] = timeout;

	queue_limits[Q_STORAGE_CMD_OUT] = limit;
	queue_timeouts[Q_STORAGE_CMD_OUT] = timeout;

	queue_limits[Q_STORAGE_DATA_IN] = limit;
	queue_timeouts[Q_STORAGE_DATA_IN] = timeout;

	queue_limits[Q_STORAGE_DATA_OUT] = limit;
	queue_timeouts[Q_STORAGE_DATA_OUT] = timeout;

	if (expected_pcr) {
		ret = check_proc_pcr(P_STORAGE, expected_pcr);
		if (ret) {
			printf("%s: Error: unexpected PCR\n", __func__);
			wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
			wait_until_empty(Q_STORAGE_DATA_IN,
					 MAILBOX_QUEUE_SIZE_LARGE);
			mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
			mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);
			mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
			mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);

			queue_limits[Q_STORAGE_CMD_IN] = 0;
			queue_timeouts[Q_STORAGE_CMD_IN] = 0;
			queue_limits[Q_STORAGE_CMD_OUT] = 0;
			queue_timeouts[Q_STORAGE_CMD_OUT] = 0;
			queue_limits[Q_STORAGE_DATA_IN] = 0;
			queue_timeouts[Q_STORAGE_DATA_IN] = 0;
			queue_limits[Q_STORAGE_DATA_OUT] = 0;
			queue_timeouts[Q_STORAGE_DATA_OUT] = 0;
			return ERR_UNEXPECTED;
		}
	}
	
	queue_update_callbacks[Q_STORAGE_CMD_IN] = callback;
	queue_update_callbacks[Q_STORAGE_CMD_OUT] = callback;
	queue_update_callbacks[Q_STORAGE_DATA_IN] = callback;
	queue_update_callbacks[Q_STORAGE_DATA_OUT] = callback;
#endif

	has_access_to_secure_storage = true;

	return 0;
}

/*
 * partiton_size will be only used if not partition is already created and a new
 * one needs to be created.
 */
int request_secure_storage_access(uint32_t partition_size,
				  limit_t limit, timeout_t timeout,
				  queue_update_callback_t callback,
				  uint8_t *expected_pcr)
{
	int ret, unlock_ret, set_key_ret;

	if (!secure_storage_key_set) {
		printf("%s: Error: secure storage key not set.\n", __func__);
		return ERR_INVALID;
	}

	ret = request_secure_storage_queues_access(limit, timeout, callback,
						   expected_pcr);	
	if (ret) {
		printf("%s: Error: couldn't get access to storage queues.\n",
		       __func__);
		return ret;
	}

	/* Unlock the storage (mainly needed to deal with reset-related
	 * interruptions. Won't do anything if it's the first time accessing
	 * the secure storage).
	 */
	unlock_ret = unlock_secure_storage(secure_storage_key);
	if (unlock_ret == ERR_EXIST) {
		uint8_t temp_key[STORAGE_KEY_SIZE];
		int create_ret, unlock_ret_2;
		yield_secure_storage_queues_access();
		create_ret = request_secure_storage_creation(temp_key,
							     partition_size);
		if (create_ret) {
			printf("%s: Error: request for secure storage creation "
			       "failed.\n", __func__);
			return create_ret;
		}
		ret = request_secure_storage_queues_access(limit, timeout,
							callback, expected_pcr);	
		if (ret) {
			printf("%s: Error: couldn't regain access to storage "
			       "queues.\n", __func__);
			return ret;
		}
		/* FIXME: verify the partition size? */
		unlock_ret_2 = unlock_secure_storage(temp_key);
		if (unlock_ret_2) {
			yield_secure_storage_queues_access();
			return create_ret;
		}
	} else if (unlock_ret) {
		yield_secure_storage_queues_access();
		return unlock_ret;
	}

	/* if new storage, set the key */
	set_key_ret = set_secure_storage_key(secure_storage_key);
	if (set_key_ret) {
		yield_secure_storage_access();
		return set_key_ret;
	}

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

	wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
	wait_until_empty(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);

	SYSCALL_SET_ZERO_ARGS(SYSCALL_DELETE_SECURE_STORAGE)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	return 0;
}

/* FIXME: modified from write_blocks() in os/file_system.c */
int write_secure_storage_blocks(uint8_t *data, uint32_t start_block,
				uint32_t num_blocks)
{
	int i;

	if (!secure_storage_available) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return 0;
	}

	STORAGE_SET_TWO_ARGS(start_block, num_blocks)
	buf[0] = STORAGE_OP_WRITE;
	send_msg_to_storage_no_response(buf);
	for (i = 0; i < (int) num_blocks; i++)
		write_to_storage_data_queue(data + (i * STORAGE_BLOCK_SIZE));
	get_response_from_storage(buf);

	STORAGE_GET_ONE_RET
	return (int) ret0;
}

/* FIXME: modified from read_blocks() in os/file_system.c */
int read_secure_storage_blocks(uint8_t *data, uint32_t start_block,
			       uint32_t num_blocks)
{
	int i;

	if (!secure_storage_available) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return 0;
	}

	STORAGE_SET_TWO_ARGS(start_block, num_blocks)
	buf[0] = STORAGE_OP_READ;
	send_msg_to_storage_no_response(buf);
	for (i = 0; i < (int) num_blocks; i++)
		read_from_storage_data_queue(data + (i * STORAGE_BLOCK_SIZE));
	get_response_from_storage(buf);

	STORAGE_GET_ONE_RET
	return (int) ret0;
}

/* FIXME: modified from read_from_block() in os/file_system.c */
int read_from_secure_storage_block(uint8_t *data, uint32_t block_num,
				   uint32_t block_offset, uint32_t read_size)
{
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int ret;

	if (!secure_storage_available) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return 0;
	}

	if (block_offset + read_size > STORAGE_BLOCK_SIZE)
		return 0;

	ret = read_secure_storage_blocks(buf, block_num, 1);
	if (ret != STORAGE_BLOCK_SIZE)
		return 0;

	memcpy(data, buf + block_offset, read_size);

	return (int) read_size;
}

/* FIXME: modified from write_to_block in os/file_system.c */
int write_to_secure_storage_block(uint8_t *data, uint32_t block_num,
				  uint32_t block_offset, uint32_t write_size)
{
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int ret;

	if (!secure_storage_available) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return 0;
	}

	if (block_offset + write_size > STORAGE_BLOCK_SIZE)
		return 0;

	/* partial block write */
	if (!(block_offset == 0 && write_size == STORAGE_BLOCK_SIZE)) {
		int read_ret = read_secure_storage_blocks(buf, block_num, 1);
		if (read_ret != STORAGE_BLOCK_SIZE)
			return 0;
	}

	memcpy(buf + block_offset, data, write_size);

	ret = write_secure_storage_blocks(buf, block_num, 1);
	/* FIXME: data might have been partially written. */
	if (ret != STORAGE_BLOCK_SIZE)
		return 0;

	return (int) write_size;
}
