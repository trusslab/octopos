/* octopos storage client */
#if !defined(CONFIG_UML) && !defined(CONFIG_ARM64) /* !(Linux UML or Secure HW) */
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
#include <octopos/io.h>
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
	DESERIALIZE_32(&ret0, &buf[0]);			\

#define STORAGE_GET_TWO_RETS				\
	uint32_t ret0, ret1;				\
	DESERIALIZE_32(&ret0, &buf[0]);			\
	DESERIALIZE_32(&ret1, &buf[4]);			\

#define STORAGE_GET_ONE_RET_DATA(data)						\
	uint32_t ret0;								\
	uint8_t _size, max_size = MAILBOX_QUEUE_MSG_SIZE - 5;			\
	DESERIALIZE_32(&ret0, &buf[0]);						\
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

bool secure_storage_created = false;
uint32_t secure_partition_id = 0;
bool has_access_to_secure_storage = false;

bool context_set = false;
void *context_addr = NULL;
uint32_t context_size = 0;
uint32_t context_tag = 0xDEADBEEF;
#define CONTEXT_TAG_SIZE	4

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

static int deauthenticate_storage(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	buf[0] = IO_OP_DEAUTHENTICATE;

	send_msg_to_storage(buf);
	
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int authenticate_storage(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	buf[0] = IO_OP_AUTHENTICATE;

	send_msg_to_storage(buf);
	
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int query_and_verify_storage(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t data[MAILBOX_QUEUE_MSG_SIZE];

	buf[0] = IO_OP_QUERY_STATE;

	send_msg_to_storage(buf);
	
	STORAGE_GET_ONE_RET_DATA(data)
	if (ret0) {
		printf("Error: %s: couldn't query the state of the storage "
		       "service.\n", __func__);
		return (int) ret0;
	}

	if (_size != 5) {
		printf("Error: %s: unexpected state query size (%d).\n",
		       __func__, _size);
		return ERR_UNEXPECTED;
	}

#ifndef UNTRUSTED_DOMAIN
	if ((data[0] != 1) || (data[1] != 0) || (data[2] != 0) ||
	    (data[3] != secure_partition_id) || (data[4] != 1)) {
		printf("Error: %s: couldn't successfully verify the query "
		       "response from the storage service (bound = %d, "
		       "used = %d, authenticated = %d, bound_partition = %d, "
		       "is_created = %d).\n", __func__, data[0], data[1],
		       data[2], data[3], data[4]);
		return ERR_FAULT;
	}
#else
	/* For the untrusted domain, we don't check the "used" status.
	 * This is an optimization for the untrusted domain. We allow it to
	 * continue using the storage service without a reset. The OS assists
	 * in this optimization (in handle_request_secure_storage_access_syscall().
	 * Note that we still check for "authenticated". This is because before
	 * yielding the storage access, the untrusted domain deauthenticates.
	 */
	if ((data[0] != 1) || (data[2] != 0) ||
	    (data[3] != secure_partition_id) || (data[4] != 1)) {
		printf("Error: %s: couldn't successfully verify the query "
		       "response from the storage service (bound = %d, "
		       "authenticated = %d, bound_partition = %d, is_created = "
		       "%d).\n", __func__, data[0], data[2], data[3], data[4]);
		return ERR_FAULT;
	}
#endif

	return 0;
}

static int destroy_storage(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	buf[0] = IO_OP_DESTROY_RESOURCE;

	send_msg_to_storage(buf);
	
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int request_secure_storage_creation(uint32_t size)
{
	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_SECURE_STORAGE_CREATION, size)
	issue_syscall(buf);
	SYSCALL_GET_TWO_RETS
	
	if (!ret0) {
		secure_storage_created = true;
		secure_partition_id = ret1;
	}

	return (int) ret0;
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
	int ret;

	if (!has_access_to_secure_storage) {
		return ERR_INVALID;
	}

	ret = deauthenticate_storage();
	if (ret) {
		printf("%s: Error: failed to deauthenticate with the storage "
		       "service\n", __func__);
		return ERR_FAULT;
	}

	has_access_to_secure_storage = false;

	yield_secure_storage_queues_access();

	return 0;
}

/* @expected_pcr: if not NULL, we request the PCR val for the storage service
 * and compare it with expected_pcr.
 * @return_pcr: if expected_pcr is NULL but return_pcr is not, we'll request
 * and return the PCR val for the storage service. This is useful because the
 * app might not have the expected value when it first asks for storage access.
 * It can get the measured value here and compare it with the expected value
 * later.
 *
 * FIXME: @callback, @expected_pcr, and @return_ocr can be set by the untrusted
 * domain, but they're no ops.
 */
static int request_secure_storage_queues_access(limit_t limit,
						timeout_t timeout,
						queue_update_callback_t callback,
						uint8_t *expected_pcr,
						uint8_t *return_pcr)
{
	int ret;

	if (!secure_storage_created) {
		printf("Error: %s: secure storage not created.\n", __func__);
		return ERR_INVALID;
	}

	reset_queue_sync(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
	reset_queue_sync(Q_STORAGE_CMD_OUT, 0);
	reset_queue_sync(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
	reset_queue_sync(Q_STORAGE_DATA_OUT, 0);

	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_SECURE_STORAGE_ACCESS,
			     (uint32_t) limit, (uint32_t) timeout)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0) {
		return (int) ret0;
	}

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

#ifndef ARCH_SEC_HW
	if (expected_pcr) {
		ret = check_proc_pcr(P_STORAGE, expected_pcr);
		if (ret) {
			printf("%s: Error: unexpected PCR\n", __func__);
			ret = ERR_UNEXPECTED;
			goto error;
		}
	} else if (return_pcr) {
		ret = read_tpm_pcr_for_proc(P_STORAGE, return_pcr);
		if (ret) {
			printf("%s: Error: couldn't read PCR\n", __func__);
			ret = ERR_FAULT;
			goto error;
		}
	}
#endif
	
	queue_update_callbacks[Q_STORAGE_CMD_IN] = callback;
	queue_update_callbacks[Q_STORAGE_CMD_OUT] = callback;
	queue_update_callbacks[Q_STORAGE_DATA_IN] = callback;
	queue_update_callbacks[Q_STORAGE_DATA_OUT] = callback;
#endif

	ret = query_and_verify_storage();
	if (ret) {
		printf("%s: Error: couldn't query and verify access to the "
		       "storage service\n", __func__);
		ret = ERR_UNEXPECTED;
		goto error;
	}

	ret = authenticate_storage();
	if (ret) {
		printf("%s: Error: couldn't authenticate with the storage "
		       "service\n", __func__);
		ret = ERR_UNEXPECTED;
		goto error;
	}

	has_access_to_secure_storage = true;

	return 0;

error:
	wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
	wait_until_empty(Q_STORAGE_DATA_IN,
			 MAILBOX_QUEUE_SIZE_LARGE);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);

#ifndef UNTRUSTED_DOMAIN
	queue_limits[Q_STORAGE_CMD_IN] = 0;
	queue_timeouts[Q_STORAGE_CMD_IN] = 0;
	queue_limits[Q_STORAGE_CMD_OUT] = 0;
	queue_timeouts[Q_STORAGE_CMD_OUT] = 0;
	queue_limits[Q_STORAGE_DATA_IN] = 0;
	queue_timeouts[Q_STORAGE_DATA_IN] = 0;
	queue_limits[Q_STORAGE_DATA_OUT] = 0;
	queue_timeouts[Q_STORAGE_DATA_OUT] = 0;
#endif

	return ret;
}

/*
 * partiton_size will be only used if no partition is already created and a new
 * one needs to be created.
 */
int request_secure_storage_access(uint32_t partition_size,
				  limit_t limit, timeout_t timeout,
				  queue_update_callback_t callback,
				  uint8_t *expected_pcr, uint8_t *return_pcr)
{
	int ret;

	ret = request_secure_storage_creation(partition_size);
	if (ret) {
		printf("%s: Error: request for secure storage creation "
		       "failed.\n", __func__);
		return ret;
	}

	ret = request_secure_storage_queues_access(limit, timeout,
				callback, expected_pcr, return_pcr);	
	if (ret) {
		printf("%s: Error: couldn't gain access to storage "
		       "queues.\n", __func__);
		return ret;
	}
	
	return 0;
}

int delete_and_yield_secure_storage(void)
{
	int ret;

	if (!has_access_to_secure_storage) {
		printf("Error: %s: no access to secure storage.\n", __func__);
		return ERR_INVALID;
	}

	/* wipe storage content */
	ret = destroy_storage();
	if (ret) {
		printf("Error: %s: couldn't destroy/wipe storage partition.\n",
		       __func__);
	}

	secure_storage_created = false;
	has_access_to_secure_storage = false;

	wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
	wait_until_empty(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);

	return 0;
}

/* FIXME: modified from write_blocks() in os/file_system.c */
int write_secure_storage_blocks(uint8_t *data, uint32_t start_block,
				uint32_t num_blocks)
{
	int i;

	if (!has_access_to_secure_storage) {
		printf("%s: Error: secure storage has not been set up\n",
		       __func__);
		return 0;
	}

	STORAGE_SET_TWO_ARGS(start_block, num_blocks)
	buf[0] = IO_OP_SEND_DATA;
	send_msg_to_storage_no_response(buf);
	for (i = 0; i < (int) num_blocks; i++)
		write_to_storage_data_queue(data + (i * STORAGE_BLOCK_SIZE));
	get_response_from_storage(buf);

	STORAGE_GET_TWO_RETS
	if (ret0) {
		printf("Error: %s: storage service returned error (%d).\n",
		       __func__, (int) ret0);
		return 0;
	}

	return (int) ret1; /* size */
}

/* FIXME: modified from read_blocks() in os/file_system.c */
int read_secure_storage_blocks(uint8_t *data, uint32_t start_block,
			       uint32_t num_blocks)
{
	int i;

	if (!has_access_to_secure_storage) {
		printf("%s: Error: secure storage has not been set up\n",
		       __func__);
		return 0;
	}

	STORAGE_SET_TWO_ARGS(start_block, num_blocks)
	buf[0] = IO_OP_RECEIVE_DATA;
	send_msg_to_storage_no_response(buf);
	for (i = 0; i < (int) num_blocks; i++)
		read_from_storage_data_queue(data + (i * STORAGE_BLOCK_SIZE));
	get_response_from_storage(buf);

	STORAGE_GET_TWO_RETS
	if (ret0) {
		printf("Error: %s: storage service returned error (%d).\n",
		       __func__, (int) ret0);
		return 0;
	}

	return (int) ret1; /* size */
}

/* FIXME: modified from read_from_block() in os/file_system.c */
int read_from_secure_storage_block(uint8_t *data, uint32_t block_num,
				   uint32_t block_offset, uint32_t read_size)
{
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int ret;

	if (!has_access_to_secure_storage) {
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

	if (!has_access_to_secure_storage) {
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

/* FIXME: bad and complex API. */
int set_up_context(void *addr, uint32_t size, int do_yield, int *context_found,
		   uint32_t partition_size, limit_t limit, timeout_t timeout,
		   queue_update_callback_t callback, uint8_t *expected_pcr,
		   uint8_t *return_pcr)
{
	uint8_t context_block[STORAGE_BLOCK_SIZE];
	if (size > (STORAGE_BLOCK_SIZE - CONTEXT_TAG_SIZE)) {
		printf("Error (%s): context size is too big.\n", __func__);
		return ERR_INVALID;
	}

	context_addr = addr;
	context_size = size;
	context_set = true;
	if (context_found)
		*context_found = 0;
	/* Now, let's retrieve the context. */
	int ret = request_secure_storage_access(partition_size, limit, timeout,
						callback, expected_pcr,
						return_pcr);
	if (ret) {
		printf("Error (%s): Failed to get secure access to storage.\n",
		       __func__);
		return ret;
	}

	uint32_t rret = read_from_secure_storage_block(context_block, 0, 0,
						context_size + CONTEXT_TAG_SIZE);
	if (rret != (context_size + CONTEXT_TAG_SIZE)) {
		printf("%s: Couldn't read from secure storage.\n", __func__);
		goto no_context;
	}

	if ((*(uint32_t *) context_block) != context_tag) {
		printf("%s: No context to use.\n", __func__);
		goto no_context;
	}

	memcpy(context_addr, &context_block[CONTEXT_TAG_SIZE], context_size);
	if (context_found)
		*context_found = 1;

no_context:
	if (do_yield)
		yield_secure_storage_access();

	return 0;
}

int write_context_to_storage(int do_yield)
{
	uint8_t context_block[STORAGE_BLOCK_SIZE];

	if (!has_access_to_secure_storage || !context_set) {
		printf("%s: Error: either the secure storage key or context "
		       "not set or secure storage not previously set up\n",
		       __func__);
		return ERR_INVALID;
	}

#if defined(ARCH_SEC_HW) && !defined(CONFIG_ARM64)
	async_syscall_mode = true;
#endif

	memcpy(context_block, &context_tag, CONTEXT_TAG_SIZE);
	memcpy(&context_block[CONTEXT_TAG_SIZE], context_addr, context_size);

	uint32_t wret = write_to_secure_storage_block(context_block, 0, 0,
						context_size + CONTEXT_TAG_SIZE);
	if (wret != (context_size + CONTEXT_TAG_SIZE))
		printf("Error: couldn't write the context to secure storage.\n");

	yield_secure_storage_access();

	return 0;
}


