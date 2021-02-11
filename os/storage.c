/* OctopOS storage code for the OS
 *
 * This file is used the OS and its bootloader.
 * We use macros ROLE_... to specialize, i.e., to compile only the needed code for each.
 */
#include <arch/defines.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/syscall.h>
#include <octopos/error.h>
#include <os/storage.h>
#include <os/scheduler.h>
#include <arch/mailbox_os.h>

uint8_t os_storage_key[STORAGE_KEY_SIZE];
bool is_partition_locked = true;

#ifdef ROLE_OS
uint8_t os_storage_config_key[STORAGE_KEY_SIZE];
bool is_storage_config_locked = false;

static int set_storage_config_key(uint8_t *key)
{
	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
	buf[0] = STORAGE_OP_SET_CONFIG_KEY;
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int unlock_storage_config(uint8_t *key)
{
	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
	buf[0] = STORAGE_OP_UNLOCK_CONFIG;
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int lock_storage_config(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	buf[0] = STORAGE_OP_LOCK_CONFIG;
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}
#endif /* ROLE_OS */

/* FIXME: modified from runtime/storage_client.c */
static int unlock_secure_storage(uint8_t *key)
{
	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
	buf[0] = STORAGE_OP_UNLOCK;
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

#ifdef ROLE_OS
/* FIXME: modified from runtime/storage_client.c */
static int lock_secure_storage(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	buf[0] = STORAGE_OP_LOCK;
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}
#endif

static int storage_create_secure_partition(uint8_t *temp_key, int *partition_id,
					   uint32_t partition_size)
{
	STORAGE_SET_ONE_ARG_DATA(partition_size, temp_key, STORAGE_KEY_SIZE) 
	buf[0] = STORAGE_OP_CREATE_SECURE_PARTITION;
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	STORAGE_GET_TWO_RETS
	if (ret0)
		return (int) ret0;

	*partition_id = (int) ret1;

	return 0;
}

#ifdef ROLE_OS
static int storage_delete_secure_partition(int partition_id)
{
	STORAGE_SET_ONE_ARG(partition_id) 
	buf[0] = STORAGE_OP_DELETE_SECURE_PARTITION;
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	STORAGE_GET_ONE_RET

	return (int) ret0;
}

void handle_request_secure_storage_creation_syscall(uint8_t runtime_proc_id,
						    uint8_t *buf)
{
	SYSCALL_GET_ONE_ARG
	uint32_t partition_size = arg0;

	/* sanity check on the requested size:
	 * the root_fs of the untrusted domain should be
	 * the largest partition.
	 */
	if (partition_size > STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE) {
		char dummy;
		SYSCALL_SET_ONE_RET_DATA((uint32_t) ERR_INVALID, &dummy, 0)
		return;
	}

	int sec_partition_id = 0;

	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
		char dummy;
		SYSCALL_SET_ONE_RET_DATA((uint32_t) ERR_FAULT, &dummy, 0)
		return;
	}
	struct app *app = runtime_proc->app;

	/* temp key */
	uint8_t temp_key[STORAGE_KEY_SIZE];
	/* generate a key */
	for (int i = 0; i < STORAGE_KEY_SIZE; i++)
		/* FIXME: use a random number */
		temp_key[i] = runtime_proc_id;

	wait_for_storage();
	int ret = storage_create_secure_partition(temp_key, &sec_partition_id,
						  partition_size);
	if (ret) {
		char dummy;
		SYSCALL_SET_ONE_RET_DATA((uint32_t) ERR_FAULT, &dummy, 0)
		return;
	}

	app->sec_partition_id = sec_partition_id;
	app->sec_partition_created = true;

	SYSCALL_SET_ONE_RET_DATA(0, temp_key, STORAGE_KEY_SIZE)
}

void handle_request_secure_storage_access_syscall(uint8_t runtime_proc_id,
						  uint8_t *buf)
{
	SYSCALL_GET_TWO_ARGS
	uint32_t limit = arg0;
	uint32_t timeout = arg1;

	/* FIXME: should we check to see whether we have previously created a partition for this app? */

	if (limit > MAILBOX_MAX_LIMIT_VAL) {
		printf("Error: %s: limit (%d) too large\n", __func__, limit);
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		return;
	}

	if (runtime_proc_id == P_UNTRUSTED) {
		/* The untrusted domain uses the storage domain frequently.
		 * We limit its usage to MAILBOX_DEFAULT_TIMEOUT_VAL per
		 * request in order not to starve other domains.
		 */
		if (timeout > MAILBOX_DEFAULT_TIMEOUT_VAL) {
			printf("Error: %s: timeout (%d) too large for the "
			       "untrusted domain\n", __func__, timeout);
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			return;
		}
	} else {
		if (timeout > 100) {
			printf("Error: %s: timeout (%d) too large\n", __func__,
			       timeout);
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			return;
		}
	}

	wait_for_storage();

	if (!is_partition_locked) {
		int ret = lock_secure_storage();
		if (ret) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
			return;
		}
		is_partition_locked = true;
	}

	if (!is_storage_config_locked) {
		int ret = lock_storage_config();
		if (ret) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
			return;
		}
		is_storage_config_locked = true;
	}

	wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
	wait_until_empty(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

	mark_queue_unavailable(Q_STORAGE_CMD_IN);
	mark_queue_unavailable(Q_STORAGE_CMD_OUT);
	mark_queue_unavailable(Q_STORAGE_DATA_IN);
	mark_queue_unavailable(Q_STORAGE_DATA_OUT);

	mailbox_delegate_queue_access(Q_STORAGE_CMD_IN, runtime_proc_id,
				      (limit_t) limit, (timeout_t) timeout);
	mailbox_delegate_queue_access(Q_STORAGE_CMD_OUT, runtime_proc_id,
				      (limit_t) limit, (timeout_t) timeout);
	mailbox_delegate_queue_access(Q_STORAGE_DATA_IN, runtime_proc_id,
				      (limit_t) limit, (timeout_t) timeout);
	mailbox_delegate_queue_access(Q_STORAGE_DATA_OUT, runtime_proc_id,
				      (limit_t) limit, (timeout_t) timeout);

	SYSCALL_SET_ONE_RET(0)
}

void handle_delete_secure_storage_syscall(uint8_t runtime_proc_id,
					  uint8_t *buf)
{
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
		return;
	}
	struct app *app = runtime_proc->app;

	if (!app->sec_partition_created) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		return;
	}

	wait_for_storage();
	storage_delete_secure_partition(app->sec_partition_id);
	app->sec_partition_created = false;
	app->sec_partition_id = -1;

	SYSCALL_SET_ONE_RET(0)
}
#endif /* ROLE_OS */

/*
 * Check that all queues are available and that the partition is unlocked.
 */
void wait_for_storage(void)
{
	int ret = is_queue_available(Q_STORAGE_CMD_IN);
	if (!ret) {
		wait_for_queue_availability(Q_STORAGE_CMD_IN);
	}

	ret = is_queue_available(Q_STORAGE_CMD_OUT);
	if (!ret) {
		wait_for_queue_availability(Q_STORAGE_CMD_OUT);
	}

#ifdef ROLE_OS	
	ret = is_queue_available(Q_STORAGE_DATA_IN);
	if (!ret) {
		wait_for_queue_availability(Q_STORAGE_DATA_IN);
	}
#endif

	ret = is_queue_available(Q_STORAGE_DATA_OUT);
	if (!ret) {
		wait_for_queue_availability(Q_STORAGE_DATA_OUT);
	}

#ifdef ROLE_OS
	if (is_storage_config_locked) {
		unlock_storage_config(os_storage_config_key);
		is_storage_config_locked = false;
	}
#endif

	if (is_partition_locked) {
		unlock_secure_storage(os_storage_key);
		is_partition_locked = false;
	}
}

uint32_t initialize_storage(void)
{
	uint32_t partition_size = STORAGE_BOOT_PARTITION_SIZE;

	for (int i = 0; i < STORAGE_KEY_SIZE; i++)
		os_storage_key[i] = i + 3;

#ifdef ROLE_OS
	for (int i = 0; i < STORAGE_KEY_SIZE; i++)
		os_storage_config_key[i] = i + 4;

	set_storage_config_key(os_storage_config_key);
#endif

	/* unlock the storage (mainly needed to deal with reset-related interruptions.
	 * won't do anything if it's the first time accessing the secure storage) */
	int unlock_ret = unlock_secure_storage(os_storage_key);
	if (unlock_ret == ERR_EXIST) {
		int unused_partition_id;
		int create_ret = storage_create_secure_partition(os_storage_key,
						&unused_partition_id, partition_size);
		if (create_ret) {
			printf("Error (%s): couldn't initialize the storage partition for the OS.\n",
											__func__);
			exit(-1);
		}
		/* FIXME: verify the partition size? */
		int unlock_ret_2 = unlock_secure_storage(os_storage_key);
		if (unlock_ret_2) {
			printf("Error (%s): couldn't unlock the storage partition for the OS.\n",
											__func__);
			exit(-1);
		}
	} else if (unlock_ret) {
		printf("Error (%s): unexpected response from the storage response.\n", __func__);
		exit(-1);
	}
	is_partition_locked = false;

	return partition_size;
}
