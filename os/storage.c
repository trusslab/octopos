/* OctopOS storage client for the OS */
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

/* FIXME: modified from runtime/storage_client.c */
static int unlock_secure_storage(uint8_t *key)
{
	printf("%s [1]\n", __func__);
	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
	buf[0] = STORAGE_OP_UNLOCK;
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

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

	/* sanity check on the requested size */
	/* FIXME: hard-coded */
	if (partition_size > 2048) {
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
	SYSCALL_GET_ONE_ARG
	uint32_t count = arg0;

	/* FIXME: should we check to see whether we have previously created a partition for this app? */

	/* No more than 200 block reads/writes */
	/* FIXME: hard-coded */
	if (count > 200) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		return;
	}

	/* Or should we make this blocking? */
	if (!is_queue_available(Q_STORAGE_CMD_IN) ||
	    !is_queue_available(Q_STORAGE_CMD_OUT) ||
	    !is_queue_available(Q_STORAGE_DATA_IN) ||
	    !is_queue_available(Q_STORAGE_DATA_OUT)) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_AVAILABLE)
		return;
	}

	if (!is_partition_locked) {
		int ret = lock_secure_storage();
		if (ret) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
			return;
		}
		is_partition_locked = true;
	}

	wait_until_empty(Q_STORAGE_CMD_IN, MAILBOX_QUEUE_SIZE);
	wait_until_empty(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

	mark_queue_unavailable(Q_STORAGE_CMD_IN);
	mark_queue_unavailable(Q_STORAGE_CMD_OUT);
	mark_queue_unavailable(Q_STORAGE_DATA_IN);
	mark_queue_unavailable(Q_STORAGE_DATA_OUT);

#ifdef ARCH_SEC_HW
	mailbox_change_queue_access(Q_STORAGE_CMD_IN, WRITE_ACCESS, runtime_proc_id, (uint16_t) count);
	mailbox_change_queue_access(Q_STORAGE_CMD_OUT, READ_ACCESS, runtime_proc_id, (uint16_t) count);
	mailbox_change_queue_access(Q_STORAGE_DATA_IN, WRITE_ACCESS, runtime_proc_id, (uint16_t) count);
	mailbox_change_queue_access(Q_STORAGE_DATA_OUT, READ_ACCESS, runtime_proc_id, (uint16_t) count);
#else
	mailbox_change_queue_access(Q_STORAGE_CMD_IN, WRITE_ACCESS, runtime_proc_id, (uint8_t) count);
	mailbox_change_queue_access(Q_STORAGE_CMD_OUT, READ_ACCESS, runtime_proc_id, (uint8_t) count);
	mailbox_change_queue_access(Q_STORAGE_DATA_IN, WRITE_ACCESS, runtime_proc_id, (uint8_t) count);
	mailbox_change_queue_access(Q_STORAGE_DATA_OUT, READ_ACCESS, runtime_proc_id, (uint8_t) count);
#endif

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

	storage_delete_secure_partition(app->sec_partition_id);
	app->sec_partition_created = false;
	app->sec_partition_id = -1;

	SYSCALL_SET_ONE_RET(0)
}

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
	
	ret = is_queue_available(Q_STORAGE_DATA_IN);
	if (!ret) {
		wait_for_queue_availability(Q_STORAGE_DATA_IN);
	}
	
	ret = is_queue_available(Q_STORAGE_DATA_OUT);
	if (!ret) {
		wait_for_queue_availability(Q_STORAGE_DATA_OUT);
	}

	if (is_partition_locked) {
		unlock_secure_storage(os_storage_key);
		is_partition_locked = false;
	}
}

void initialize_storage_partition(void)
{
	for (int i = 0; i < STORAGE_KEY_SIZE; i++)
		os_storage_key[i] = i + 3;
	/* unlock the storage (mainly needed to deal with reset-related interruptions.
	 * won't do anything if it's the first time accessing the secure storage) */
	int unlock_ret = unlock_secure_storage(os_storage_key);
	printf("%s [6]\n", __func__);
	if (unlock_ret == ERR_EXIST) {
		printf("%s [7]\n", __func__);
		int unused_partition_id;
		int create_ret = storage_create_secure_partition(os_storage_key,
						&unused_partition_id, 1000);
		if (create_ret) {
			printf("Error (%s): couldn't initialize the storage partition for the OS.\n",
											__func__);
			exit(-1);
		}
		/* FIXME: verify the partition size? */
		printf("%s [7.1]\n", __func__);
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
	printf("%s [8]\n", __func__);
}
