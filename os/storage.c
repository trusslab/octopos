/* OctopOS storage code for the OS
 *
 * This file is used the OS and its bootloader.
 * We use macros ROLE_... to specialize, i.e., to compile only the needed code
 * for each.
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
#include <octopos/io.h>
#include <octopos/error.h>
#include <os/storage.h>
#include <os/scheduler.h>
#include <os/boot.h>
#include <tpm/tpm.h>
#include <arch/mailbox_os.h>

struct partition *partitions;
uint32_t num_partitions = 0;
uint8_t storage_status = OS_ACCESS;
struct app *current_app_with_storage_access = NULL;
struct partition *boot_partition = NULL;
extern struct app untrusted_app;

//uint8_t os_storage_key[STORAGE_KEY_SIZE];
//bool is_partition_locked = true;

//#ifdef ROLE_OS
//uint8_t os_storage_config_key[STORAGE_KEY_SIZE];
//bool is_storage_config_locked = false;
//
//static int set_storage_config_key(uint8_t *key)
//{
//	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
//	buf[0] = STORAGE_OP_SET_CONFIG_KEY;
//	send_msg_to_storage_no_response(buf);
//	get_response_from_storage(buf);
//	STORAGE_GET_ONE_RET
//	return (int) ret0;
//}
//
//static int unlock_storage_config(uint8_t *key)
//{
//	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
//	buf[0] = STORAGE_OP_UNLOCK_CONFIG;
//	send_msg_to_storage_no_response(buf);
//	get_response_from_storage(buf);
//	STORAGE_GET_ONE_RET
//	return (int) ret0;
//}
//
//static int lock_storage_config(void)
//{
//	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
//	buf[0] = STORAGE_OP_LOCK_CONFIG;
//	send_msg_to_storage_no_response(buf);
//	get_response_from_storage(buf);
//	STORAGE_GET_ONE_RET
//	return (int) ret0;
//}
//#endif /* ROLE_OS */
//
///* FIXME: modified from runtime/storage_client.c */
//static int unlock_secure_storage(uint8_t *key)
//{
//	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
//	buf[0] = STORAGE_OP_UNLOCK;
//	send_msg_to_storage_no_response(buf);
//	get_response_from_storage(buf);
//	STORAGE_GET_ONE_RET
//	return (int) ret0;
//}
//
//#ifdef ROLE_OS
///* FIXME: modified from runtime/storage_client.c */
//static int lock_secure_storage(void)
//{
//	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
//	buf[0] = STORAGE_OP_LOCK;
//	send_msg_to_storage_no_response(buf);
//	get_response_from_storage(buf);
//	STORAGE_GET_ONE_RET
//	return (int) ret0;
//}
//#endif

static int query_number_partitions(void)
{
	uint32_t query_type, partition_id;
	uint8_t data[MAILBOX_QUEUE_MSG_SIZE];

	query_type = 0;
	partition_id = 0; /* not used in this query */
	
	STORAGE_SET_TWO_ARGS(query_type, partition_id)
	buf[0] = IO_OP_QUERY_ALL_RESOURCES;
	
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	
	STORAGE_GET_ONE_RET_DATA(data)
	
	if (!ret0) {
		if (_size == 4) {
			memcpy(&num_partitions, data, 4);
			return 0;
		} else {
			printf("Error: %s: unexpected returned data size.\n",
			       __func__);
			return ERR_UNEXPECTED;
		}
	}

	return (int) ret0;
}

static int query_partition(uint32_t partition_id, struct partition *partition)
{
	uint32_t query_type;
	uint8_t data[MAILBOX_QUEUE_MSG_SIZE];

	query_type = 1;
	
	STORAGE_SET_TWO_ARGS(query_type, partition_id)
	buf[0] = IO_OP_QUERY_ALL_RESOURCES;
	
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	
	STORAGE_GET_ONE_RET_DATA(data)
	
	if (ret0)
		return (int) ret0;

	if (_size != (5 + TPM_EXTEND_HASH_SIZE)) {
		printf("Error: %s: unexpected returned data size.\n", __func__);
		return ERR_UNEXPECTED;
	}

	partition->partition_id = partition_id;
	memcpy(&partition->size, data, 4);
	partition->is_created = data[4];

	if (partition->is_created)
		memcpy(partition->key, &data[5], TPM_EXTEND_HASH_SIZE);

	return 0;
}

static int query_storage_partitions(void)
{
	uint32_t i;
	int ret;

	if (partitions) {
		printf("Error: %s: partitions must be NULL\n", __func__);
		return ERR_UNEXPECTED;
	}

	ret = query_number_partitions();
	if (ret) {
		printf("Error: %s: couldn't query the number of partitions\n",
		       __func__);
		return ret;
	}

	/* FIXME: we never free(). */
	partitions = (struct partition *) malloc(num_partitions *
						 sizeof(struct partition));
	if (!partitions) {
		printf("Error: %s: couldn't allocate memory for partitions.\n",
		       __func__);
		return ERR_MEMORY;
	}

	memset(partitions, 0x0, num_partitions * sizeof(struct partition));
	printf("%s [1]: num_partitions = %d\n", __func__, num_partitions);

	for (i = 0; i < num_partitions; i++) {
		ret = query_partition(i, &partitions[i]);
		if (ret) {
			printf("Error: %s: failed to query partition %d\n",
			       __func__, i);
			return ERR_FAULT;
		}
	}

	return 0;
}

/* boot partition is partition 0.
 * Here, we do a sanity check on its size.
 * We can do this check for now since we've fixed the size of the boot
 * partition.
 */
static struct partition *get_boot_partition(void)
{
	/* This shouldn't happen, but we check anyway. */
	if (!partitions) {
		printf("Error: %s: partitions is NULL\n", __func__);
		return NULL;
	}

	if (partitions[0].size != STORAGE_BOOT_PARTITION_SIZE) {
		printf("Error: %s: unexpected size for the boot partition.\n",
		       __func__);
		return NULL;
	}

	return &partitions[0];
}

static int bind_partition(uint32_t partition_id)
{
	STORAGE_SET_ONE_ARG(partition_id)
	buf[0] = IO_OP_BIND_RESOURCE;
	
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	
	STORAGE_GET_ONE_RET
	
	return (int) ret0;
}

static int authenticate_with_storage_service(void)
{
	/* FIXME: use a macro for this. */
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	buf[0] = IO_OP_AUTHENTICATE;
	
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	
	STORAGE_GET_ONE_RET
	printf("%s [1]: ret0 = %d\n", __func__, ret0);
	
	return (int) ret0;
}

#ifdef ROLE_OS
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

/* FIXME: why do we need this ifdef? */
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

//#ifdef ROLE_OS
//	if (is_storage_config_locked) {
//		unlock_storage_config(os_storage_config_key);
//		is_storage_config_locked = false;
//	}
//#endif
//
//	if (is_partition_locked) {
//		unlock_secure_storage(os_storage_key);
//		is_partition_locked = false;
//	}
}
#endif

int wait_for_storage_for_os_use(void)
{
	int ret;

	if (storage_status != OS_USE) {
		if (storage_status == OS_ACCESS) {
			if (!boot_partition) {
				printf("Error: %s: boot partition is NULL\n",
				       __func__);
				return ERR_UNEXPECTED;
			}

			ret = bind_partition(boot_partition->partition_id);
			if (ret) {
				printf("Error: %s: couldn't bind the boot "
				       "partition.\n", __func__);
				return ERR_FAULT;
			}

			ret = authenticate_with_storage_service();
			if (ret) {
				printf("Error: %s: couldn't authenticate with "
				       "the storage service to access the boot "
				       "partition.\n", __func__);
				return ERR_FAULT;
			}

			storage_status = OS_USE;
		} else {
#ifdef ROLE_OS
			if (!boot_partition) {
				printf("Error: %s: boot_partition is NULL "
				       "(else)\n", __func__);
				return ERR_UNEXPECTED;
			}

			wait_for_storage();
			ret = reset_proc_simple(P_STORAGE);
			if (ret) {
				printf("Error: %s: couldn't reset the storage "
				       "service.\n", __func__);
				return ERR_FAULT;
			}

			storage_status = OS_ACCESS;
			
			ret = bind_partition(boot_partition->partition_id);
			if (ret) {
				printf("Error: %s: couldn't bind the boot "
				       "partition (else).\n", __func__);
				return ERR_FAULT;
			}

			ret = authenticate_with_storage_service();
			if (ret) {
				printf("Error: %s: couldn't authenticate with "
				       "the storage service to access the boot "
				       "partition.\n", __func__);
				return ERR_FAULT;
			}

			storage_status = OS_USE;
#else /* ROLE_OS */
			printf("Error: %s: unexpected state.\n", __func__);
			exit(-1);
#endif /* ROLE_OS */
		}
	}

	return 0;
}

#ifdef ROLE_OS	
static int storage_create_secure_partition(uint8_t *app_key,
					   uint8_t runtime_proc_id,
					   uint32_t partition_size,
					   uint32_t *partition_id)
{
	uint32_t i, _partition_id;

	if (runtime_proc_id == P_UNTRUSTED) {
		if ((num_partitions >= 2) &&
		    (partitions[1].size == partition_size) &&
		    !partitions[1].is_created) {
			_partition_id = 1;
		} else {
			printf("Error: %s: couldn't find the proper partition "
			       "for the untrusted domain.\n", __func__);
			return ERR_EXIST;
		}
	} else {
		for (i = 2; i < num_partitions; i++) { 
			if ((partitions[i].size == partition_size) &&
			    !partitions[i].is_created) {
				_partition_id = i;
				break;
			}
		}

		if (i >= num_partitions) {
			printf("Error: %s: couldn't find a proper partition "
			       "for the domain.\n", __func__);
			return ERR_EXIST;
		}
	}

	STORAGE_SET_ONE_ARG_DATA(_partition_id, app_key, TPM_EXTEND_HASH_SIZE)
	buf[0] = IO_OP_CREATE_RESOURCE;
	
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	
	STORAGE_GET_ONE_RET

	if (!ret0) {
		partitions[_partition_id].is_created = 1;
		*partition_id = _partition_id;
	}
	
	return (int) ret0;
}

//static int storage_delete_secure_partition(int partition_id)
//{
//	STORAGE_SET_ONE_ARG(partition_id) 
//	buf[0] = STORAGE_OP_DELETE_SECURE_PARTITION;
//	send_msg_to_storage_no_response(buf);
//	get_response_from_storage(buf);
//	STORAGE_GET_ONE_RET
//
//	return (int) ret0;
//}

void handle_request_secure_storage_creation_syscall(uint8_t runtime_proc_id,
						    uint8_t *buf)
{
	uint32_t sec_partition_id = 0, partition_size, i;
	struct runtime_proc *runtime_proc;
	struct app *app;
	uint8_t app_key[TPM_EXTEND_HASH_SIZE];
	int ret;

	SYSCALL_GET_ONE_ARG
	partition_size = arg0;
	printf("%s [1]: partition_size = %d\n", __func__, partition_size);

	/* sanity check on the requested size:
	 * the root_fs of the untrusted domain should be
	 * the largest partition.
	 */
	if (partition_size > STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE) {
		SYSCALL_SET_TWO_RETS((uint32_t) ERR_INVALID, 0)
		return;
	}

	runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
		SYSCALL_SET_TWO_RETS((uint32_t) ERR_FAULT, 0)
		return;
	}
	
	app = runtime_proc->app;

	/* Let's see if the app already has a partition. */
	if (app->sec_partition_created) {
		SYSCALL_SET_TWO_RETS(0, app->sec_partition_id)
		return;
	}

	ret = tpm_processor_read_pcr(runtime_proc_id, app_key);
	if (ret) {
		printf("Error: %s: couldn't read TPM PCR for runtime proc %d.\n",
		       __func__, runtime_proc_id);
		SYSCALL_SET_TWO_RETS((uint32_t) ERR_FAULT, 0)
		return;
	}

	/* The partition might have been created in previous runs. Therefore,
	 * let's check the query data we received from the storage service too.
	 */
	for (i = 1; i < num_partitions; i++) {
		if (!memcmp(app_key, partitions[i].key, TPM_EXTEND_HASH_SIZE)) {
			app->sec_partition_id = i;
			app->sec_partition_created = true;
			SYSCALL_SET_TWO_RETS(0, i)
			printf("%s [2]: found an existing partition (%d)\n", __func__, i);
			return;
		}
	}
	printf("%s [3]: need to create a new partition\n", __func__);

	if (storage_status != OS_ACCESS) {
		if (storage_status == OS_USE) {
			ret = reset_proc_simple(P_STORAGE);
			if (ret) {
				printf("Error: %s: couldn't reset the storage "
				       "service.\n", __func__);
				SYSCALL_SET_TWO_RETS((uint32_t) ERR_FAULT, 0)
				return;
			}
			storage_status = OS_ACCESS;
		} else {
			wait_for_storage();
			ret = reset_proc_simple(P_STORAGE);
			if (ret) {
				printf("Error: %s: couldn't reset the storage "
				       "service (2).\n", __func__);
				SYSCALL_SET_TWO_RETS((uint32_t) ERR_FAULT, 0)
				return;
			}
			storage_status = OS_ACCESS;
		}
	}

	ret = storage_create_secure_partition(app_key, runtime_proc_id,
					      partition_size, &sec_partition_id);
	if (ret) {
		SYSCALL_SET_TWO_RETS((uint32_t) ERR_FAULT, 0)
		return;
	}

	app->sec_partition_id = sec_partition_id;
	app->sec_partition_created = true;

	SYSCALL_SET_TWO_RETS(0, sec_partition_id)
}

void handle_request_secure_storage_access_syscall(uint8_t runtime_proc_id,
						  uint8_t *buf)
{
	uint32_t limit, timeout;
	struct runtime_proc *runtime_proc;
	struct app *app;
	int ret;
	int no_reset = 0;

	SYSCALL_GET_TWO_ARGS
	limit = arg0;
	timeout = arg1;

	if (limit > MAILBOX_MAX_LIMIT_VAL) {
		printf("Error: %s: limit (%d) too large\n", __func__, limit);
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		return;
	}

	runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
		return;
	}

	app = runtime_proc->app;

	if (!app->sec_partition_created) {
		printf("Error: %s: app does not have a secure storage "
		       "partition.\n", __func__);
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

	if ((storage_status == APP_ACCESS) &&
	    (current_app_with_storage_access == app)) {
		if (is_queue_available(Q_STORAGE_CMD_IN) &&
		    is_queue_available(Q_STORAGE_CMD_OUT) &&
		    is_queue_available(Q_STORAGE_DATA_IN) &&
		    is_queue_available(Q_STORAGE_DATA_OUT)) {
			/* This can happen, for example, when the untrusted
			 * domain uses up its quota and asks for access again.
			 *
			 * FIXME: there's a race condition here. The syscall
			 * request might get to us before we handle the
			 * change-of-ownership interrupts from these queues.
			 */

			/* This is an optimization so that we don't reset the
			 * storage service again and again when it is being
			 * used by the untrusted domain.
			 */ 
			if (app == &untrusted_app)
				no_reset = 1;
		} else {
			printf("Error: %s: app already has access to the "
			       "storage queues.\n", __func__);
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			return;
		}
	}

	if ((storage_status != OS_ACCESS) && !no_reset) {
		if (storage_status == OS_USE) {
			ret = reset_proc_simple(P_STORAGE);
			if (ret) {
				printf("Error: %s: couldn't reset the storage "
				       "service.\n", __func__);
				SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
				return;
			}
			current_app_with_storage_access = app;
			storage_status = APP_ACCESS;
		} else {
			wait_for_storage();
			ret = reset_proc_simple(P_STORAGE);
			if (ret) {
				printf("Error: %s: couldn't reset the storage "
				       "service (2).\n", __func__);
				SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
				return;
			}
		}
	}

	current_app_with_storage_access = app;
	storage_status = APP_ACCESS;

	if (!no_reset) {
		ret = bind_partition(app->sec_partition_id);
		if (ret) {
			printf("Error: %s: couldn't bind the storage service "
			       "to partition (%d).\n", __func__,
			       app->sec_partition_id);
			SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
			return;
		}
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
//
//void handle_delete_secure_storage_syscall(uint8_t runtime_proc_id,
//					  uint8_t *buf)
//{
//	//struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
//	//if (!runtime_proc || !runtime_proc->app) {
//	//	SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
//	//	return;
//	//}
//	//struct app *app = runtime_proc->app;
//
//	//if (!app->sec_partition_created) {
//	//	SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
//	//	return;
//	//}
//
//	//wait_for_storage();
//	//storage_delete_secure_partition(app->sec_partition_id);
//	//app->sec_partition_created = false;
//	//app->sec_partition_id = -1;
//
//	//SYSCALL_SET_ONE_RET(0)
//}
#endif /* ROLE_OS */

uint32_t initialize_storage(void)
{
	int ret;
	printf("%s [1]\n", __func__);

#ifdef ROLE_OS
	/* The bootloader has already used the partition. */
	ret = reset_proc_simple(P_STORAGE);
	if (ret) {
		printf("Error: %s: couldn't reset the storage service.\n",
		       __func__);
		exit(-1);
	}
	printf("%s [2]\n", __func__);
#endif

	ret = query_storage_partitions();
	if (ret) {
		printf("Error: %s: couldn't successfully query storage "
		       "partitions\n", __func__);
		exit(-1);
	}
	printf("%s [3]\n", __func__);

	boot_partition = get_boot_partition();
	if (!boot_partition) {
		printf("Error: %s: couldn't find the boot partition.\n",
		       __func__);
		exit(-1);
	}
	printf("%s [4]\n", __func__);

	if (!boot_partition->is_created) {
		printf("Error: %s: boot partition isn't created.\n", __func__);
		exit(-1);
	}
	printf("%s [5]\n", __func__);

	storage_status = OS_USE;

	ret = bind_partition(boot_partition->partition_id);
	if (ret) {
		printf("Error: %s: couldn't bind the boot partition.\n",
		       __func__);
		exit(-1);
	}
	printf("%s [6]\n", __func__);

	ret = authenticate_with_storage_service();
	if (ret) {
		printf("Error: %s: couldn't authenticate with the storage "
		       "service to access the boot partition.\n", __func__);
		exit(-1);
	}
	printf("%s [7]: boot_partition->size = %d\n", __func__, boot_partition->size);

	return boot_partition->size;
}
