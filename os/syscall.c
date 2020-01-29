/* OctopOS syscalls */

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
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/error.h>
#include <os/scheduler.h>
#include <os/ipc.h>
#include <os/shell.h>
#include <os/file_system.h>
#include <os/storage.h>
#include <arch/mailbox_os.h>

#define SYSCALL_SET_ONE_RET(ret0)			\
	buf[0] = RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG;	\
	*((uint32_t *) &buf[1]) = ret0;			\

#define SYSCALL_SET_TWO_RETS(ret0, ret1)		\
	buf[0] = RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG;	\
	*((uint32_t *) &buf[1]) = ret0;			\
	*((uint32_t *) &buf[5]) = ret1;			\

/* FIXME: when calling this one, we need to allocate a ret_buf. Can we avoid that? */
#define SYSCALL_SET_ONE_RET_DATA(ret0, data, size)		\
	buf[0] = RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG;		\
	*((uint32_t *) &buf[1]) = ret0;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 6;		\
	if (max_size < 256 && size <= ((int) max_size)) {	\
		buf[5] = (uint8_t) size;			\
		memcpy(&buf[6], data, size);			\
	} else {						\
		printf("Error: invalid max_size or size\n");	\
		buf[5] = 0;					\
	}							\

#define SYSCALL_GET_ONE_ARG		\
	uint32_t arg0;			\
	arg0 = *((uint32_t *) &buf[2]); \

#define SYSCALL_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	arg0 = *((uint32_t *) &buf[2]); \
	arg1 = *((uint32_t *) &buf[6]); \

#define SYSCALL_GET_THREE_ARGS		\
	uint32_t arg0, arg1, arg2;	\
	arg0 = *((uint32_t *) &buf[2]); \
	arg1 = *((uint32_t *) &buf[6]); \
	arg2 = *((uint32_t *) &buf[10]);\

#define SYSCALL_GET_ZERO_ARGS_DATA				\
	uint8_t data_size, *data;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 3;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data_size = buf[2];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data = &buf[3];						\

#define SYSCALL_GET_ONE_ARG_DATA				\
	uint32_t arg0;						\
	uint8_t data_size, *data;				\
	arg0 = *((uint32_t *) &buf[2]);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 7;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data_size = buf[6];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data = &buf[7];						\

#define SYSCALL_GET_TWO_ARGS_DATA				\
	uint32_t arg0, arg1;					\
	uint8_t data_size, *data;				\
	arg0 = *((uint32_t *) &buf[2]);				\
	arg1 = *((uint32_t *) &buf[6]);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 11;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data_size = buf[10];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data = &buf[11];					\

/* response for async syscalls */
void syscall_read_from_shell_response(uint8_t runtime_proc_id, uint8_t *line, int size)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	SYSCALL_SET_ONE_RET_DATA(0, line, size)
	/* FIXME: we need to send msg to runtime proc that issues the syscall */
	check_avail_and_send_msg_to_runtime(runtime_proc_id, buf);
}

static int storage_create_secure_partition(uint8_t *temp_key, int *partition_id)
{
	STORAGE_SET_ZERO_ARGS_DATA(temp_key, STORAGE_KEY_SIZE) 
	buf[0] = STORAGE_OP_CREATE_SECURE_PARTITION;
	send_msg_to_storage_no_response(buf);
	printf("%s [4]\n", __func__);
	get_response_from_storage(buf);
	printf("%s [5]\n", __func__);
	STORAGE_GET_TWO_RETS
	if (ret0)
		return (int) ret0;

	*partition_id = (int) ret1;
	printf("%s [6]: allocated partition %d\n", __func__, *partition_id);

	return 0;
}

static int storage_delete_secure_partition(int partition_id)
{
	STORAGE_SET_ONE_ARG(partition_id) 
	buf[0] = STORAGE_OP_DELETE_SECURE_PARTITION;
	send_msg_to_storage_no_response(buf);
	get_response_from_storage(buf);
	STORAGE_GET_ONE_RET

	return ret0;
}

static void handle_syscall(uint8_t runtime_proc_id, uint8_t *buf, bool *no_response, int *late_processing)
{
	uint16_t syscall_nr;

	syscall_nr = *((uint16_t *) &buf[0]);
	*no_response = false;

	switch (syscall_nr) {
	case SYSCALL_REQUEST_SECURE_SERIAL_OUT: {
		SYSCALL_GET_ONE_ARG
		uint32_t count = arg0;

		/* No more than 200 characters */
		if (count > 200) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		int ret = is_queue_available(Q_SERIAL_OUT);
		/* Or should we make this blocking? */
		if (!ret) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_AVAILABLE)
			break;
		}

		wait_until_empty(Q_SERIAL_OUT, MAILBOX_QUEUE_SIZE);

		mark_queue_unavailable(Q_SERIAL_OUT);

		mailbox_change_queue_access(Q_SERIAL_OUT, WRITE_ACCESS, runtime_proc_id, (uint8_t) count);
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_REQUEST_SECURE_KEYBOARD: {
		SYSCALL_GET_ONE_ARG
		uint32_t count = arg0;

		/* No more than 100 characters */
		if (count > 100) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		int ret = is_queue_available(Q_KEYBOARD);
		/* Or should we make this blocking? */
		if (!ret) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_AVAILABLE)
			break;
		}

		mark_queue_unavailable(Q_KEYBOARD);

		mailbox_change_queue_access(Q_KEYBOARD, READ_ACCESS, runtime_proc_id, (uint8_t) count);
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_INFORM_OS_OF_TERMINATION: {
		inform_shell_of_termination(runtime_proc_id);
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_INFORM_OS_OF_PAUSE: {
		inform_shell_of_pause(runtime_proc_id);
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_INFORM_OS_RUNTIME_READY: {
		int ret = sched_runtime_ready(runtime_proc_id);
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	case SYSCALL_WRITE_TO_SHELL: {
		int ret;
		SYSCALL_GET_ZERO_ARGS_DATA
		struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
		if (!runtime_proc || !runtime_proc->app) {
			SYSCALL_SET_ONE_RET(ERR_FAULT)
			break;
		}
		
		if (runtime_proc->app->output_dst)
			ret = ipc_send_data(runtime_proc->app, data, (int) data_size);
		else
			ret = app_write_to_shell(runtime_proc->app, data, data_size);
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	case SYSCALL_READ_FROM_SHELL: {
		struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
		if (!runtime_proc || !runtime_proc->app) {
			//FIXME: return Error
		}
	       
		if (runtime_proc->app->input_src) {
			ipc_receive_data(runtime_proc->app);
			*no_response = true;
		} else {
			int ret = app_read_from_shell(runtime_proc->app);
			if (!ret) {
				*no_response = true;
			} else {
				char dummy;
				SYSCALL_SET_ONE_RET_DATA(ret, &dummy, 0);
			}
		}
		break;
	}
	case SYSCALL_OPEN_FILE: {
		SYSCALL_GET_ONE_ARG_DATA
		uint32_t mode = arg0;
		char filename[256];
		if (data_size >= 256) {
			printf("Error: filename is too large\n");
			SYSCALL_SET_ONE_RET(0)
		}
		memcpy(filename, data, data_size);
		/* playing it safe */
		filename[data_size] = '\0';
		uint32_t fd = file_system_open_file(filename, mode);
		SYSCALL_SET_ONE_RET(fd)
		break;
	}
	case SYSCALL_WRITE_TO_FILE: {
		uint32_t ret;
		SYSCALL_GET_TWO_ARGS_DATA
		ret = (uint32_t) file_system_write_to_file(arg0, data, (int) data_size, (int) arg1);
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	case SYSCALL_READ_FROM_FILE: {
		int fs_ret;
		uint32_t ret;
		uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];
		SYSCALL_GET_THREE_ARGS
		int size = (int) arg1;
		/* FIXME: the size info should only be in the corresponding de/marshalling macro. */
		if (size > (MAILBOX_QUEUE_MSG_SIZE - 5)) {
			printf("Error: read size too big. Will truncate\n");
			size = MAILBOX_QUEUE_MSG_SIZE - 5;
		}
		fs_ret = file_system_read_from_file(arg0, ret_buf, size, (int) arg2);
		/* safety check */
		if (fs_ret > size) {
			printf("Error: unexpected return from file_system_read_from_file\n");
			fs_ret = size;
		}
		ret = (uint32_t) fs_ret;
		SYSCALL_SET_ONE_RET_DATA(ret, ret_buf, ret)
		break;
	}
	case SYSCALL_WRITE_FILE_BLOCKS: {
		uint32_t ret;
		SYSCALL_GET_THREE_ARGS
		ret = (uint32_t) file_system_write_file_blocks(arg0, (int) arg1, (int) arg2, runtime_proc_id);
		if (ret)
			*late_processing = SYSCALL_WRITE_FILE_BLOCKS;
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	case SYSCALL_READ_FILE_BLOCKS: {
		uint32_t ret;
		SYSCALL_GET_THREE_ARGS
		ret = (uint32_t) file_system_read_file_blocks(arg0, (int) arg1, (int) arg2, runtime_proc_id);
		if (ret)
			*late_processing = SYSCALL_READ_FILE_BLOCKS;
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	case SYSCALL_CLOSE_FILE: {
		uint32_t ret;
		SYSCALL_GET_ONE_ARG
		ret = (uint32_t) file_system_close_file(arg0);
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	case SYSCALL_REMOVE_FILE: {
		uint32_t ret;
		SYSCALL_GET_ZERO_ARGS_DATA
		char filename[256];
		if (data_size >= 256) {
			printf("Error: filename is too large\n");
			SYSCALL_SET_ONE_RET(0)
		}
		memcpy(filename, data, data_size);
		/* playing it safe */
		filename[data_size] = '\0';
		ret = (uint32_t) file_system_remove_file(filename);
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	case SYSCALL_REQUEST_SECURE_STORAGE_CREATION: {
		printf("%s [1]\n", __func__);
		int sec_partition_id = 0;

		struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
		if (!runtime_proc || !runtime_proc->app) {
			char dummy;
			SYSCALL_SET_ONE_RET_DATA((uint32_t) ERR_FAULT, &dummy, 0)
			break;
		}
		struct app *app = runtime_proc->app;

		/* temp key */
		uint8_t temp_key[STORAGE_KEY_SIZE];
		/* generate a key */
		for (int i = 0; i < STORAGE_KEY_SIZE; i++)
			/* FIXME: use a random number */
			temp_key[i] = runtime_proc_id;

		int ret = storage_create_secure_partition(temp_key, &sec_partition_id);
		if (ret) {
			char dummy;
			SYSCALL_SET_ONE_RET_DATA((uint32_t) ERR_FAULT, &dummy, 0)
			break;
		}
		printf("%s [6]\n", __func__);

		app->sec_partition_id = sec_partition_id;
		app->sec_partition_created = true;

		SYSCALL_SET_ONE_RET_DATA(0, temp_key, STORAGE_KEY_SIZE)
		printf("%s [7]\n", __func__);
		break;
	}
	case SYSCALL_REQUEST_SECURE_STORAGE_ACCESS: {
		SYSCALL_GET_ONE_ARG
		uint32_t count = arg0;
		printf("%s [1]\n", __func__);

		/* FIXME: should we check to see whether we have previously created a partition for this app? */

		/* No more than 200 block reads/writes */
		/* FIXME: hard-coded */
		if (count > 200) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}
		printf("%s [2]\n", __func__);

		int ret_in = is_queue_available(Q_STORAGE_IN_2);
		int ret_out = is_queue_available(Q_STORAGE_OUT_2);
		/* Or should we make this blocking? */
		if (!ret_in || !ret_out) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_AVAILABLE)
			break;
		}
		printf("%s [3]\n", __func__);

		wait_until_empty(Q_STORAGE_IN_2, MAILBOX_QUEUE_SIZE);

		mark_queue_unavailable(Q_STORAGE_IN_2);
		mark_queue_unavailable(Q_STORAGE_OUT_2);

		mailbox_change_queue_access(Q_STORAGE_IN_2, WRITE_ACCESS, runtime_proc_id, (uint8_t) count);
		mailbox_change_queue_access(Q_STORAGE_OUT_2, READ_ACCESS, runtime_proc_id, (uint8_t) count);
		SYSCALL_SET_ONE_RET(0)
		printf("%s [7]\n", __func__);
		break;
	}
	/* FIXME: we also to need to deal with cases that the app does not properly call the delete */
	case SYSCALL_DELETE_SECURE_STORAGE: {
		printf("%s [1]\n", __func__);

		struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
		if (!runtime_proc || !runtime_proc->app) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
			break;
		}
		struct app *app = runtime_proc->app;

		if (!app->sec_partition_created) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		storage_delete_secure_partition(app->sec_partition_id);
		app->sec_partition_created = false;
		app->sec_partition_id = -1;

		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_REQUEST_SECURE_IPC: {
		SYSCALL_GET_TWO_ARGS
		uint8_t target_runtime_queue_id = arg0;
		uint32_t count = arg1;
		uint32_t runtime_queue_id = 0;

		/* No more than 200 block reads/writes */
		if (count > 200) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		if (!is_valid_runtime_queue_id(target_runtime_queue_id)) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		runtime_queue_id = get_runtime_queue_id(runtime_proc_id);
		if (!runtime_queue_id) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
			break;
		}

		int ret1 = is_queue_available(target_runtime_queue_id);
		int ret2 = is_queue_available(runtime_queue_id);
		/* Or should we make this blocking? */
		if (!ret1 || !ret2) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_AVAILABLE)
			break;
		}

		int ret = set_up_secure_ipc(target_runtime_queue_id, runtime_queue_id, runtime_proc_id, count, no_response);
		if (ret) {
			SYSCALL_SET_ONE_RET((uint32_t) ret)
			break;
		}

		if (!(*no_response))
			SYSCALL_SET_ONE_RET(0)
		break;
	}
	default:
		printf("Error: invalid syscall\n");
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		break;
	}
}

void process_system_call(uint8_t *buf, uint8_t runtime_proc_id)
{
	if (runtime_proc_id == P_RUNTIME1 || runtime_proc_id == P_RUNTIME2) {
		bool no_response = false;
		int late_processing = NUM_SYSCALLS;
	
		handle_syscall(runtime_proc_id, buf, &no_response, &late_processing);

		/* send response */
		if (!no_response) {
			check_avail_and_send_msg_to_runtime(runtime_proc_id, buf);
		}

		/* FIXME: use async interrupt processing instead. */
		if (late_processing == SYSCALL_WRITE_FILE_BLOCKS)
			file_system_write_file_blocks_late();
		else if (late_processing == SYSCALL_READ_FILE_BLOCKS)
			file_system_read_file_blocks_late();

	} else {
		printf("Error: invalid syscall caller (%d)\n", runtime_proc_id);
	}
}
