/* OctopOS syscalls */
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
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/io.h>
#include <octopos/storage.h>
#include <octopos/bluetooth.h>
#include <octopos/error.h>
#include <os/scheduler.h>
#include <os/ipc.h>
#include <os/shell.h>
#include <os/file_system.h>
#include <os/storage.h>
#ifndef ARCH_SEC_HW
#include <os/network.h>
#endif
#include <os/boot.h>
#include <arch/mailbox_os.h>

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

static void handle_syscall(uint8_t runtime_proc_id, uint8_t *buf, bool *no_response, int *late_processing)
{
	uint16_t syscall_nr;

	syscall_nr = *((uint16_t *) &buf[0]);
	*no_response = false;

#ifdef ARCH_SEC_HW
	_SEC_HW_DEBUG("syscall %d received from %d", syscall_nr, runtime_proc_id);
#endif

	switch (syscall_nr) {
	case SYSCALL_REQUEST_SECURE_SERIAL_OUT: {
		SYSCALL_GET_TWO_ARGS
		uint32_t limit = arg0;
		uint32_t timeout = arg1;

		/* FIXME: arbitrary thresholds */
		/* No more than 1000 characters; no more than 100 seconds */
		if (limit > 1000 || timeout > 100) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		int ret = is_queue_available(Q_SERIAL_OUT);
		/* Or should we make this blocking? */
		if (!ret) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_AVAILABLE)
			break;
		}

		/* ARCH_SEC_HW does not check on send queue availability
		 * because it already blocks on send. */
		wait_until_empty(Q_SERIAL_OUT, MAILBOX_QUEUE_SIZE);

		mark_queue_unavailable(Q_SERIAL_OUT);

		mailbox_delegate_queue_access(Q_SERIAL_OUT, runtime_proc_id,
					      (limit_t) limit,
					      (timeout_t) timeout);

		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_REQUEST_SECURE_KEYBOARD: {
		SYSCALL_GET_TWO_ARGS
		uint32_t limit = arg0;
		uint32_t timeout = arg1;
		printf("%s [1]\n", __func__);

		/* FIXME: arbitrary thresholds */
		/* No more than 100 characters; no more than 100 seconds. */
		if (limit > 100 || timeout > 100) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}
		printf("%s [2]\n", __func__);

		int ret = is_queue_available(Q_KEYBOARD);
		/* Or should we make this blocking? */
		if (!ret) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_AVAILABLE)
			break;
		}
		printf("%s [3]\n", __func__);

		mark_queue_unavailable(Q_KEYBOARD);
		printf("%s [4]\n", __func__);

		mailbox_delegate_queue_access(Q_KEYBOARD, runtime_proc_id,
					      (limit_t) limit,
					      (timeout_t) timeout);
		printf("%s [5]\n", __func__);

		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_INFORM_OS_OF_TERMINATION: {
		printf("%s [6]: INFORM_OS_OF_TERMINATION\n", __func__);
		inform_shell_of_termination(runtime_proc_id);
		*late_processing = SYSCALL_INFORM_OS_OF_TERMINATION;
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_INFORM_OS_OF_PAUSE: {
		inform_shell_of_pause(runtime_proc_id);
		*late_processing = SYSCALL_INFORM_OS_OF_PAUSE;
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
	case SYSCALL_GET_FILE_SIZE: {
		uint32_t ret;
		SYSCALL_GET_ONE_ARG
		ret = file_system_get_file_size(arg0);
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
		handle_request_secure_storage_creation_syscall(runtime_proc_id, buf);
		break;
	}
	case SYSCALL_REQUEST_SECURE_STORAGE_ACCESS: {
		handle_request_secure_storage_access_syscall(runtime_proc_id, buf);
		break;
	}
	/* FIXME: we also to need to deal with cases that the app does not properly call the delete */
	case SYSCALL_DELETE_SECURE_STORAGE: {
		handle_delete_secure_storage_syscall(runtime_proc_id, buf);
		break;
	}
	case SYSCALL_REQUEST_SECURE_IPC: {
		SYSCALL_GET_THREE_ARGS
		uint8_t target_runtime_queue_id = arg0;
		uint32_t limit = arg1;
		uint32_t timeout = arg2;
		uint32_t runtime_queue_id = 0;

		/* FIXME: arbitrary thresholds. */
		/* No more than 200 block reads/writes;
		 * no more than 100 seconds
		 */
		if (limit > 200 || timeout > 100) {
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

		int ret = set_up_secure_ipc(target_runtime_queue_id,
					    runtime_queue_id, runtime_proc_id,
					    (limit_t) limit, (timeout_t) timeout,
					    no_response);
		if (ret) {
			SYSCALL_SET_ONE_RET((uint32_t) ret)
			break;
		}

		/* Runtime queue ownership has been transferred at this point,
		 * So we cannot issue syscall response to the runtime anymore.
		 * Otherwise, return the error code.
		 */
		if (!(*no_response))
			SYSCALL_SET_ONE_RET(0)
		break;
	}
#ifdef ARCH_UMODE
	case SYSCALL_ALLOCATE_SOCKET: {
		handle_allocate_socket_syscall(runtime_proc_id, buf);
		break;
	}
	case SYSCALL_REQUEST_NETWORK_ACCESS: {
		handle_request_network_access_syscall(runtime_proc_id, buf);
		break;
	}
	case SYSCALL_CLOSE_SOCKET: {
		handle_close_socket_syscall(runtime_proc_id, buf);
		break;
	}

	case SYSCALL_REQUEST_BLUETOOTH_ACCESS: {
		SYSCALL_GET_TWO_ARGS_DATA
		uint32_t limit = arg0;
		uint32_t timeout = arg1;
		uint8_t *device_name = data;
		uint8_t msg[MAILBOX_QUEUE_MSG_SIZE];

		if (data_size != BD_ADDR_LEN) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		/* FIXME: add access control here. Do we allow the requesting
		 * app to have access to this resource?
		 */

		/* FIXME: arbitrary thresholds. */
		if (limit > 200 || timeout > 100) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		/* Send msg to the bluetooth service to bind the resource */
		memset(msg, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		msg[0] = IO_OP_BIND_RESOURCE;
		memcpy(&msg[1], device_name, BD_ADDR_LEN);

		uint32_t ret = send_cmd_to_bluetooth(msg);
		if (ret) {
			SYSCALL_SET_ONE_RET(ret)
			break;
		}

		int iret1 = is_queue_available(Q_BLUETOOTH_DATA_IN);
		int iret2 = is_queue_available(Q_BLUETOOTH_DATA_OUT);
		int iret3 = is_queue_available(Q_BLUETOOTH_CMD_IN);
		int iret4 = is_queue_available(Q_BLUETOOTH_CMD_OUT);
		/* Or should we make this blocking? */
		if (!iret1 || !iret2 || !iret3 || !iret4) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_AVAILABLE)
			break;
		}

		mark_queue_unavailable(Q_BLUETOOTH_DATA_IN);
		mark_queue_unavailable(Q_BLUETOOTH_DATA_OUT);
		mark_queue_unavailable(Q_BLUETOOTH_CMD_IN);
		mark_queue_unavailable(Q_BLUETOOTH_CMD_OUT);

		mailbox_delegate_queue_access(Q_BLUETOOTH_DATA_IN,
					      runtime_proc_id, (limit_t) limit,
					      (timeout_t) timeout);
		mailbox_delegate_queue_access(Q_BLUETOOTH_DATA_OUT,
					      runtime_proc_id, (limit_t) limit,
					      (timeout_t) timeout);
		mailbox_delegate_queue_access(Q_BLUETOOTH_CMD_IN,
					      runtime_proc_id, (limit_t) limit,
					      (timeout_t) timeout);
		mailbox_delegate_queue_access(Q_BLUETOOTH_CMD_OUT,
					      runtime_proc_id, (limit_t) limit,
					      (timeout_t) timeout);

		SYSCALL_SET_ONE_RET(0)
		break;
	}
#endif
	case SYSCALL_DEBUG_OUTPUTS: {
		SYSCALL_GET_ZERO_ARGS_DATA
#ifdef ARCH_SEC_HW
		xil_printf("RUNTIME%d: %s\r\n", runtime_proc_id, data);
#else
		printf("RUNTIME%d: %s\r\n", runtime_proc_id, data);
#endif
		*no_response = true;
		break;
	}
	case SYSCALL_REQUEST_TPM_ACCESS: {
		SYSCALL_GET_TWO_ARGS
		uint32_t limit = arg0;
		uint32_t timeout = arg1;

		/* FIXME: if no other timeout values are used,
		 * then it shouldn't be an input parameter.
		 *
		 * Also, why 100?
		 */
		if (limit > 100 || timeout != MAILBOX_DEFAULT_TIMEOUT_VAL)
		{
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		int ret = is_queue_available(Q_TPM_IN);
		if (!ret)	
			wait_for_queue_availability(Q_TPM_IN);

		ret = is_queue_available(Q_TPM_OUT);
		if (!ret)	
			wait_for_queue_availability(Q_TPM_OUT);

		mark_queue_unavailable(Q_TPM_IN);
		mark_queue_unavailable(Q_TPM_OUT);

		mailbox_delegate_queue_access(Q_TPM_IN, runtime_proc_id,
					      (limit_t) limit,
					      (timeout_t) timeout);

		mailbox_delegate_queue_access(Q_TPM_OUT, runtime_proc_id,
					      (limit_t) limit,
					      (timeout_t) timeout);

		SYSCALL_SET_ONE_RET(0)
		break;
	}

	default:
		printf("Error: invalid syscall\n");
#ifdef ARCH_SEC_HW
		_SEC_HW_ERROR("invalid syscall, args: %s", buf);
#endif
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		break;
	}
}

static void handle_untrusted_syscall(uint8_t *buf)
{
	uint16_t syscall_nr;

	syscall_nr = *((uint16_t *) &buf[0]);

	switch (syscall_nr) {
	case SYSCALL_WRITE_TO_SHELL: {
		int ret;
		SYSCALL_GET_ZERO_ARGS_DATA

		ret = untrusted_write_to_shell(data, data_size);
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	/* FIXME: the next 7 are very similar to normal secure syscall handler */
	case SYSCALL_INFORM_OS_OF_TERMINATION: {
		inform_shell_of_termination(P_UNTRUSTED);
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_REQUEST_SECURE_STORAGE_CREATION: {
		handle_request_secure_storage_creation_syscall(P_UNTRUSTED, buf);
		break;
	}
	case SYSCALL_REQUEST_SECURE_STORAGE_ACCESS: {
		handle_request_secure_storage_access_syscall(P_UNTRUSTED, buf);
		break;
	}
	/* FIXME: we also to need to deal with cases that the app does not properly call the delete */
	case SYSCALL_DELETE_SECURE_STORAGE: {
		handle_delete_secure_storage_syscall(P_UNTRUSTED, buf);
		break;
	}
#ifdef ARCH_UMODE
	case SYSCALL_ALLOCATE_SOCKET: {
		handle_allocate_socket_syscall(P_UNTRUSTED, buf);
		break;
	}
	case SYSCALL_REQUEST_NETWORK_ACCESS: {
		handle_request_network_access_syscall(P_UNTRUSTED, buf);
		break;
	}
	case SYSCALL_CLOSE_SOCKET: {
		handle_close_socket_syscall(P_UNTRUSTED, buf);
		break;
	}
#endif
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
		printf("%s [1]\n", __func__);
		/* FIXME: use async interrupt processing instead. */
		if (late_processing == SYSCALL_WRITE_FILE_BLOCKS)
			file_system_write_file_blocks_late();
		else if (late_processing == SYSCALL_READ_FILE_BLOCKS)
		      file_system_read_file_blocks_late();
		else if (late_processing == SYSCALL_INFORM_OS_OF_TERMINATION ||
			 late_processing == SYSCALL_INFORM_OS_OF_PAUSE)
			reset_proc(runtime_proc_id);
		printf("%s [2]\n", __func__);
	} else if (runtime_proc_id == P_UNTRUSTED) {
		handle_untrusted_syscall(buf);
		send_cmd_to_untrusted(buf);
	} else {
		printf("Error: invalid syscall caller (%d)\n", runtime_proc_id);
	}
}
