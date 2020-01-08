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
#include <octopos/error.h>
#include "scheduler.h"

/* FIXME: move to header file */
void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint8_t count);
void inform_shell_of_termination(uint8_t runtime_proc_id);
int app_write_to_shell(struct app *app, uint8_t *data, int size);
int app_read_from_shell(struct app *app);
uint32_t file_system_open_file(char *filename);
int file_system_write_to_file(uint32_t fd, uint8_t *data, int size, int offset);
int file_system_read_from_file(uint32_t fd, uint8_t *data, int size, int offset);
int file_system_close_file(uint32_t fd);
uint8_t get_runtime_queue_id(uint8_t runtime_proc_id);
bool is_valid_runtime_queue_id(int queue_id);
int set_up_secure_ipc(uint8_t target_runtime_queue_id, uint8_t runtime_queue_id, uint8_t runtime_proc_id, int count, bool *no_response);

#define SYSCALL_SET_ONE_RET(ret0)	\
	*((uint32_t *) &buf[0]) = ret0; \

/* FIXME: when calling this one, we need to allocate a ret_buf. Can we avoid that? */
#define SYSCALL_SET_ONE_RET_DATA(ret0, data, size)		\
	*((uint32_t *) &buf[0]) = ret0;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 5;		\
	if (max_size < 256 && size <= ((int) max_size)) {	\
		buf[4] = (uint8_t) size;			\
		memcpy(&buf[5], data, size);			\
	} else {						\
		printf("Error: invalid max_size or size\n");	\
		buf[4] = 0;					\
	}							\

#define SYSCALL_GET_ONE_ARG		\
	uint32_t arg0;			\
	arg0 = *((uint32_t *) &buf[3]); \

#define SYSCALL_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	arg0 = *((uint32_t *) &buf[3]); \
	arg1 = *((uint32_t *) &buf[7]); \

#define SYSCALL_GET_THREE_ARGS		\
	uint32_t arg0, arg1, arg2;	\
	arg0 = *((uint32_t *) &buf[3]); \
	arg1 = *((uint32_t *) &buf[7]); \
	arg2 = *((uint32_t *) &buf[11]);\

#define SYSCALL_GET_ZERO_ARGS_DATA				\
	uint8_t data_size, *data;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 4;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data_size = buf[3];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data = &buf[4];						\

#define SYSCALL_GET_TWO_ARGS_DATA				\
	uint32_t arg0, arg1;					\
	uint8_t data_size, *data;				\
	arg0 = *((uint32_t *) &buf[3]);				\
	arg1 = *((uint32_t *) &buf[7]);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 12;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data_size = buf[11];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		break;						\
	}							\
	data = &buf[12];					\

/* FIXME: move to header file */
int send_msg_to_runtime(uint8_t runtime_proc_id, uint8_t *buf);
struct runtime_proc *get_runtime_proc(int id);
int ipc_send_data(struct app *sender, uint8_t *data, int data_size);
void ipc_receive_data(struct app *receiver);

/* response for async syscalls */
void syscall_read_from_shell_response(uint8_t runtime_proc_id, uint8_t *line, int size)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	SYSCALL_SET_ONE_RET_DATA(0, line, size)
	/* FIXME: we need to send msg to runtime proc that issues the syscall */
	send_msg_to_runtime(runtime_proc_id, buf);
}

void syscall_request_secure_ipc_response(uint8_t runtime_proc_id, int ret)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	SYSCALL_SET_ONE_RET((uint32_t) ret)
	send_msg_to_runtime(runtime_proc_id, buf);
}

static void handle_syscall(uint8_t runtime_proc_id, uint8_t *buf, bool *no_response)
{
	uint16_t syscall_nr;

	syscall_nr = *((uint16_t *) &buf[1]);
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

		/* FIXME: Check to make sure secure serial_out is available */

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

		/* FIXME: Check to make sure secure keyboard is available */

		mailbox_change_queue_access(Q_KEYBOARD, READ_ACCESS, runtime_proc_id, (uint8_t) count);
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_INFORM_OS_OF_TERMINATION: {
		inform_shell_of_termination(runtime_proc_id);
		SYSCALL_SET_ONE_RET(0)
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
		SYSCALL_GET_ZERO_ARGS_DATA
		char filename[256];
		if (data_size >= 256) {
			printf("Error: filename is too large\n");
			SYSCALL_SET_ONE_RET(0)
		}
		memcpy(filename, data, data_size);
		/* playing it safe */
		filename[data_size] = '\0';
		uint32_t fd = file_system_open_file(filename);
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
	case SYSCALL_CLOSE_FILE: {
		uint32_t ret;
		SYSCALL_GET_ONE_ARG
		ret = (uint32_t) file_system_close_file(arg0);
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	case SYSCALL_REQUEST_SECURE_STORAGE: {
		SYSCALL_GET_ONE_ARG
		uint32_t count = arg0;

		/* No more than 200 block reads/writes */
		if (count > 200) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		/* FIXME: Check to make sure secure storage is available */

		mailbox_change_queue_access(Q_STORAGE_IN_2, WRITE_ACCESS, runtime_proc_id, (uint8_t) count);
		mailbox_change_queue_access(Q_STORAGE_OUT_2, READ_ACCESS, runtime_proc_id, (uint8_t) count);
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

void process_system_call(uint8_t *buf)
{
	/* only allow syscalls from RUNTIME, for now */
	/* FIXME: we can't rely on the other processor declaring who it is.
	 * Must be set automatically in the mailbox */
	int runtime_proc_id = buf[0];
	if (runtime_proc_id == P_RUNTIME1 || runtime_proc_id == P_RUNTIME2) {
		bool no_response = false;
	
		handle_syscall(buf[0], buf, &no_response);

		/* send response */
		if (!no_response) {
			send_msg_to_runtime(runtime_proc_id, buf);
		}
	} else {
		printf("Error: invalid syscall caller\n");
	}
}
