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

/* FIXME: move to header file */
void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint8_t access_mode, uint8_t count);
void inform_shell_of_termination(void);
int app_write_to_shell(uint8_t *data, int size);
int app_read_from_shell(void);
uint32_t file_system_open_file(char *filename);
int file_system_write_to_file(uint32_t fd, uint8_t *data, int size, int offset);
int file_system_read_from_file(uint32_t fd, uint8_t *data, int size, int offset);
int file_system_close_file(uint32_t fd);

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
	}							\
	data_size = buf[3];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
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
	}							\
	data_size = buf[11];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)	\
	}							\
	data = &buf[12];					\

static void handle_syscall(uint8_t caller_id, uint8_t *buf, bool *is_async)
{
	uint16_t syscall_nr;

	syscall_nr = *((uint16_t *) &buf[1]);
	*is_async = false;

	switch (syscall_nr) {
	case SYSCALL_REQUEST_ACCESS_SERIAL_OUT: {
		SYSCALL_GET_TWO_ARGS
		uint32_t access_mode = arg0, count = arg1;
		if (!(access_mode == ACCESS_LIMITED_IRREVOCABLE || access_mode == ACCESS_UNLIMITED_REVOCABLE)) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		/* No more than 100 characters to be printed without revocability */
		if (access_mode == ACCESS_LIMITED_IRREVOCABLE && count > 100) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		mailbox_change_queue_access(Q_SERIAL_OUT, WRITE_ACCESS, caller_id, (uint8_t) access_mode, (uint8_t) count);
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_REQUEST_ACCESS_KEYBOARD: {
		SYSCALL_GET_TWO_ARGS
		uint32_t access_mode = arg0, count = arg1;
		if (!(access_mode == ACCESS_LIMITED_IRREVOCABLE || access_mode == ACCESS_UNLIMITED_REVOCABLE)) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		/* No more than 10 characters to be received from keyboard without revocability */
		if (access_mode == ACCESS_LIMITED_IRREVOCABLE && count > 10) {
			SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
			break;
		}

		mailbox_change_queue_access(Q_KEYBOARD, READ_ACCESS, caller_id, (uint8_t) access_mode, (uint8_t) count);
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_INFORM_OS_OF_TERMINATION: {
		inform_shell_of_termination();
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_WRITE_TO_SHELL: {
		int ret;
		SYSCALL_GET_ZERO_ARGS_DATA
		ret = app_write_to_shell(data, data_size);
		SYSCALL_SET_ONE_RET(ret)
		break;
	}
	case SYSCALL_READ_FROM_SHELL: {
		app_read_from_shell();
		*is_async = true;
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
	default:
		printf("Error: invalid syscall\n");
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		break;
	}
}


/* FIXME: move to header file */
int send_msg_to_runtime(uint8_t *buf);

/* response for async syscalls */
void syscall_read_from_shell_response(uint8_t *line, int size)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	SYSCALL_SET_ONE_RET_DATA(0, line, size)
	send_msg_to_runtime(buf);
}

void process_system_call(uint8_t *buf)
{
	/* only allow syscalls from RUNTIME, for now */
	/* FIXME: we can't rely on the other processor declaring who it is.
	 * Must be set automatically in the mailbox */
	if (buf[0] == P_RUNTIME) {
		bool is_async = false;
	
		handle_syscall(P_RUNTIME, buf, &is_async);

		/* send response */
		if (!is_async)
			send_msg_to_runtime(buf);
	} else {
		printf("Error: invalid syscall caller\n");
	}
}
