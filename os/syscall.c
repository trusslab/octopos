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
int send_msg_to_storage(uint8_t *msg_buf, uint8_t *resp_buf);

#define SYSCALL_GET_ONE_ARG		\
	uint32_t arg0;			\
	arg0 = *((uint32_t *) &buf[3]); \

#define SYSCALL_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	arg0 = *((uint32_t *) &buf[3]); \
	arg1 = *((uint32_t *) &buf[7]); \

#define SYSCALL_SET_ONE_RET(ret0)	\
	*((uint32_t *) &buf[0]) = ret0; \

static void handle_syscall(uint8_t caller_id, uint8_t *buf)
{
	uint16_t syscall_nr;

	syscall_nr = *((uint16_t *) &buf[1]);

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
	case SYSCALL_WRITE_TO_FILE: {
		SYSCALL_GET_ONE_ARG
		uint32_t data = arg0;
		uint8_t data_buf[MAILBOX_QUEUE_MSG_SIZE];
		uint8_t resp_buf[MAILBOX_QUEUE_MSG_SIZE];
		data_buf[0] = 0; /* write */
		*((uint32_t *) &data_buf[1]) = data;
		send_msg_to_storage(data_buf, resp_buf);
		SYSCALL_SET_ONE_RET(0)
		break;
	}
	case SYSCALL_READ_FROM_FILE: {
		uint8_t data_buf[MAILBOX_QUEUE_MSG_SIZE];
		uint8_t resp_buf[MAILBOX_QUEUE_MSG_SIZE];
		data_buf[0] = 1; /* read */
		send_msg_to_storage(data_buf, resp_buf);
		SYSCALL_SET_ONE_RET(*((uint32_t *) &resp_buf[1]))
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

void process_system_call(uint8_t *buf)
{
	/* only allow syscalls from RUNTIME, for now */
	/* FIXME: we can't rely on the other processor declaring who it is.
	 * Must be set automatically in the mailbox */
	if (buf[0] == P_RUNTIME) {
		
		handle_syscall(P_RUNTIME, buf);

		/* send response */
		send_msg_to_runtime(buf);
	} else {
		printf("Error: invalid syscall caller\n");
	}
}
