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

void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint8_t access_mode, uint8_t count);

uint32_t handle_syscall(uint8_t caller_id, uint16_t syscall_nr, uint32_t arg0, uint32_t arg1)
{
	uint32_t ret;

	switch (syscall_nr) {
	case SYSCALL_REQUEST_ACCESS_SERIAL_OUT: {
		uint32_t access_mode = arg0, count = arg1;
		if (!(access_mode == ACCESS_LIMITED_IRREVOCABLE || access_mode == ACCESS_UNLIMITED_REVOCABLE)) {
			ret = (uint32_t) ERR_INVALID;
			break;
		}

		/* No more than 100 characters to be printed without revocability */
		if (access_mode == ACCESS_LIMITED_IRREVOCABLE && count > 100) {
			ret = (uint32_t) ERR_INVALID;
			break;
		}

		mailbox_change_queue_access(Q_SERIAL_OUT, WRITE_ACCESS, caller_id, (uint8_t) access_mode, (uint8_t) count);
		ret = 0;
		break;
	}
	case SYSCALL_REQUEST_ACCESS_KEYBOARD: {
		uint32_t access_mode = arg0, count = arg1;
		if (!(access_mode == ACCESS_LIMITED_IRREVOCABLE || access_mode == ACCESS_UNLIMITED_REVOCABLE)) {
			ret = (uint32_t) ERR_INVALID;
			break;
		}

		/* No more than 10 characters to be received from keyboard without revocability */
		if (access_mode == ACCESS_LIMITED_IRREVOCABLE && count > 10) {
			ret = (uint32_t) ERR_INVALID;
			break;
		}

		mailbox_change_queue_access(Q_KEYBOARD, READ_ACCESS, caller_id, (uint8_t) access_mode, (uint8_t) count);
		ret = 0;
		break;
	}
	default:
		printf("Error: invalid syscall\n");
		ret = (uint32_t) ERR_INVALID;
		break;
	}

	return ret;
}

/* FIXME: move to header file */
int send_msg_to_runtime(uint8_t *buf);

void process_system_call(uint8_t *buf)
{
	uint16_t syscall_nr;
	uint32_t arg0, arg1, ret;

	/* only allow syscalls from RUNTIME, for now */
	/* FIXME: we can't rely on the other processor declaring who it is.
	 * Must be set automatically in the mailbox */
	if (buf[0] == P_RUNTIME) {
		uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];
		syscall_nr = *((uint16_t *) &buf[1]);
		arg0 = *((uint32_t *) &buf[3]);
		arg1 = *((uint32_t *) &buf[7]);
		ret = handle_syscall(P_RUNTIME, syscall_nr, arg0, arg1);

		/* send response */
		*((uint32_t *) &ret_buf[0]) = ret;
		send_msg_to_runtime(ret_buf);
	} else {
		printf("Error: invalid syscall caller\n");
	}

}
