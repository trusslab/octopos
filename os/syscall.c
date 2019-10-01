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

void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id);

uint32_t handle_syscall(uint8_t caller_id, uint16_t syscall_nr, uint32_t arg0, uint32_t arg1)
{
	uint32_t ret;

	switch (syscall_nr) {
	case REQUEST_ACCESS_SERIAL_OUT:
		mailbox_change_queue_access(SERIAL_OUT, WRITE_ACCESS, caller_id);
		ret = 0;
		break;
	case YIELD_ACCESS_SERIAL_OUT:
		mailbox_change_queue_access(SERIAL_OUT, WRITE_ACCESS, OS);
		ret = 0;
		break;
	case REQUEST_ACCESS_KEYBOARD:
		mailbox_change_queue_access(KEYBOARD, READ_ACCESS, caller_id);
		ret = 0;
		break;
	case YIELD_ACCESS_KEYBOARD:
		mailbox_change_queue_access(KEYBOARD, READ_ACCESS, OS);
		ret = 0;
		break;
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
	if (buf[0] == RUNTIME) {
		uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];
		syscall_nr = *((uint16_t *) &buf[1]);
		arg0 = *((uint32_t *) &buf[3]);
		arg1 = *((uint32_t *) &buf[7]);
		ret = handle_syscall(RUNTIME, syscall_nr, arg0, arg1);

		/* send response */
		*((uint32_t *) &ret_buf[0]) = ret;
		send_msg_to_runtime(ret_buf);
	} else {
		printf("Error: invalid syscall caller\n");
	}

}
