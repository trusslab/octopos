/* octopos IPC */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <octopos/mailbox.h>
#include <octopos/error.h>
#include "scheduler.h"

/* FIXME: move to header file */
void syscall_read_from_shell_response(uint8_t runtime_proc_id, uint8_t *line, int size);
struct app *get_app(int app_id);

int ipc_send_data(struct app *sender, uint8_t *data, int data_size)
{
	int receiver_id = sender->output_dst;
	struct app *receiver = get_app(receiver_id);
	if (!receiver)
		return ERR_FAULT;

	if (receiver->waiting_for_msg && (receiver->state == SCHED_RUNNING)) {
		/* send msg */
		struct runtime_proc *runtime_proc = receiver->runtime_proc;
		/* FIXME: we need to return error to sender if data_size too big */
		receiver->waiting_for_msg = false;
		syscall_read_from_shell_response(runtime_proc->id, data, data_size);
		return 0;
	}

	/* buffer msg */
	if (receiver->has_pending_msg)
		return ERR_MEMORY;

	if (data_size > APP_MSG_BUF_SIZE)
		return ERR_INVALID;

	memcpy(receiver->msg_buf, data, data_size);
	receiver->msg_size = data_size;
	receiver->has_pending_msg = true;

	return 0;
}

void ipc_receive_data(struct app *receiver)
{
	if (receiver->has_pending_msg) {
		syscall_read_from_shell_response(receiver->runtime_proc->id,
						 receiver->msg_buf, receiver->msg_size);
		memset(receiver->msg_buf, 0x0, receiver->msg_size);
		receiver->msg_size = 0;
		receiver->has_pending_msg = false;
	} else {
		receiver->waiting_for_msg = true;
	}
}
