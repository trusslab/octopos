/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* octopos IPC */
#include <arch/defines.h>
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
#include <os/scheduler.h>
#include <os/syscall.h>
#include <arch/mailbox_os.h>

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

int set_up_secure_ipc(uint8_t target_runtime_queue_id, uint8_t runtime_queue_id,
		      uint8_t runtime_proc_id, limit_t limit, timeout_t timeout,
		      bool *no_response)
{
	uint8_t target_proc_id = get_runtime_proc_id(target_runtime_queue_id);
	*no_response = false;
	if (!target_proc_id)
		return ERR_INVALID;

	struct runtime_proc *target_runtime_proc = get_runtime_proc(target_proc_id);
	if (!target_runtime_proc)
		return ERR_FAULT;

	/* FIXME: need a critical section here. */

	if (target_runtime_proc->pending_secure_ipc_request == runtime_queue_id) {

		/* FIXME: do we need to wait for these queues to be empty using wait_until_empty()? */

		mark_queue_unavailable(target_runtime_queue_id);
		mark_queue_unavailable(runtime_queue_id);

		mailbox_delegate_queue_access(target_runtime_queue_id,
					      runtime_proc_id, limit, timeout);
		mailbox_delegate_queue_access(runtime_queue_id,
					      target_runtime_proc->id, limit,
					      timeout);
		
		target_runtime_proc->pending_secure_ipc_request = 0;
		*no_response = true;
	} else {
		struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
		if (!runtime_proc)
			return ERR_FAULT;

		if (runtime_proc->pending_secure_ipc_request)
			return ERR_INVALID;

		runtime_proc->pending_secure_ipc_request = target_runtime_queue_id;
		*no_response = true;
	}

	return 0;

}
