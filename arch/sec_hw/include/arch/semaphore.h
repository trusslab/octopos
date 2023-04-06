/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __SEC_HW_SEMAPHORE_H
#define __SEC_HW_SEMAPHORE_H

#include "arch/ring_buffer.h"
#include <arch/octopos_xmbox.h>

typedef struct {
    int     count;
} sem_t;

int sem_init(sem_t *sem, int pshared, int value);

int sem_post(sem_t *sem);

int sem_wait(sem_t *sem);

int sem_wait_one_time_receive_cbuf(sem_t *sem, OCTOPOS_XMbox *InstancePtr, cbuf_handle_t cbuf);

int sem_wait_one_time_receive_buf(sem_t *sem, OCTOPOS_XMbox *InstancePtr, uint8_t* buf);

int sem_wait_impatient_receive_cbuf(sem_t *sem, OCTOPOS_XMbox *InstancePtr, cbuf_handle_t cbuf);

int sem_wait_impatient_receive_buf(sem_t *sem, OCTOPOS_XMbox *InstancePtr, uint8_t* buf);

int sem_wait_impatient_receive_buf_large(sem_t *sem, OCTOPOS_XMbox *InstancePtr, uint8_t* buf);

int sem_wait_impatient_send(sem_t *sem, OCTOPOS_XMbox *InstancePtr, u32* buf);

int sem_wait_impatient_send_large(sem_t *sem, OCTOPOS_XMbox *InstancePtr, u32* buf);

OCTOPOS_XMbox* sem_wait_impatient_receive_multiple(sem_t *sem, int mb_count, ...);

int sem_getvalue(sem_t *sem, int *value);

int _sem_deliver_mailbox_message_blocking(OCTOPOS_XMbox *InstancePtr, u32* buf);

#endif /* __SEC_HW_SEMAPHORE_H */
