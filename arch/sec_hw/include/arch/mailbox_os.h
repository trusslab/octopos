/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __SEC_HW_MAILBOX_OS_H
#define __SEC_HW_MAILBOX_OS_H

#include "octopos/mailbox.h"

#ifdef ARMR5
#define IPI_TRIGGER_REG 0xFF310018U
#else
#define IPI_TRIGGER_REG 0xFF340018U
#endif

void _mailbox_print_queue_status(uint8_t queue_id);

int is_queue_available(uint8_t queue_id);
void wait_for_queue_availability(uint8_t queue_id);
void mark_queue_unavailable(uint8_t queue_id);

int send_output(uint8_t *buf);
int recv_input(uint8_t *buf, uint8_t *queue_id);

int check_avail_and_send_msg_to_runtime(uint8_t runtime_proc_id, uint8_t *buf);
void wait_until_empty(uint8_t queue_id, int queue_size);

int send_msg_to_storage_no_response(uint8_t *buf);
int get_response_from_storage(uint8_t *buf);
void read_from_storage_data_queue(uint8_t *buf);
void write_to_storage_data_queue(uint8_t *buf);
int send_cmd_to_untrusted(uint8_t *buf);
int send_cmd_to_network(uint8_t *buf) ;
void mailbox_delegate_queue_access(uint8_t queue_id, uint8_t proc_id, limit_t limit, timeout_t timeout);

int init_os_mailbox(void);
void close_os_mailbox(void);

void wait_for_storage_sec_hw(void);

#endif /* __SEC_HW_MAILBOX_OS_H */
