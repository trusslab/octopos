/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __UMODE_MAILBOX_STORAGE_H
#define __UMODE_MAILBOX_STORAGE_H

void storage_event_loop(void);
int init_storage(void);
void close_storage(void);
void send_response(uint8_t *buf, uint8_t queue_id);
void read_data_from_queue(uint8_t *buf, uint8_t queue_id);
void write_data_to_queue(uint8_t *buf, uint8_t queue_id);

#endif /* __UMODE_MAILBOX_STORAGE_H */

