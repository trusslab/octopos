/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __SEC_HW_MAILBOX_NETWORK_H
#define __SEC_HW_MAILBOX_NETWORK_H

void network_event_loop(void);
int init_network(void);
void close_network(void);
void read_data_from_queue(uint8_t *buf, uint8_t queue_id);
void write_data_to_queue(uint8_t *buf, uint8_t queue_id);
void send_received_packet(uint8_t *buf, uint8_t queue_id);

#endif /* __SEC_HW_MAILBOX_STORAGE_H */

