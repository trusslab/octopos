/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __SEC_HW_MAILBOX_SERIAL_OUT_H
#define __SEC_HW_MAILBOX_SERIAL_OUT_H

void get_chars_from_serial_out_queue(uint8_t *buf);
void write_chars_to_serial_out(uint8_t *buf);
int init_serial_out(void);
void close_serial_out(void);
void runtime_core(void);

#endif /* __SEC_HW_MAILBOX_SERIAL_OUT_H */
