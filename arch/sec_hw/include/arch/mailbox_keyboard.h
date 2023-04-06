/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __SEC_HW_MAILBOX_KEYBOARD_H
#define __SEC_HW_MAILBOX_KEYBOARD_H

uint8_t read_char_from_keyboard(void);
void put_char_on_keyboard_queue(uint8_t kchar);
int init_keyboard(void);
void close_keyboard(void);

#endif /* __SEC_HW_MAILBOX_KEYBOARD_H */
