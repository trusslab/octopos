/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
uint8_t read_from_bluetooth_cmd_queue_get_owner(uint8_t *buf);
void write_to_bluetooth_cmd_queue(uint8_t *buf);
void read_from_bluetooth_data_queue(uint8_t *buf);
void write_to_bluetooth_data_queue(uint8_t *buf);
int init_bluetooth(void);
void close_bluetooth(void);
