/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
void syscall_read_from_shell_response(uint8_t runtime_proc_id, uint8_t *line, int size);
void process_system_call(uint8_t *buf, uint8_t runtime_proc_id);
