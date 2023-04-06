/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
void inform_shell_of_termination(uint8_t runtime_proc_id);
void inform_shell_of_pause(uint8_t runtime_proc_id);
int app_write_to_shell(struct app *app, uint8_t *data, int size);
int untrusted_write_to_shell(uint8_t *data, int size);
int app_read_from_shell(struct app *app);
void initialize_shell(void);
void shell_process_input(char buf);
