/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
int ipc_send_data(struct app *sender, uint8_t *data, int data_size);
void ipc_receive_data(struct app *receiver);
int set_up_secure_ipc(uint8_t target_runtime_queue_id, uint8_t runtime_queue_id,
		      uint8_t runtime_proc_id, limit_t limit, timeout_t timeout,
		      bool *no_response);
