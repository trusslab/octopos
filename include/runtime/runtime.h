/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* FIXME: also repeated in mailbox_runtime.c */
#ifdef ARCH_UMODE
typedef int bool;
#define true	(int) 1
#define false	(int) 0
#endif

/* FIXME: do these funcs belong in the same header file? */
void issue_syscall(uint8_t *buf);
void queue_sync_getval(uint8_t queue_id, int *val);
void wait_until_empty(uint8_t queue_id, int queue_size);
void report_queue_usage(uint8_t queue_id);
int check_proc_pcr(uint8_t proc_id, uint8_t *expected_pcr);
int read_tpm_pcr_for_proc(uint8_t proc_id, uint8_t *pcr_val);
