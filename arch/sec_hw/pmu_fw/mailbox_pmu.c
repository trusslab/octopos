/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/

#ifdef ARCH_SEC_HW_PMU

#include <stdio.h>
#include <stdlib.h>
#include "xil_printf.h"
#include "xstatus.h"
#include "xil_io.h"

#include "mailbox_pmu.h"
#include "octopos_pmu_common.h"

UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1] = {0};

u32 octopos_mailbox_get_status_reg(UINTPTR base)
{
	Xil_AssertNonvoid(base != 0);

	return Xil_In32(base);
}

void mailbox_print_queue_status(uint8_t queue_id)
{
	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];
	_SEC_HW_DEBUG("queue %d: ctrl reg %p", queue_id, queue_ptr);
	_SEC_HW_DEBUG("queue %d: ctrl reg content %08x", queue_id, octopos_mailbox_get_status_reg(queue_ptr));
}

void pmu_initialize_octopos_mbox()
{
	Mbox_ctrl_regs[Q_KEYBOARD] = 0xA0000000;
	Mbox_ctrl_regs[Q_SERIAL_OUT] = 0xA0001000;
	Mbox_ctrl_regs[Q_RUNTIME1] = 0xA0035000;
	Mbox_ctrl_regs[Q_RUNTIME2] = 0xA0033000;
}

#endif

