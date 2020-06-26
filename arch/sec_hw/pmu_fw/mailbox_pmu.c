
#ifdef ARCH_SEC_HW_PMU

#include <stdio.h>
#include <stdlib.h>
#include "xil_printf.h"
#include "xstatus.h"
#include "xil_io.h"

#include "mailbox_pmu.h"

UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1];

u32 octopos_mailbox_get_status_reg(UINTPTR base)
{
	Xil_AssertNonvoid(base != 0);

	return Xil_In32(base);
}

void mailbox_print_queue_status(uint8_t queue_id)
{
    UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];
    xil_printf("queue %d: ctrl reg %p", queue_id, queue_ptr);
    xil_printf("queue %d: ctrl reg content %08x", queue_id, octopos_mailbox_get_status_reg(queue_ptr));
}

void pmu_initialize_octopos_mbox()
{
    Mbox_ctrl_regs[Q_KEYBOARD] = XPAR_OCTOPOS_MAILBOX_1WRI_0_BASEADDR;
    Mbox_ctrl_regs[Q_SERIAL_OUT] = XPAR_OCTOPOS_MAILBOX_3WRI_0_BASEADDR;
    Mbox_ctrl_regs[Q_RUNTIME1] = XPAR_OCTOPOS_MAILBOX_3WRI_2_BASEADDR;
    Mbox_ctrl_regs[Q_RUNTIME2] = XPAR_OCTOPOS_MAILBOX_3WRI_1_BASEADDR;
}

#endif

