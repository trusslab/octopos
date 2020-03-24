#ifndef __ARCH_OCTOPOS_MBOX_OWNERSHIP_MAP_H_
#define __ARCH_OCTOPOS_MBOX_OWNERSHIP_MAP_H_

#include "octopos/mailbox.h"

/* OMboxIds keeps the process IDs for each OctopOS mailbox.
 * These numbers correspond to the pin numbers in the FPGA
 * design.
 */
u8 OMboxIds[NUM_QUEUES][NUM_PROCESSORS] = {0};

/* OMboxCtrlIntrs keeps the irq numbers for each processor.
 * These numbers correspond to the irq numbers in the FPGA
 * design.
 */
u8 OMboxCtrlIntrs[ALL_PROCESSORS][NUM_QUEUES] = {0};

void OMboxIds_init() {
	OMboxIds[Q_SERIAL_OUT][P_OS] = 0;
	OMboxIds[Q_SERIAL_OUT][P_RUNTIME1] = 1;
	OMboxIds[Q_SERIAL_OUT][P_RUNTIME2] = 2;

	OMboxIds[Q_KEYBOARD][P_OS] = 0;
	OMboxIds[Q_KEYBOARD][P_RUNTIME1] = 1;
	OMboxIds[Q_KEYBOARD][P_RUNTIME2] = 2;

	OMboxIds[Q_RUNTIME1][P_OS] = 0;
	OMboxIds[Q_RUNTIME1][P_RUNTIME2] = 1;

	OMboxIds[Q_RUNTIME2][P_OS] = 0;
	OMboxIds[Q_RUNTIME2][P_RUNTIME1] = 1;

#if RUNTIME_ID == 1
	OMboxCtrlIntrs[P_RUNTIME1][Q_RUNTIME1] = XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_3WRI_2_INTERRUPT_CTRL_FIXED_INTR;
	OMboxCtrlIntrs[P_RUNTIME1][Q_RUNTIME2] = XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_3WRI_1_INTERRUPT_CTRL1_INTR;
#elif RUNTIME_ID == 2
	OMboxCtrlIntrs[P_RUNTIME2][Q_RUNTIME1] = XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_3WRI_2_INTERRUPT_CTRL1_INTR;
	OMboxCtrlIntrs[P_RUNTIME2][Q_RUNTIME2] = XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_3WRI_1_INTERRUPT_CTRL_FIXED_INTR;
#endif
}


#endif /* __ARCH_OCTOPOS_MBOX_OWNERSHIP_MAP_H_ */
