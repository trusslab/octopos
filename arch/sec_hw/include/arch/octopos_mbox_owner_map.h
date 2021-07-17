#ifndef __ARCH_OCTOPOS_MBOX_OWNERSHIP_MAP_H_
#define __ARCH_OCTOPOS_MBOX_OWNERSHIP_MAP_H_

#include "octopos/mailbox.h"

#include "arch/octopos_mbox.h"
#include "arch/octopos_xmbox.h"

/* OMboxIds keeps the process IDs for each OctopOS mailbox.
 * These numbers correspond to the pin numbers in the FPGA
 * design.
 */
u8 OMboxIds[NUM_QUEUES + 1][NUM_PROCESSORS + 1] = {0};

/* OMboxCtrlIntrs keeps the irq numbers for each processor.
 * These numbers correspond to the irq numbers in the FPGA
 * design.
 */
u8 OMboxCtrlIntrs[NUM_PROCESSORS + 1][NUM_QUEUES + 1] = {0};
u8 OMboxIntrs[NUM_PROCESSORS + 1][NUM_QUEUES + 1] = {0};

/* OCTOPOS_XMbox_ConfigTable keeps processor-specific mailbox
 * parameters. These data will be used to access the mailbox
 * data.
 */
#if defined ARCH_SEC_HW_OS
OCTOPOS_XMbox_Config OCTOPOS_XMbox_ConfigTable[] = {
	{
		XPAR_OS_MBOX_Q_KEYBOARD_DEVICE_ID,
		XPAR_OS_MBOX_Q_KEYBOARD_BASEADDR,
		XPAR_OS_MBOX_Q_KEYBOARD_USE_FSL,
		XPAR_OS_MBOX_Q_KEYBOARD_SEND_FSL,
		XPAR_OS_MBOX_Q_KEYBOARD_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_SERIAL_OUT_DEVICE_ID,
		XPAR_OS_MBOX_Q_SERIAL_OUT_BASEADDR,
		XPAR_OS_MBOX_Q_SERIAL_OUT_USE_FSL,
		XPAR_OS_MBOX_Q_SERIAL_OUT_SEND_FSL,
		XPAR_OS_MBOX_Q_SERIAL_OUT_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_RUNTIME1_DEVICE_ID,
		XPAR_OS_MBOX_Q_RUNTIME1_BASEADDR,
		XPAR_OS_MBOX_Q_RUNTIME1_USE_FSL,
		XPAR_OS_MBOX_Q_RUNTIME1_SEND_FSL,
		XPAR_OS_MBOX_Q_RUNTIME1_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_RUNTIME2_DEVICE_ID,
		XPAR_OS_MBOX_Q_RUNTIME2_BASEADDR,
		XPAR_OS_MBOX_Q_RUNTIME2_USE_FSL,
		XPAR_OS_MBOX_Q_RUNTIME2_SEND_FSL,
		XPAR_OS_MBOX_Q_RUNTIME2_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_STORAGE_DATA_IN_DEVICE_ID,
		XPAR_OS_MBOX_Q_STORAGE_DATA_IN_BASEADDR,
		XPAR_OS_MBOX_Q_STORAGE_DATA_IN_USE_FSL,
		XPAR_OS_MBOX_Q_STORAGE_DATA_IN_SEND_FSL,
		XPAR_OS_MBOX_Q_STORAGE_DATA_IN_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_DEVICE_ID,
		XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_BASEADDR,
		XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_USE_FSL,
		XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_SEND_FSL,
		XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_CMD_IN_DEVICE_ID,
		XPAR_OS_MBOX_Q_CMD_IN_BASEADDR,
		XPAR_OS_MBOX_Q_CMD_IN_USE_FSL,
		XPAR_OS_MBOX_Q_CMD_IN_SEND_FSL,
		XPAR_OS_MBOX_Q_CMD_IN_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_CMD_OUT_DEVICE_ID,
		XPAR_OS_MBOX_Q_CMD_OUT_BASEADDR,
		XPAR_OS_MBOX_Q_CMD_OUT_USE_FSL,
		XPAR_OS_MBOX_Q_CMD_OUT_SEND_FSL,
		XPAR_OS_MBOX_Q_CMD_OUT_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_ENCLAVE0_DEVICE_ID, 
		XPAR_OS_MBOX_Q_ENCLAVE0_BASEADDR, 
		XPAR_OS_MBOX_Q_ENCLAVE0_USE_FSL,
		XPAR_OS_MBOX_Q_ENCLAVE0_SEND_FSL,
		XPAR_OS_MBOX_Q_ENCLAVE0_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_ENCLAVE1_DEVICE_ID, 
		XPAR_OS_MBOX_Q_ENCLAVE1_BASEADDR, 
		XPAR_OS_MBOX_Q_ENCLAVE1_USE_FSL,
		XPAR_OS_MBOX_Q_ENCLAVE1_SEND_FSL,
		XPAR_OS_MBOX_Q_ENCLAVE1_RECV_FSL
	},
	{
		XPAR_OS_MBOX_Q_UNTRUSTED_DEVICE_ID,
		XPAR_OS_MBOX_Q_UNTRUSTED_BASEADDR,
		XPAR_OS_MBOX_Q_UNTRUSTED_USE_FSL,
		XPAR_OS_MBOX_Q_UNTRUSTED_SEND_FSL,
		XPAR_OS_MBOX_Q_UNTRUSTED_RECV_FSL,
	},
	{
		XPAR_OS_MBOX_Q_OSU_DEVICE_ID,
		XPAR_OS_MBOX_Q_OSU_BASEADDR,
		XPAR_OS_MBOX_Q_OSU_USE_FSL,
		XPAR_OS_MBOX_Q_OSU_SEND_FSL,
		XPAR_OS_MBOX_Q_OSU_RECV_FSL,
	},
};
#elif defined ARCH_SEC_HW_STORAGE
OCTOPOS_XMbox_Config OCTOPOS_XMbox_ConfigTable[] = {
	{
		XPAR_STORAGE_MBOX_DATA_IN_DEVICE_ID,
		XPAR_STORAGE_MBOX_DATA_IN_BASEADDR,
		XPAR_STORAGE_MBOX_DATA_IN_USE_FSL,
		XPAR_STORAGE_MBOX_DATA_IN_SEND_FSL,
		XPAR_STORAGE_MBOX_DATA_IN_RECV_FSL
	},
	{
		XPAR_STORAGE_MBOX_DATA_OUT_DEVICE_ID,
		XPAR_STORAGE_MBOX_DATA_OUT_BASEADDR,
		XPAR_STORAGE_MBOX_DATA_OUT_USE_FSL,
		XPAR_STORAGE_MBOX_DATA_OUT_SEND_FSL,
		XPAR_STORAGE_MBOX_DATA_OUT_RECV_FSL
	},
	{
		XPAR_STORAGE_MBOX_CMD_IN_DEVICE_ID,
		XPAR_STORAGE_MBOX_CMD_IN_BASEADDR,
		XPAR_STORAGE_MBOX_CMD_IN_USE_FSL,
		XPAR_STORAGE_MBOX_CMD_IN_SEND_FSL,
		XPAR_STORAGE_MBOX_CMD_IN_RECV_FSL
	},
	{
		XPAR_STORAGE_MBOX_CMD_OUT_DEVICE_ID,
		XPAR_STORAGE_MBOX_CMD_OUT_BASEADDR,
		XPAR_STORAGE_MBOX_CMD_OUT_USE_FSL,
		XPAR_STORAGE_MBOX_CMD_OUT_SEND_FSL,
		XPAR_STORAGE_MBOX_CMD_OUT_RECV_FSL
	},
};
#elif defined ARCH_SEC_HW_RUNTIME
OCTOPOS_XMbox_Config OCTOPOS_XMbox_ConfigTable[] = {
	{
		XPAR_RUNTIME_KEYBOARD_DEVICE_ID,
		XPAR_RUNTIME_KEYBOARD_BASEADDR,
		XPAR_RUNTIME_KEYBOARD_USE_FSL,
		XPAR_RUNTIME_KEYBOARD_SEND_FSL,
		XPAR_RUNTIME_KEYBOARD_RECV_FSL
	},
	{
		XPAR_RUNTIME_SERIAL_OUT_DEVICE_ID,
		XPAR_RUNTIME_SERIAL_OUT_BASEADDR,
		XPAR_RUNTIME_SERIAL_OUT_USE_FSL,
		XPAR_RUNTIME_SERIAL_OUT_SEND_FSL,
		XPAR_RUNTIME_SERIAL_OUT_RECV_FSL
	},
	{
		XPAR_RUNTIME_RUNTIME1_DEVICE_ID,
		XPAR_RUNTIME_RUNTIME1_BASEADDR,
		XPAR_RUNTIME_RUNTIME1_USE_FSL,
		XPAR_RUNTIME_RUNTIME1_SEND_FSL,
		XPAR_RUNTIME_RUNTIME1_RECV_FSL
	},
	{
		XPAR_RUNTIME_RUNTIME2_DEVICE_ID,
		XPAR_RUNTIME_RUNTIME2_BASEADDR,
		XPAR_RUNTIME_RUNTIME2_USE_FSL,
		XPAR_RUNTIME_RUNTIME2_SEND_FSL,
		XPAR_RUNTIME_RUNTIME2_RECV_FSL
	},
	{
		XPAR_RUNTIME_STORAGE_DATA_IN_DEVICE_ID,
		XPAR_RUNTIME_STORAGE_DATA_IN_BASEADDR,
		XPAR_RUNTIME_STORAGE_DATA_IN_USE_FSL,
		XPAR_RUNTIME_STORAGE_DATA_IN_SEND_FSL,
		XPAR_RUNTIME_STORAGE_DATA_IN_RECV_FSL
	},
	{
		XPAR_RUNTIME_STORAGE_DATA_OUT_DEVICE_ID,
		XPAR_RUNTIME_STORAGE_DATA_OUT_BASEADDR,
		XPAR_RUNTIME_STORAGE_DATA_OUT_USE_FSL,
		XPAR_RUNTIME_STORAGE_DATA_OUT_SEND_FSL,
		XPAR_RUNTIME_STORAGE_DATA_OUT_RECV_FSL
	},
	{
		XPAR_RUNTIME_STORAGE_CMD_IN_DEVICE_ID,
		XPAR_RUNTIME_STORAGE_CMD_IN_BASEADDR,
		XPAR_RUNTIME_STORAGE_CMD_IN_USE_FSL,
		XPAR_RUNTIME_STORAGE_CMD_IN_SEND_FSL,
		XPAR_RUNTIME_STORAGE_CMD_IN_RECV_FSL
	},
	{
		XPAR_RUNTIME_STORAGE_CMD_OUT_DEVICE_ID,
		XPAR_RUNTIME_STORAGE_CMD_OUT_BASEADDR,
		XPAR_RUNTIME_STORAGE_CMD_OUT_USE_FSL,
		XPAR_RUNTIME_STORAGE_CMD_OUT_SEND_FSL,
		XPAR_RUNTIME_STORAGE_CMD_OUT_RECV_FSL
	},
	{
		XPAR_RUNTIME_OS_DEVICE_ID,
		XPAR_RUNTIME_OS_BASEADDR,
		XPAR_RUNTIME_OS_USE_FSL,
		XPAR_RUNTIME_OS_SEND_FSL,
		XPAR_RUNTIME_OS_RECV_FSL
	},
};
#elif defined ARCH_SEC_HW_KEYBOARD
OCTOPOS_XMbox_Config OCTOPOS_XMbox_ConfigTable[] = {
	{
		XPAR_KEYBOARD_KEYBOARD_DEVICE_ID,
		XPAR_KEYBOARD_KEYBOARD_BASEADDR,
		XPAR_KEYBOARD_KEYBOARD_USE_FSL,
		XPAR_KEYBOARD_KEYBOARD_SEND_FSL,
		XPAR_KEYBOARD_KEYBOARD_RECV_FSL
	},
	{
		XPAR_KEYBOARD_STORAGE_DATA_OUT_DEVICE_ID,
		XPAR_KEYBOARD_STORAGE_DATA_OUT_BASEADDR,
		XPAR_KEYBOARD_STORAGE_DATA_OUT_USE_FSL,
		XPAR_KEYBOARD_STORAGE_DATA_OUT_SEND_FSL,
		XPAR_KEYBOARD_STORAGE_DATA_OUT_RECV_FSL
	},
};
#elif defined ARCH_SEC_HW_SERIAL_OUT
OCTOPOS_XMbox_Config OCTOPOS_XMbox_ConfigTable[] = {
	{
		XPAR_SERIAL_OUT_SERIAL_OUT_DEVICE_ID,
		XPAR_SERIAL_OUT_SERIAL_OUT_BASEADDR,
		XPAR_SERIAL_OUT_SERIAL_OUT_USE_FSL,
		XPAR_SERIAL_OUT_SERIAL_OUT_SEND_FSL,
		XPAR_SERIAL_OUT_SERIAL_OUT_RECV_FSL
	},
	{
		XPAR_SERIAL_OUT_STORAGE_DATA_OUT_DEVICE_ID,
		XPAR_SERIAL_OUT_STORAGE_DATA_OUT_BASEADDR,
		XPAR_SERIAL_OUT_STORAGE_DATA_OUT_USE_FSL,
		XPAR_SERIAL_OUT_STORAGE_DATA_OUT_SEND_FSL,
		XPAR_SERIAL_OUT_STORAGE_DATA_OUT_RECV_FSL
	},
};
#endif

#define P_PREVIOUS 0xff

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

	OMboxIds[Q_STORAGE_DATA_OUT][P_OS] = 0;
	OMboxIds[Q_STORAGE_DATA_OUT][P_RUNTIME1] = 1;
	OMboxIds[Q_STORAGE_DATA_OUT][P_RUNTIME2] = 2;
	OMboxIds[Q_STORAGE_DATA_OUT][P_UNTRUSTED] = 3;
	OMboxIds[Q_STORAGE_DATA_OUT][P_SERIAL_OUT] = 4;
	OMboxIds[Q_STORAGE_DATA_OUT][P_KEYBOARD] = 5;

	OMboxIds[Q_STORAGE_DATA_IN][P_OS] = 0;
	OMboxIds[Q_STORAGE_DATA_IN][P_RUNTIME1] = 1;
	OMboxIds[Q_STORAGE_DATA_IN][P_RUNTIME2] = 2;
	OMboxIds[Q_STORAGE_DATA_IN][P_UNTRUSTED] = 3;

	OMboxIds[Q_STORAGE_CMD_OUT][P_OS] = 0;
	OMboxIds[Q_STORAGE_CMD_OUT][P_RUNTIME1] = 1;
	OMboxIds[Q_STORAGE_CMD_OUT][P_RUNTIME2] = 2;
	OMboxIds[Q_STORAGE_CMD_OUT][P_UNTRUSTED] = 3;

	OMboxIds[Q_STORAGE_CMD_IN][P_OS] = 0;
	OMboxIds[Q_STORAGE_CMD_IN][P_RUNTIME1] = 1;
	OMboxIds[Q_STORAGE_CMD_IN][P_RUNTIME2] = 2;
	OMboxIds[Q_STORAGE_CMD_IN][P_UNTRUSTED] = 3;

#if RUNTIME_ID == 1
	OMboxCtrlIntrs[P_RUNTIME1][Q_RUNTIME1] = XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_3WRI_2_INTERRUPT_CTRL_FIXED_INTR;
	OMboxCtrlIntrs[P_RUNTIME1][Q_RUNTIME2] = XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_3WRI_1_INTERRUPT_CTRL1_INTR;
	OMboxCtrlIntrs[P_RUNTIME1][Q_SERIAL_OUT] = XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_3WRI_0_INTERRUPT_CTRL1_INTR;
	OMboxCtrlIntrs[P_RUNTIME1][Q_KEYBOARD] = XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_1WRI_0_INTERRUPT_CTRL1_INTR;
	OMboxCtrlIntrs[P_RUNTIME1][Q_STORAGE_DATA_OUT] = XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_1WRI_1_INTERRUPT_CTRL1_INTR;
	OMboxCtrlIntrs[P_RUNTIME1][Q_STORAGE_DATA_IN] = XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_4WRI_0_INTERRUPT_CTRL1_INTR;
	OMboxCtrlIntrs[P_RUNTIME1][Q_STORAGE_CMD_OUT] = XPAR_MICROBLAZE_2_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_CTRL1_INTR;
	OMboxCtrlIntrs[P_RUNTIME1][Q_STORAGE_CMD_IN] = XPAR_MICROBLAZE_2_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_CTRL1_INTR;
#elif RUNTIME_ID == 2
	OMboxCtrlIntrs[P_RUNTIME2][Q_RUNTIME1] = XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_3WRI_2_INTERRUPT_CTRL1_INTR;
	OMboxCtrlIntrs[P_RUNTIME2][Q_RUNTIME2] = XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_3WRI_1_INTERRUPT_CTRL_FIXED_INTR;
	OMboxCtrlIntrs[P_RUNTIME2][Q_SERIAL_OUT] = XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_3WRI_0_INTERRUPT_CTRL2_INTR;
	OMboxCtrlIntrs[P_RUNTIME2][Q_KEYBOARD] = XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_1WRI_0_INTERRUPT_CTRL2_INTR;
	OMboxCtrlIntrs[P_RUNTIME2][Q_STORAGE_DATA_OUT] = XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_1WRI_1_INTERRUPT_CTRL2_INTR;
	OMboxCtrlIntrs[P_RUNTIME2][Q_STORAGE_DATA_IN] = XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_4WRI_0_INTERRUPT_CTRL2_INTR;
	OMboxCtrlIntrs[P_RUNTIME2][Q_STORAGE_CMD_OUT] = XPAR_MICROBLAZE_3_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_CTRL2_INTR;
	OMboxCtrlIntrs[P_RUNTIME2][Q_STORAGE_CMD_IN] = XPAR_MICROBLAZE_3_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_CTRL2_INTR;
#endif

#ifdef ARCH_SEC_HW_OS
	OMboxCtrlIntrs[P_OS][Q_KEYBOARD] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_1WRI_0_INTERRUPT_CTRL0_INTR;
	OMboxCtrlIntrs[P_OS][Q_SERIAL_OUT] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_3WRI_0_INTERRUPT_CTRL0_INTR;
	OMboxCtrlIntrs[P_OS][Q_RUNTIME1] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_3WRI_2_INTERRUPT_CTRL0_INTR;
	OMboxCtrlIntrs[P_OS][Q_RUNTIME2] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_3WRI_1_INTERRUPT_CTRL0_INTR;
	OMboxCtrlIntrs[P_OS][Q_STORAGE_CMD_IN] = XPAR_MICROBLAZE_6_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_CTRL0_INTR;
	OMboxCtrlIntrs[P_OS][Q_STORAGE_CMD_OUT] = XPAR_MICROBLAZE_6_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_CTRL0_INTR;
	OMboxCtrlIntrs[P_OS][Q_STORAGE_DATA_IN] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_4WRI_0_INTERRUPT_CTRL0_INTR;
	OMboxCtrlIntrs[P_OS][Q_STORAGE_DATA_OUT] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_1WRI_1_INTERRUPT_CTRL0_INTR;
	OMboxIntrs[P_OS][Q_KEYBOARD] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_1WRI_0_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_SERIAL_OUT] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_3WRI_0_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_RUNTIME1] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_3WRI_2_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_RUNTIME2] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_3WRI_1_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_STORAGE_CMD_IN] = XPAR_MICROBLAZE_6_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_STORAGE_CMD_OUT] = XPAR_MICROBLAZE_6_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_STORAGE_DATA_IN] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_4WRI_0_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_STORAGE_DATA_OUT] = XPAR_MICROBLAZE_6_AXI_INTC_OCTOPOS_MAILBOX_1WRI_1_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_OS1] = XPAR_MICROBLAZE_6_AXI_INTC_ENCLAVE0_PS_MAILBOX_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_OS2] = XPAR_MICROBLAZE_6_AXI_INTC_ENCLAVE1_PS_MAILBOX_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_OSU] = XPAR_MICROBLAZE_6_AXI_INTC_Q_OSU_INTERRUPT_0_INTR;
	OMboxIntrs[P_OS][Q_UNTRUSTED] = XPAR_MICROBLAZE_6_AXI_INTC_Q_UNTRUSTED_INTERRUPT_0_INTR;
#endif
}

#endif /* __ARCH_OCTOPOS_MBOX_OWNERSHIP_MAP_H_ */
