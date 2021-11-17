#ifdef ARCH_SEC_HW_STORAGE
#include <stdio.h>
#include <stdlib.h>
#include "xil_printf.h"
#include "sleep.h"
#include "xstatus.h"
#include "xintc.h"

#include "xil_cache.h"

#include "arch/sec_hw.h"
#include "arch/semaphore.h"
#include "arch/octopos_xmbox.h"
#include "arch/ring_buffer.h"
#include "arch/octopos_mbox_owner_map.h"
#include "arch/octopos_mbox.h"
#include "arch/pmod_fop.h"

#include "octopos/mailbox.h"
#include "octopos/storage.h"
#include "octopos/error.h"

XIntc			intc;

OCTOPOS_XMbox	Mbox_storage_in_2,
				Mbox_storage_out_2,
				Mbox_storage_cmd_in,
				Mbox_storage_cmd_out,
				Mbox_storage_data_in,
				Mbox_storage_data_out;

sem_t			interrupts[NUM_QUEUES + 1];

OCTOPOS_XMbox*	Mbox_regs[NUM_QUEUES + 1];
UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1] = {0};

void process_request(uint8_t *buf, uint8_t proc_id);
void initialize_storage_space(void);

void read_data_from_queue(uint8_t *buf, uint8_t queue_id)
{
	OCTOPOS_XMbox_ReadBlocking(Mbox_regs[queue_id], (u32*) buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void write_data_to_queue(uint8_t *buf, uint8_t queue_id)
{
	OCTOPOS_XMbox_WriteBlocking(Mbox_regs[queue_id], (u32*) buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void mailbox_change_queue_access_bottom_half(uint8_t queue_id)
{
	/* Threshold registers will need to be reinitialized
	 * every time it switches ownership
	 */
	switch (queue_id) {
		case Q_STORAGE_CMD_OUT:
		case Q_STORAGE_DATA_OUT:
			OCTOPOS_XMbox_SetSendThreshold(Mbox_regs[queue_id], 0);
			OCTOPOS_XMbox_SetInterruptEnable(Mbox_regs[queue_id], OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);
			break;

		case Q_STORAGE_CMD_IN:
			OCTOPOS_XMbox_SetReceiveThreshold(Mbox_regs[queue_id], MAILBOX_DEFAULT_RX_THRESHOLD);
			OCTOPOS_XMbox_SetInterruptEnable(Mbox_regs[queue_id], OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;
		case Q_STORAGE_DATA_IN:
			OCTOPOS_XMbox_SetReceiveThreshold(Mbox_regs[queue_id], MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
			OCTOPOS_XMbox_SetInterruptEnable(Mbox_regs[queue_id], OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;

		default:
			_SEC_HW_ERROR("unknown/unsupported queue %d", queue_id);
	}
}

static void handle_change_queue_interrupts(void* callback_ref)
{
	uint8_t queue_id = (int) callback_ref;

	mailbox_change_queue_access_bottom_half(queue_id);
	octopos_mailbox_clear_interrupt(Mbox_ctrl_regs[queue_id]);
}

static void handle_mailbox_interrupts(void* callback_ref)
{
	u32         mask;
	OCTOPOS_XMbox       *mbox_inst = (OCTOPOS_XMbox *)callback_ref;

	_SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
	mask = OCTOPOS_XMbox_GetInterruptStatus(mbox_inst);

	if (mask & OCTOPOS_XMB_IX_STA) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_STA");
		if (callback_ref == &Mbox_storage_cmd_out) {
			sem_post(&interrupts[Q_STORAGE_CMD_OUT]);
		} else if (callback_ref == &Mbox_storage_data_out) {
			sem_post(&interrupts[Q_STORAGE_DATA_OUT]);
		}
	} else if (mask & OCTOPOS_XMB_IX_RTA) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_RTA");
		if (callback_ref == &Mbox_storage_cmd_in) {
			sem_post(&interrupts[Q_STORAGE_CMD_IN]);
		} else if (callback_ref == &Mbox_storage_data_in) {
			sem_post(&interrupts[Q_STORAGE_DATA_IN]);
		}
	} else if (mask & OCTOPOS_XMB_IX_ERR) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_ERR, from %p", callback_ref);
	} else {
		_SEC_HW_DEBUG("interrupt type unknown, mask %d, from %p", mask, callback_ref);
	}

	OCTOPOS_XMbox_ClearInterrupt(mbox_inst, mask);

	_SEC_HW_DEBUG("interrupt cleared");
}

void storage_event_loop(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		sem_wait(&interrupts[Q_STORAGE_CMD_IN]);
		OCTOPOS_XMbox_ReadBlocking(&Mbox_storage_cmd_in, (u32*) buf, MAILBOX_QUEUE_MSG_SIZE);
		process_request(buf, 0);
		OCTOPOS_XMbox_WriteBlocking(&Mbox_storage_cmd_out, (u32*) buf, MAILBOX_QUEUE_MSG_SIZE);
	}
}

int init_storage(void)
{
	int				Status;
	OCTOPOS_XMbox_Config	*Config_cmd_out, 
					*Config_cmd_in, 
					*Config_Data_out, 
					*Config_Data_in;

	initialize_pmodsd();

#ifndef ARCH_SEC_HW_BOOT
	/* Initialize OCTOPOS_XMbox */
	Config_cmd_in = OCTOPOS_XMbox_LookupConfig(XPAR_STORAGE_MBOX_CMD_IN_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_cmd_in, Config_cmd_in, Config_cmd_in->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_STORAGE_MBOX_CMD_IN_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_cmd_out = OCTOPOS_XMbox_LookupConfig(XPAR_STORAGE_MBOX_CMD_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_cmd_out, Config_cmd_out, Config_cmd_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_STORAGE_MBOX_CMD_OUT_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_Data_in = OCTOPOS_XMbox_LookupConfig(XPAR_STORAGE_MBOX_DATA_IN_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_data_in, Config_Data_in, Config_Data_in->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_STORAGE_MBOX_DATA_IN_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_Data_out = OCTOPOS_XMbox_LookupConfig(XPAR_STORAGE_MBOX_DATA_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_data_out, Config_Data_out, Config_Data_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_STORAGE_MBOX_DATA_OUT_DEVICE_ID);
		return XST_FAILURE;
	}

	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_storage_cmd_in, MAILBOX_DEFAULT_RX_THRESHOLD);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_cmd_in, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_storage_cmd_out, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_cmd_out, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_storage_data_in, MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_data_in, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_storage_data_out, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_data_out, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

	/* OctopOS mailbox maps must be initialized before setting up interrupts. */
	OMboxIds_init();

	/* Initialize pointers for bookkeeping */
	Mbox_regs[Q_STORAGE_CMD_IN] = &Mbox_storage_cmd_in;
	Mbox_regs[Q_STORAGE_CMD_OUT] = &Mbox_storage_cmd_out;
	Mbox_regs[Q_STORAGE_DATA_OUT] = &Mbox_storage_data_out;
	Mbox_regs[Q_STORAGE_DATA_IN] = &Mbox_storage_data_in;

	Mbox_ctrl_regs[Q_STORAGE_CMD_IN] = OCTOPOS_STORAGE_Q_STORAGE_IN_2_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_CMD_OUT] = OCTOPOS_STORAGE_Q_STORAGE_OUT_2_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_DATA_OUT] = OCTOPOS_STORAGE_Q_STORAGE_DATA_OUT_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_DATA_IN] = OCTOPOS_STORAGE_Q_STORAGE_DATA_IN_BASEADDR;

	/* Initialize XIntc hardware in case the domain is not power cycled */
	XIntc_Out32(XPAR_INTC_SINGLE_BASEADDR + 28, 0);

	/* Initialize XIntc */
	Status = XIntc_Initialize(&intc, XPAR_INTC_SINGLE_DEVICE_ID);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Initialize %d failed", XPAR_INTC_SINGLE_DEVICE_ID);
		return XST_FAILURE;
	}

	Status = XIntc_SelfTest(&intc);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			OMboxIntrs[P_STORAGE][Q_STORAGE_DATA_OUT],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_data_out);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				OMboxIntrs[P_STORAGE][Q_STORAGE_DATA_OUT]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			OMboxIntrs[P_STORAGE][Q_STORAGE_DATA_IN],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_data_in);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				OMboxIntrs[P_STORAGE][Q_STORAGE_DATA_IN]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			OMboxIntrs[P_STORAGE][Q_STORAGE_CMD_OUT],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_cmd_out);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				OMboxIntrs[P_STORAGE][Q_STORAGE_CMD_OUT]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			OMboxIntrs[P_STORAGE][Q_STORAGE_CMD_IN],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_storage_cmd_in);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				OMboxIntrs[P_STORAGE][Q_STORAGE_CMD_IN]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_CMD_IN],
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_CMD_IN);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
				OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_CMD_IN]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_CMD_OUT],
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_CMD_OUT);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
				OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_CMD_OUT]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_DATA_IN],
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_DATA_IN);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
				OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_DATA_IN]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_DATA_OUT],
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_DATA_OUT);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
				OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_DATA_OUT]);
		return XST_FAILURE;
	}

	Status = XIntc_Start(&intc, XIN_REAL_MODE);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Start failed");
		return XST_FAILURE;
	}

	/* Enable interrupts */
	XIntc_Enable(&intc, OMboxIntrs[P_STORAGE][Q_STORAGE_DATA_OUT]);
	XIntc_Enable(&intc, OMboxIntrs[P_STORAGE][Q_STORAGE_DATA_IN]);
	XIntc_Enable(&intc, OMboxIntrs[P_STORAGE][Q_STORAGE_CMD_OUT]);
	XIntc_Enable(&intc, OMboxIntrs[P_STORAGE][Q_STORAGE_CMD_IN]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_DATA_OUT]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_DATA_IN]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_CMD_OUT]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_STORAGE][Q_STORAGE_CMD_IN]);

	Xil_ExceptionInit();
	Xil_ExceptionEnable();

	sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, 0);
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, 0);
	sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, MAILBOX_QUEUE_SIZE);

	initialize_storage_space();
#endif

	return XST_SUCCESS;
}

void close_storage(void)
{
	/* no-op */
}

#endif /* ARCH_SEC_HW_STORAGE */
