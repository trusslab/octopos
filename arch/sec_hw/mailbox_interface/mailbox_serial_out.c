/* OctopOS Serial Out mailbox interface */
#ifdef ARCH_SEC_HW_SERIAL_OUT
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

#include "octopos/mailbox.h"

OCTOPOS_XMbox	Mbox, Mbox_storage_data_out;
XIntc			intc;
uint32_t		recv_message;
sem_t			interrupt_serial_out;

cbuf_handle_t	cbuf_serial_out;

OCTOPOS_XMbox*	Mbox_regs[NUM_QUEUES + 1];
UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1];

void get_chars_from_serial_out_queue(uint8_t *buf)
{
	uint32_t ptrbuf = 0;

	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	sem_wait_impatient_receive_cbuf(&interrupt_serial_out, &Mbox, cbuf_serial_out);
	
	circular_buf_get(cbuf_serial_out, (uint32_t*) &ptrbuf);
	memcpy(buf ,(void*) ptrbuf, MAILBOX_QUEUE_MSG_SIZE);

	free((void*) ptrbuf);
}

void write_chars_to_serial_out(uint8_t *buf)
{
	printf("%s", buf);
}

static void handle_mailbox_interrupts(void* callback_ref)
{
	u32			mask;
	OCTOPOS_XMbox		*mbox_inst = (OCTOPOS_XMbox *)callback_ref;

	_SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
	mask = OCTOPOS_XMbox_GetInterruptStatus(mbox_inst);

	if (mask & OCTOPOS_XMB_IX_STA) {
		_SEC_HW_ERROR("Invalid interrupt OCTOPOS_XMB_IX_STA");
	} else if (mask & OCTOPOS_XMB_IX_RTA) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_RTA");

		sem_post(&interrupt_serial_out);
	} else if (mask & OCTOPOS_XMB_IX_ERR) {
		_SEC_HW_ERROR("interrupt type: OCTOPOS_XMB_IX_ERR, from %p", callback_ref);
	} else {
		_SEC_HW_ERROR("interrupt type unknown, mask %d, from %p", mask, callback_ref);
	}

	OCTOPOS_XMbox_ClearInterrupt(mbox_inst, mask);

	_SEC_HW_DEBUG("handle_mailbox_interrupts: interrupt cleared");
}

int init_serial_out(void)
{
	int Status;
	OCTOPOS_XMbox_Config *ConfigPtr, *Config_storage_data_out;

	Xil_ICacheEnable();
	Xil_DCacheEnable();

	ConfigPtr = OCTOPOS_XMbox_LookupConfig(XPAR_SERIAL_OUT_SERIAL_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox, ConfigPtr, ConfigPtr->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_SERIAL_OUT_SERIAL_OUT_DEVICE_ID);
		return XST_FAILURE;
	}

	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox, MAILBOX_MAX_COMMAND_SIZE);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	Mbox_regs[Q_SERIAL_OUT] = &Mbox;

#ifndef ARCH_SEC_HW_BOOT
	Xil_ExceptionInit();
	Xil_ExceptionEnable();

	/* Initialize XIntc hardware in case the domain is not power cycled */
	XIntc_Out32(XPAR_INTC_SINGLE_BASEADDR + 28, 0);

	Status = XIntc_Initialize(&intc, XPAR_INTC_SINGLE_DEVICE_ID);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Initialize %d failed", XPAR_INTC_SINGLE_DEVICE_ID);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
		XPAR_SECURE_SERIAL_OUT_MICROBLAZE_0_AXI_INTC_SECURE_SERIAL_OUT_OCTOPOS_MAILBOX_3WRI_0_INTERRUPT_FIXED_INTR,
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			XPAR_SECURE_SERIAL_OUT_MICROBLAZE_0_AXI_INTC_SECURE_SERIAL_OUT_OCTOPOS_MAILBOX_3WRI_0_INTERRUPT_FIXED_INTR);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_SECURE_SERIAL_OUT_MICROBLAZE_0_AXI_INTC_SECURE_SERIAL_OUT_OCTOPOS_MAILBOX_3WRI_0_INTERRUPT_FIXED_INTR);

	Status = XIntc_Start(&intc, XIN_REAL_MODE);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Start failed");
		return XST_FAILURE;
	}
#else
	Config_storage_data_out = OCTOPOS_XMbox_LookupConfig(XPAR_SERIAL_OUT_STORAGE_DATA_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_data_out,
		Config_storage_data_out, 
		Config_storage_data_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_SERIAL_OUT_STORAGE_DATA_OUT_DEVICE_ID);
		return XST_FAILURE;
	}

//	/* it doesn't matter because we are not using interrupt for booting */
//	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_storage_data_out, MAILBOX_MAX_COMMAND_SIZE);
//	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_data_out, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	Mbox_regs[Q_STORAGE_DATA_OUT] = &Mbox_storage_data_out;
	Mbox_ctrl_regs[Q_STORAGE_DATA_OUT] = OCTOPOS_SERIAL_OUT_MAILBOX_STORAGE_DATA_OUT_BASEADDR;
#endif

	sem_init(&interrupt_serial_out, 0, 0);

	cbuf_serial_out = circular_buf_get_instance(MAILBOX_QUEUE_SIZE);

	return XST_SUCCESS;
}

void close_serial_out(void)
{
	circular_buf_free(cbuf_serial_out);

	Xil_DCacheDisable();
	Xil_ICacheDisable();
}
#endif

