/* OctopOS Keyboard mailbox interface */
#ifdef ARCH_SEC_HW_KEYBOARD
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
sem_t			interrupt_keyboard;

cbuf_handle_t	cbuf_serial_in;

OCTOPOS_XMbox*	Mbox_regs[NUM_QUEUES + 1];
UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1];

uint8_t read_char_from_keyboard(void)
{
	return (uint8_t) getchar();
}

void put_char_on_keyboard_queue(uint8_t kchar)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	buf[0] = kchar;

	sem_wait_impatient_send(&interrupt_keyboard, &Mbox, (u32*) buf);
}

static void handle_mailbox_interrupts(void* callback_ref)
{
	u32 mask;
	OCTOPOS_XMbox *mbox_inst = (OCTOPOS_XMbox *)callback_ref;

	_SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
	mask = OCTOPOS_XMbox_GetInterruptStatus(mbox_inst);

	if (mask & OCTOPOS_XMB_IX_STA) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_STA");
		sem_post(&interrupt_keyboard);
	} else if (mask & OCTOPOS_XMB_IX_RTA) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_RTA");
	} else if (mask & OCTOPOS_XMB_IX_ERR) {
		_SEC_HW_ERROR("interrupt type: OCTOPOS_XMB_IX_ERR, from %p", 
			callback_ref);
	} else {
		_SEC_HW_ERROR("interrupt type unknown, mask %d, from %p", 
			mask, 
			callback_ref);
	}

	OCTOPOS_XMbox_ClearInterrupt(mbox_inst, mask);

	_SEC_HW_DEBUG("handle_mailbox_interrupts: interrupt cleared");
}

int init_keyboard(void)
{
	int Status;
	OCTOPOS_XMbox_Config *ConfigPtr, *Config_storage_data_out;

	ConfigPtr = OCTOPOS_XMbox_LookupConfig(XPAR_KEYBOARD_KEYBOARD_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox, 
		ConfigPtr, 
		ConfigPtr->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", 
			XPAR_KEYBOARD_KEYBOARD_DEVICE_ID);
		return XST_FAILURE;
	}

	/* OctopOS mailbox maps must be initialized before setting up interrupts. */
	OMboxIds_init();
	OCTOPOS_XMbox_SetSendThreshold(&Mbox, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox, 
		OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

	Mbox_regs[Q_KEYBOARD] = &Mbox;

#ifndef ARCH_SEC_HW_BOOT
	Xil_ExceptionInit();
	Xil_ExceptionEnable();

	/* Initialize XIntc hardware in case the domain is not power cycled */
	XIntc_Out32(XPAR_INTC_SINGLE_BASEADDR + 28, 0);

	Status = XIntc_Initialize(&intc, XPAR_INTC_SINGLE_DEVICE_ID);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Initialize %d failed", 
			XPAR_INTC_SINGLE_DEVICE_ID);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
		OMboxIntrs[P_KEYBOARD][Q_KEYBOARD],
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			OMboxIntrs[P_KEYBOARD][Q_KEYBOARD]);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, OMboxIntrs[P_KEYBOARD][Q_KEYBOARD]);

	Status = XIntc_Start(&intc, XIN_REAL_MODE);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Start failed");
		return XST_FAILURE;
	}
#else
	Config_storage_data_out = 
		OCTOPOS_XMbox_LookupConfig(XPAR_KEYBOARD_STORAGE_DATA_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_data_out,
		Config_storage_data_out, 
		Config_storage_data_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", 
			XPAR_KEYBOARD_STORAGE_DATA_OUT_DEVICE_ID);
		return XST_FAILURE;
	}

	Mbox_regs[Q_STORAGE_DATA_OUT] = &Mbox_storage_data_out;
	Mbox_ctrl_regs[Q_STORAGE_DATA_OUT] = 
		OCTOPOS_KEYBOARD_SERIAL_MAILBOX_STORAGE_DATA_OUT_BASEADDR;
#endif

#ifndef ARCH_SEC_HW
	setvbuf(stdin, NULL, _IONBF, 0);
#endif

	sem_init(&interrupt_keyboard, 0, MAILBOX_QUEUE_SIZE);
	cbuf_serial_in = circular_buf_get_instance(MAILBOX_QUEUE_SIZE);

	return XST_SUCCESS;
}

void close_keyboard(void)
{
	circular_buf_free(cbuf_serial_in);
}
#endif
