/* OctopOS Keyboard mailbox interface */
#ifdef ARCH_SEC_HW_KEYBOARD
#include <stdio.h>
#include <stdlib.h>
#include "xil_printf.h"
#include "sleep.h"
#include "xstatus.h"
#include "xmbox.h"
#include "xintc.h"

#include "arch/sec_hw.h"
#include "arch/semaphore.h"
#include "arch/ring_buffer.h"

#include "octopos/mailbox.h"

XMbox           Mbox;
XIntc           intc;
uint32_t        recv_message;
sem_t           interrupt_keyboard;

cbuf_handle_t   cbuf_serial_in;


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
    u32         mask;
    XMbox       *mbox_inst = (XMbox *)callback_ref;

    _SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
    mask = XMbox_GetInterruptStatus(mbox_inst);

    if (mask & XMB_IX_STA) {
        _SEC_HW_DEBUG("interrupt type: XMB_IX_STA");
        sem_post(&interrupt_keyboard);
    } else if (mask & XMB_IX_RTA) {
        _SEC_HW_DEBUG("interrupt type: XMB_IX_RTA");
    } else if (mask & XMB_IX_ERR) {
        _SEC_HW_ERROR("interrupt type: XMB_IX_ERR, from %p", callback_ref);
    } else {
        _SEC_HW_ERROR("interrupt type unknown, mask %d, from %p", mask, callback_ref);
    }

    XMbox_ClearInterrupt(mbox_inst, mask);

    _SEC_HW_DEBUG("handle_mailbox_interrupts: interrupt cleared");
}

int init_keyboard(void)
{
    int             Status;
    XMbox_Config*   ConfigPtr;

    init_platform();

    ConfigPtr = XMbox_LookupConfig(XPAR_MBOX_0_DEVICE_ID);
    Status = XMbox_CfgInitialize(&Mbox, ConfigPtr, ConfigPtr->BaseAddress);
    if (Status != XST_SUCCESS) {
        _SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MBOX_0_DEVICE_ID);
        return XST_FAILURE;
    }

    XMbox_SetSendThreshold(&Mbox, 0);
    XMbox_SetInterruptEnable(&Mbox, XMB_IX_STA | XMB_IX_ERR);

    Xil_ExceptionInit();
    Xil_ExceptionEnable();

    Status = XIntc_Initialize(&intc, XPAR_INTC_SINGLE_DEVICE_ID);
    if (Status != XST_SUCCESS) {
        _SEC_HW_ERROR("XIntc_Initialize %d failed", XPAR_INTC_SINGLE_DEVICE_ID);
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc, 
        XPAR_MICROBLAZE_1_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts, 
        (void*)&Mbox);
    if (Status != XST_SUCCESS) {
        _SEC_HW_ERROR("XIntc_Connect %d failed", 
            XPAR_MICROBLAZE_1_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR);
        return XST_FAILURE;
    }

    XIntc_Enable(&intc, XPAR_MICROBLAZE_1_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR);

    Status = XIntc_Start(&intc, XIN_REAL_MODE);
    if (Status != XST_SUCCESS) {
        _SEC_HW_ERROR("XIntc_Start failed");
        return XST_FAILURE;
    }

    setvbuf(stdin, NULL, _IONBF, 0);

    sem_init(&interrupt_keyboard, 0, MAILBOX_QUEUE_SIZE);

    cbuf_serial_in = circular_buf_get_instance(MAILBOX_QUEUE_SIZE);

    return XST_SUCCESS;
}

void close_keyboard(void)
{
    circular_buf_free(cbuf_serial_in);

    cleanup_platform();
}
#endif
