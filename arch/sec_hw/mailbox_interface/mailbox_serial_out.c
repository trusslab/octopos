/* OctopOS Serial Out mailbox interface */
#ifdef ARCH_SEC_HW_SERIAL_OUT
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
sem_t           interrupt_serial_out;

cbuf_handle_t   cbuf_serial_out;


void get_chars_from_serial_out_queue(uint8_t *buf)
{
    uint32_t ptrbuf = 0;

    memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
    sem_wait_impatient_receive(&interrupt_serial_out, &Mbox, cbuf_serial_out);
    
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
    u32         mask;
    XMbox       *mbox_inst = (XMbox *)callback_ref;

    _SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
    mask = XMbox_GetInterruptStatus(mbox_inst);

    if (mask & XMB_IX_STA) {
        _SEC_HW_ERROR("Invalid interrupt XMB_IX_STA");
    } else if (mask & XMB_IX_RTA) {
        _SEC_HW_DEBUG("interrupt type: XMB_IX_RTA");

        sem_post(&interrupt_serial_out);
    } else if (mask & XMB_IX_ERR) {
        _SEC_HW_ERROR("interrupt type: XMB_IX_ERR, from %p", callback_ref);
    } else {
        _SEC_HW_ERROR("interrupt type unknown, mask %d, from %p", mask, callback_ref);
    }

    XMbox_ClearInterrupt(mbox_inst, mask);

    _SEC_HW_DEBUG("handle_mailbox_interrupts: interrupt cleared");
}

int init_serial_out(void)
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
    XMbox_SetReceiveThreshold(&Mbox, 0);
    XMbox_SetInterruptEnable(&Mbox, XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);

    Xil_ExceptionInit();
    Xil_ExceptionEnable();

    Status = XIntc_Initialize(&intc, XPAR_INTC_SINGLE_DEVICE_ID);
    if (Status != XST_SUCCESS) {
        _SEC_HW_ERROR("XIntc_Initialize %d failed", XPAR_INTC_SINGLE_DEVICE_ID);
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc, 
        XPAR_MICROBLAZE_0_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts, 
        (void*)&Mbox);
    if (Status != XST_SUCCESS) {
        _SEC_HW_ERROR("XIntc_Connect %d failed", 
            XPAR_MICROBLAZE_0_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR);
        return XST_FAILURE;
    }

    XIntc_Enable(&intc, XPAR_MICROBLAZE_0_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR);

    Status = XIntc_Start(&intc, XIN_REAL_MODE);
    if (Status != XST_SUCCESS) {
        _SEC_HW_ERROR("XIntc_Start failed");
        return XST_FAILURE;
    }

    sem_init(&interrupt_serial_out, 0, 0);

    cbuf_serial_out = circular_buf_get_instance(MAILBOX_QUEUE_SIZE);

    return XST_SUCCESS;
}

void close_serial_out(void)
{
    circular_buf_free(cbuf_serial_out);

    cleanup_platform();
}
#endif

