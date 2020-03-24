/* OctopOS runtime mailbox interface */
#ifdef ARCH_SEC_HW_RUNTIME

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#include "xmbox.h"
#include "xil_cache.h"
#include "xstatus.h"
#include "xintc.h"

#include "arch/sec_hw.h"
#include "arch/semaphore.h"
#include "arch/ring_buffer.h"
#include "arch/octopos_mbox.h"
#include "arch/octopos_mbox_owner_map.h"

#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/error.h>

#if RUNTIME_ID == 1
	#define XPAR_COMMON_AXI_INTC_FIT_TIMER_INTERRUPT_INTR XPAR_MICROBLAZE_2_AXI_INTC_FIT_TIMER_0_INTERRUPT_INTR
	#define XPAR_COMMON_AXI_INTC_ENCLAVE_MAILBOX_INTERRUPT_INTR XPAR_MICROBLAZE_2_AXI_INTC_ENCLAVE0_PS_MAILBOX_INTERRUPT_1_INTR
	#define XPAR_COMMON_ENCLAVE_PS_MAILBOX_DEVICE_ID XPAR_ENCLAVE0_PS_MAILBOX_IF_1_DEVICE_ID
	#define XPAR_COMMON_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR
#elif RUNTIME_ID == 2
	#define XPAR_COMMON_AXI_INTC_FIT_TIMER_INTERRUPT_INTR XPAR_MICROBLAZE_3_AXI_INTC_FIT_TIMER_1_INTERRUPT_INTR
	#define XPAR_COMMON_AXI_INTC_ENCLAVE_MAILBOX_INTERRUPT_INTR XPAR_MICROBLAZE_3_AXI_INTC_ENCLAVE1_PS_MAILBOX_INTERRUPT_1_INTR
	#define XPAR_COMMON_ENCLAVE_PS_MAILBOX_DEVICE_ID XPAR_ENCLAVE1_PS_MAILBOX_IF_1_DEVICE_ID
	#define XPAR_COMMON_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR
#endif

extern int 		p_runtime;
extern int 		q_runtime;
extern int		q_os;

uint8_t 		load_buf[MAILBOX_QUEUE_MSG_SIZE - 1];
extern bool 	still_running;

extern int 		change_queue;

extern bool 	secure_ipc_mode;

sem_t 			interrupts[NUM_QUEUES + 1];
sem_t 			interrupt_change;

sem_t 			load_app_sem,
				runtime_wakeup;

XMbox 			Mbox_out,
				Mbox_keyboard,
				Mbox_Runtime1,
				Mbox_Runtime2,
				Mbox_sys;

static XIntc 	intc;
cbuf_handle_t   cbuf_keyboard, cbuf_runtime;

XMbox*			Mbox_regs[NUM_QUEUES + 1];
UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1];

_Bool           runtime_inited = FALSE;

int write_syscall_response(uint8_t *buf);
void app_main(struct runtime_api *api);

void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id)
{
    _SEC_HW_ASSERT_VOID(queue_id <= NUM_QUEUES + 1)

	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];

	_SEC_HW_ERROR("[0] queue%d:%08x", queue_id, octopos_mailbox_get_status_reg(queue_ptr));
	octopos_mailbox_deduct_and_set_owner(queue_ptr, OMboxIds[queue_id][proc_id]);

	_SEC_HW_ERROR("[1] queue%d:%08x", queue_id, octopos_mailbox_get_status_reg(queue_ptr));
}

int mailbox_attest_queue_access(uint8_t queue_id, uint8_t access, uint16_t count)
{
    _SEC_HW_ASSERT_VOID(queue_id <= NUM_QUEUES + 1)

	u8 factor = MAILBOX_QUEUE_MSG_SIZE / 4;
	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];

	if (octopos_mailbox_attest_quota_limit(queue_ptr, count * factor)) {
        /* threshold regs will need to be inited everytime it switches */
        switch (queue_id) {
            case Q_KEYBOARD:
                XMbox_SetSendThreshold(&Mbox_keyboard, 0);
                XMbox_SetReceiveThreshold(&Mbox_keyboard, 0);
                XMbox_SetInterruptEnable(&Mbox_keyboard, XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);
                break;

            case Q_SERIAL_OUT:
                XMbox_SetSendThreshold(&Mbox_out, 0);
                XMbox_SetReceiveThreshold(&Mbox_out, 0);
                XMbox_SetInterruptEnable(&Mbox_out, XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);
                break;

            case Q_RUNTIME1:
                XMbox_SetSendThreshold(&Mbox_Runtime1, 0);
                XMbox_SetReceiveThreshold(&Mbox_Runtime1, 0);
                XMbox_SetInterruptEnable(&Mbox_Runtime1, XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);
                break;

            case Q_RUNTIME2:
                XMbox_SetSendThreshold(&Mbox_Runtime2, 0);
                XMbox_SetReceiveThreshold(&Mbox_Runtime2, 0);
                XMbox_SetInterruptEnable(&Mbox_Runtime2, XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);
                break;

            default:
                _SEC_HW_ERROR("unknown/unsupported queue %d", queue_id);
        }

        return TRUE;
    } else {
        return FALSE;
    }
}

static void _runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
    sem_wait_impatient_receive_buf(&interrupts[queue_id], Mbox_regs[queue_id], (u8*) buf);
}

static void _runtime_send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
    sem_wait_impatient_send(&interrupts[queue_id], Mbox_regs[queue_id], (u32*) buf);
}

void runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_recv_msg_from_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE);
}

void runtime_send_msg_on_queue(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_send_msg_on_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE);
}

void runtime_recv_msg_from_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_recv_msg_from_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_send_msg_on_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void is_ownership_change(int *is_change)
{
	sem_getvalue(&interrupt_change, is_change);
	if (*is_change)
		sem_wait(&interrupt_change);
}

void reset_queue_sync(uint8_t queue_id, int init_val)
{
	sem_init(&interrupts[queue_id], 0, init_val);
}

void queue_sync_getval(uint8_t queue_id, int *val)
{
	sem_getvalue(&interrupts[queue_id], val);
}

void wait_on_queue(uint8_t queue_id, uint8_t *buf)
{
	sem_wait_impatient_receive_buf(&interrupts[queue_id], Mbox_regs[queue_id], buf);
}

void wait_for_app_load(void)
{
	sem_wait(&load_app_sem);
}

void load_application_arch(char *msg, struct runtime_api *api)
{
	app_main(api);
}

static void handle_fixed_timer_interrupts(void* ignored)
{
	int 		bytes_read;

	if (q_runtime == 0 || !runtime_inited) {
		return;
	}

	// FIXME this calloc and free in most cases is a waste
    uint8_t* buf = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
    bytes_read = sem_wait_one_time_receive_buf(&runtime_wakeup, Mbox_regs[q_runtime], buf);
	if (bytes_read == 0) {
		free(buf);
		return;
	}
	
	if (buf[0] == RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG) {
        // FIXME syscall are blocking wait on resp, this intr isn't in use.
        // There is a small chance that the OS sends something other than
        // syscall resp.
		_SEC_HW_DEBUG("RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG");
//		 write_syscall_response(buf);
  		 sem_post(&interrupts[q_runtime]);
	} else if (buf[0] == RUNTIME_QUEUE_EXEC_APP_TAG) {
		_SEC_HW_DEBUG("RUNTIME_QUEUE_EXEC_APP_TAG");
		memcpy(load_buf, &buf[1], MAILBOX_QUEUE_MSG_SIZE);
		sem_post(&load_app_sem);
	} else if (buf[0] == RUNTIME_QUEUE_CONTEXT_SWITCH_TAG) {
		_SEC_HW_DEBUG("RUNTIME_QUEUE_CONTEXT_SWITCH_TAG");
		// FIXME Zephyr not impl. One possible way: overwrite stack to return to a new app.
	}
	free(buf);
}

static void handle_octopos_mailbox_interrupts(void* callback_ref)
{
	uint8_t queue_id = (int) callback_ref;
//    _SEC_HW_ERROR("interrupt_change");
	octopos_mailbox_clear_interrupt(OMboxCtrlIntrs[p_runtime][queue_id]);

	if (queue_id == change_queue) {
		_SEC_HW_ERROR("interrupt_change");
		sem_post(&interrupt_change);
	}
}

static void handle_mailbox_interrupts(void* callback_ref)
{
    u32         mask;
    XMbox       *mbox_inst = (XMbox *)callback_ref;

    mask = XMbox_GetInterruptStatus(mbox_inst);

    if (mask & XMB_IX_STA) {
        if (callback_ref == &Mbox_out) {
            /* Serial Out */
        	sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
        	sem_post(&interrupts[Q_SERIAL_OUT]);
        } else if (callback_ref == &Mbox_sys) {
        	/* Syscall request */
        	sem_init(&interrupts[q_os], 0, MAILBOX_QUEUE_SIZE);
        	sem_post(&interrupts[q_os]);
        } else if (callback_ref != Mbox_regs[q_runtime]) {
        	/* IPC to other runtime */
        	if (callback_ref == &Mbox_Runtime1) {
        		sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE);
        		sem_post(&interrupts[Q_RUNTIME1]);
        	} else if (callback_ref == &Mbox_Runtime2) {
        		sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE);
        		sem_post(&interrupts[Q_RUNTIME2]);
        	} else {
        		_SEC_HW_ERROR("Error: invalid interrupt from %p", callback_ref);
        	}
        } else {
        	_SEC_HW_ERROR("Error: invalid interrupt from %p", callback_ref);
        }
    } else if (mask & XMB_IX_RTA) {
        if (callback_ref == &Mbox_keyboard) {
            /* Keyboard */
        	sem_init(&interrupts[Q_KEYBOARD], 0, 0);
        	sem_post(&interrupts[Q_KEYBOARD]);
        } else if (callback_ref == Mbox_regs[q_runtime]) {
        	/* Runtime queue */
        	if (!secure_ipc_mode) {
                sem_init(&runtime_wakeup, 0, 0);
                sem_post(&runtime_wakeup);
        	}
        } else {
        	_SEC_HW_ERROR("Error: invalid interrupt from %p", callback_ref);
        }
    } else if (mask & XMB_IX_ERR) {
        _SEC_HW_ERROR("interrupt type: XMB_IX_ERR, from %p", callback_ref);
    } else {
        _SEC_HW_ERROR("interrupt type unknown, mask %ld, from %p", mask, callback_ref);
    }

    XMbox_ClearInterrupt(mbox_inst, mask);
}

void *run_app(void *load_buf);

void runtime_core()
{
	run_app(NULL);
}

/* Initializes the runtime and its mailbox */
int init_runtime(int runtime_id)
{
    int             Status;
    XMbox_Config   	*ConfigPtr_out,
					*ConfigPtr_keyboard,
					*ConfigPtr_Runtime1,
					*ConfigPtr_Runtime2,
					*ConfigPtr_sys;

	switch(runtime_id) {
	case 1:
		p_runtime = P_RUNTIME1;
		q_runtime = Q_RUNTIME1;
		q_os = Q_OS1;
		break;
	case 2:
		p_runtime = P_RUNTIME2;
		q_runtime = Q_RUNTIME2;
		q_os = Q_OS2;
		break;
	default:
		return -1;
	}

	ConfigPtr_sys = XMbox_LookupConfig(XPAR_COMMON_ENCLAVE_PS_MAILBOX_DEVICE_ID);
    Status = XMbox_CfgInitialize(&Mbox_sys, ConfigPtr_sys, ConfigPtr_sys->BaseAddress);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

	ConfigPtr_keyboard = XMbox_LookupConfig(XPAR_MBOX_0_DEVICE_ID);
    Status = XMbox_CfgInitialize(&Mbox_keyboard, ConfigPtr_keyboard, ConfigPtr_keyboard->BaseAddress);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }
	ConfigPtr_out = XMbox_LookupConfig(XPAR_MBOX_1_DEVICE_ID);
    Status = XMbox_CfgInitialize(&Mbox_out, ConfigPtr_out, ConfigPtr_out->BaseAddress);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }
    ConfigPtr_Runtime1 = XMbox_LookupConfig(XPAR_MBOX_2_DEVICE_ID);
    Status = XMbox_CfgInitialize(&Mbox_Runtime1, ConfigPtr_Runtime1, ConfigPtr_Runtime1->BaseAddress);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }
	ConfigPtr_Runtime2 = XMbox_LookupConfig(XPAR_MBOX_3_DEVICE_ID);
    Status = XMbox_CfgInitialize(&Mbox_Runtime2, ConfigPtr_Runtime2, ConfigPtr_Runtime2->BaseAddress);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Mbox_regs[q_os] = &Mbox_sys;
   	Mbox_regs[Q_RUNTIME1] = &Mbox_Runtime1;
   	Mbox_regs[Q_RUNTIME2] = &Mbox_Runtime2;
   	Mbox_regs[Q_KEYBOARD] = &Mbox_keyboard;
   	Mbox_regs[Q_SERIAL_OUT] = &Mbox_out;

    Mbox_ctrl_regs[Q_KEYBOARD] = XPAR_OCTOPOS_MAILBOX_1WRI_0_BASEADDR;
    Mbox_ctrl_regs[Q_SERIAL_OUT] = XPAR_OCTOPOS_MAILBOX_3WRI_0_BASEADDR;
    Mbox_ctrl_regs[Q_RUNTIME1] = XPAR_OCTOPOS_MAILBOX_3WRI_2_BASEADDR;
    Mbox_ctrl_regs[Q_RUNTIME2] = XPAR_OCTOPOS_MAILBOX_3WRI_1_BASEADDR;

    /* OctopOS mailbox maps must be initialized before setting up interrupts. */
	OMboxIds_init();

    XMbox_SetSendThreshold(Mbox_regs[q_runtime], 0);
    XMbox_SetReceiveThreshold(Mbox_regs[q_runtime], 0);
    XMbox_SetInterruptEnable(Mbox_regs[q_runtime], XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);
    XMbox_SetSendThreshold(&Mbox_sys, 0);
    XMbox_SetReceiveThreshold(&Mbox_sys, 0);
    XMbox_SetInterruptEnable(&Mbox_sys, XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);

    Xil_ExceptionInit();
    Xil_ExceptionEnable();

    Status = XIntc_Initialize(&intc, XPAR_INTC_SINGLE_DEVICE_ID);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
    	XPAR_COMMON_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_keyboard);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
    	XPAR_COMMON_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_out);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
    	XPAR_COMMON_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_Runtime1);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
    	XPAR_COMMON_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_Runtime2);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
    	XPAR_COMMON_AXI_INTC_ENCLAVE_MAILBOX_INTERRUPT_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_sys);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
    	XPAR_COMMON_AXI_INTC_FIT_TIMER_INTERRUPT_INTR,
        (XInterruptHandler)handle_fixed_timer_interrupts,
        0);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    /* Connect the OctopOS mailbox interrupts */
    Status = XIntc_Connect(&intc,
    	OMboxCtrlIntrs[p_runtime][Q_RUNTIME1],
        (XInterruptHandler)handle_octopos_mailbox_interrupts,
		(void*) Q_RUNTIME1);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
    	OMboxCtrlIntrs[p_runtime][Q_RUNTIME2],
        (XInterruptHandler)handle_octopos_mailbox_interrupts,
		(void*) Q_RUNTIME2);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR);
    XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR);
    XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR);
    XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR);
    XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_ENCLAVE_MAILBOX_INTERRUPT_INTR);
    XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_FIT_TIMER_INTERRUPT_INTR);
    XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_RUNTIME1]);
    XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_RUNTIME2]);

    Status = XIntc_Start(&intc, XIN_REAL_MODE);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

	sem_init(&interrupts[q_os], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[q_runtime], 0, 0);
    sem_init(&interrupts[Q_KEYBOARD], 0, 0);
    sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);

	sem_init(&load_app_sem, 0, 0);

//	cbuf_keyboard = circular_buf_get_instance(MAILBOX_QUEUE_SIZE);
//	cbuf_runtime = circular_buf_get_instance(MAILBOX_QUEUE_SIZE);



    runtime_inited = TRUE;

    return XST_SUCCESS;
}

void close_runtime(void)
{
	// FIXME: rm this when microblaze doesn't use ddr for cache
	Xil_DCacheDisable();
	Xil_ICacheDisable();
}

#endif
