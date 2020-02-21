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

#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/error.h>

extern int p_runtime;
extern int q_runtime;
extern int q_os;

uint8_t 		load_buf[MAILBOX_QUEUE_MSG_SIZE - 1];
extern bool 	still_running;

extern int 		change_queue;

extern bool 	secure_ipc_mode;

/* Not all will be used */
sem_t 			interrupts[NUM_QUEUES + 1]; // FIXME Question why +1?
sem_t 			interrupt_change;

sem_t 			load_app_sem;

XMbox 			Mbox_out,
				Mbox_keyboard,
				Mbox_Runtime1,
				Mbox_Runtime2,
				Mbox_sys;

static XIntc 	intc;
cbuf_handle_t   cbuf_keyboard, cbuf_runtime;

XMbox*			Mbox_regs[NUM_QUEUES + 1];
UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1];

int write_syscall_response(uint8_t *buf);

void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id)
{
	UINTPTR queue_ptr;

	if (queue_id == Q_KEYBOARD) {
		queue_ptr = XPAR_OCTOPOS_MAILBOX_1WRI_0_BASEADDR;
	} else if (queue_id == Q_SERIAL_OUT) {
		queue_ptr = XPAR_OCTOPOS_MAILBOX_3WRI_0_BASEADDR;
	} else if (queue_id == q_runtime) {
		_SEC_HW_ERROR("unknown/unsupported queue %d", queue_id);
	// FIXME replace this if else with Mbox_ctrl_regs
	//	} else if (queue_id == Q_RUNTIME1) {
	} else {
		_SEC_HW_ERROR("unknown/unsupported queue %d", queue_id);
		return;
	}
	// FIXME add a indexed array to get correct proc_id
	octopos_mailbox_set_owner(queue_ptr, proc_id);

	// FIXME Question access mode read/write? We need to enforce that.
}

int mailbox_attest_queue_access(uint8_t queue_id, uint8_t access, uint8_t count)
{
	UINTPTR queue_ptr;

	// FIXME same as change_queue_access
	if (queue_id == Q_KEYBOARD) {
		queue_ptr = XPAR_OCTOPOS_MAILBOX_1WRI_0_BASEADDR;
	} else if (queue_id == Q_SERIAL_OUT) {
		queue_ptr = XPAR_OCTOPOS_MAILBOX_3WRI_0_BASEADDR;
	} else if (queue_id == q_runtime) {
		_SEC_HW_ERROR("unknown/unsupported queue %d", queue_id);
	} else {
		_SEC_HW_ERROR("unknown/unsupported queue %d", queue_id);
		return FALSE;
	}

	return octopos_mailbox_attest_quota_limit(queue_ptr, count);
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

void wait_on_queue(uint8_t queue_id)
{
	sem_wait(&interrupts[queue_id]);
}

void wait_for_app_load(void)
{
	sem_wait(&load_app_sem);
}

// FIXME move it away.
void app_main(struct runtime_api *api);

void load_application_arch(char *msg, struct runtime_api *api)
{
	app_main(api);
}

static void handle_fixed_timer_interrupts(void* ignored)
{
	int 		bytes_read;

	_SEC_HW_DEBUG("Fixed timer interrupt");

    uint8_t* buf = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
    bytes_read = sem_wait_one_time_receive_buf(&interrupts[q_runtime], Mbox_regs[q_runtime], buf);
	if (bytes_read == 0) {
		return;
	}
	
	if (buf[0] == RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG) {
		 write_syscall_response(buf);
		// FIXME: it use&interrupts[q_runtime] to wait for ANY available message on the runtime q
		// pay attion that it shouldnt be use anywhere else (e.g. wait for syscall response)
  		// sem_post(&interrupts[interrupt]);
		// if (!still_running)
		// keep_polling = false;
	} else if (buf[0] == RUNTIME_QUEUE_EXEC_APP_TAG) {
		memcpy(load_buf, &buf[1], MAILBOX_QUEUE_MSG_SIZE);
		sem_post(&load_app_sem);
	} else if (buf[0] == RUNTIME_QUEUE_CONTEXT_SWITCH_TAG) {
		// FIXME Zephyr not impl. One possible way: overwrite stack to return to a new app.
	//				pthread_cancel(app_thread);
	//				pthread_join(app_thread, NULL);
	//				int ret = pthread_create(&ctx_thread, NULL, store_context, NULL);
	//				if (ret)
	//					printf("Error: couldn't launch the app thread\n");
	//				has_ctx_thread = true;
	}
	free(buf);
}

static void handle_mailbox_interrupts(void* callback_ref)
{
    u32         mask;
    XMbox       *mbox_inst = (XMbox *)callback_ref;

    // FIXME Question why there are no availables[xx] sem?
    _SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
    mask = XMbox_GetInterruptStatus(mbox_inst);

    if (mask & XMB_IX_STA) {
        _SEC_HW_DEBUG("interrupt type: XMB_IX_STA");
        if (callback_ref == &Mbox_out) {
            /* Serial Out */
        	sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
        	sem_post(&interrupts[Q_SERIAL_OUT]);
        } else if (callback_ref == &Mbox_sys) {
        	/* Syscall request */
        	sem_init(&interrupts[q_os], 0, MAILBOX_QUEUE_SIZE);
        	sem_post(&interrupts[q_os]);
        	// FIXME: impl secure IPC (write to another runtime's queue)
//        } else if (callback_ref != Mbox_regs[q_runtime]) {
//        	/* IPC to other runtime */
//        	if (callback_ref == &Mbox_Runtime1) {
//        		sem_post(&interrupts[Q_RUNTIME1]);
//        	} else if (callback_ref == &Mbox_Runtime2) {
//        		sem_post(&interrupts[Q_RUNTIME2]);
//        	} else {
//        		_SEC_HW_ERROR("Error: invalid interrupt from %p", callback_ref);
//        	}
        } else {
        	_SEC_HW_ERROR("Error: invalid interrupt from %p", callback_ref);
        }
    } else if (mask & XMB_IX_RTA) {
        _SEC_HW_DEBUG("interrupt type: XMB_IX_RTA");
        if (callback_ref == &Mbox_keyboard) {
            /* Keyboard */
        	sem_init(&interrupts[Q_KEYBOARD], 0, 0);
        	sem_post(&interrupts[Q_KEYBOARD]);
        } else if (callback_ref == Mbox_regs[q_runtime]) {
        	/* Runtime queue */
        	if (!secure_ipc_mode) {
                sem_init(&interrupts[q_runtime], 0, 0);
                sem_post(&interrupts[q_runtime]);
        	} else {
        		// FIXME: impl secure IPC
        	}
        } else {
        	_SEC_HW_ERROR("Error: invalid interrupt from %p", callback_ref);
        }
    } else if (mask & XMB_IX_ERR) {
        _SEC_HW_ERROR("interrupt type: XMB_IX_ERR, from %p", callback_ref);
    } else {
        _SEC_HW_ERROR("interrupt type unknown, mask %ld, from %p", mask, callback_ref);
    }

//	/* interrupt handling loop */
//	while (keep_polling) {
////		read(fd_intr, &interrupt, 1);
//		if (interrupt < 1 || interrupt > (2 * NUM_QUEUES)) {
//			printf("Error: invalid interrupt (%d)\n", interrupt);
//			exit(-1);
//		} else if (interrupt > NUM_QUEUES) {
//			// FIXME: Question Zephyr What is change_queue? seems it is set for ipc
//			if ((interrupt - NUM_QUEUES) == change_queue) {
//				sem_post(&interrupt_change);
//				sem_post(&interrupts[q_runtime]);
//			}
//
//			/* ignore the rest */
//			continue;
//		} else if (interrupt == q_runtime && !secure_ipc_mode) {
//			uint8_t opcode[2];
//			uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
//
//			opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
//			opcode[1] = q_runtime;
////			write(fd_out, opcode, 2);
////			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
//				...
//		} else {
//			sem_post(&interrupts[interrupt]);
//		}
//	}
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

	ConfigPtr_sys = XMbox_LookupConfig(XPAR_ENCLAVE0_PS_MAILBOX_IF_1_DEVICE_ID);
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

//    XMbox_SetSendThreshold(&Mbox_keyboard, 0);
//    XMbox_SetReceiveThreshold(&Mbox_keyboard, 0);
//    XMbox_SetInterruptEnable(&Mbox_keyboard, XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);
//    XMbox_SetSendThreshold(&Mbox_out, 0);
//    XMbox_SetReceiveThreshold(&Mbox_out, 0);
//    XMbox_SetInterruptEnable(&Mbox_out, XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);
//    XMbox_SetSendThreshold(&Mbox_Runtime2, 0);
//    XMbox_SetReceiveThreshold(&Mbox_Runtime2, 0);
//    XMbox_SetInterruptEnable(&Mbox_Runtime2, XMB_IX_STA | XMB_IX_RTA | XMB_IX_ERR);
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

    // FIXME These will be per runtime configurations, unless we change the processor names in the macro
    Status = XIntc_Connect(&intc,
        XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_keyboard);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
        XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_out);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
        XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_Runtime1);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
        XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_Runtime2);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
    	XPAR_MICROBLAZE_2_AXI_INTC_ENCLAVE0_PS_MAILBOX_INTERRUPT_1_INTR,
        (XInterruptHandler)handle_mailbox_interrupts,
        (void*)&Mbox_sys);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    Status = XIntc_Connect(&intc,
    	XPAR_MICROBLAZE_2_AXI_INTC_FIT_TIMER_0_INTERRUPT_INTR,
        (XInterruptHandler)handle_fixed_timer_interrupts,
        0);
    if (Status != XST_SUCCESS) {
        return XST_FAILURE;
    }

    XIntc_Enable(&intc, XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR);
    XIntc_Enable(&intc, XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR);
    XIntc_Enable(&intc, XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR);
    XIntc_Enable(&intc, XPAR_MICROBLAZE_2_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR);
    XIntc_Enable(&intc, XPAR_MICROBLAZE_2_AXI_INTC_ENCLAVE0_PS_MAILBOX_INTERRUPT_1_INTR);
    XIntc_Enable(&intc, XPAR_MICROBLAZE_2_AXI_INTC_FIT_TIMER_0_INTERRUPT_INTR);

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

    return XST_SUCCESS;
}

void close_runtime(void)
{
	// FIXME Question upon termination, there's nothing to report to OS, right?
//	uint8_t opcode[2];
//	opcode[0] = MAILBOX_OPCODE_RESET;
//	write(fd_out, opcode, 2);

//    circular_buf_free(cbuf_keyboard);
//    circular_buf_free(cbuf_runtime);

	// FIXME: rm this when microblaze doesn't use ddr for cache
	Xil_DCacheDisable();
	Xil_ICacheDisable();
}


#endif
