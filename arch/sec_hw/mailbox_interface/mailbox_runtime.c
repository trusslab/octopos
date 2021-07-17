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
#ifndef ARCH_SEC_HW_BOOT
#include "arch/preload_application_map.h"
#endif

#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/error.h>

#if RUNTIME_ID == 1
	#define XPAR_COMMON_AXI_INTC_FIT_TIMER_INTERRUPT_INTR XPAR_MICROBLAZE_2_AXI_INTC_FIT_TIMER_0_INTERRUPT_INTR
	#define XPAR_COMMON_AXI_INTC_ENCLAVE_MAILBOX_INTERRUPT_INTR XPAR_MICROBLAZE_2_AXI_INTC_ENCLAVE0_PS_MAILBOX_INTERRUPT_1_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_1WRI_0_INTERRUPT_1_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_3WRI_0_INTERRUPT_1_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_3WRI_2_INTERRUPT_FIXED_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_3WRI_1_INTERRUPT_1_INTR
	#define XPAR_COMMON_AXI_INTC_Q_STORAGE_DATA_OUT_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_1WRI_1_INTERRUPT_1_INTR
	#define XPAR_COMMON_AXI_INTC_Q_STORAGE_DATA_IN_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_OCTOPOS_MAILBOX_4WRI_0_INTERRUPT_1_INTR
	#define XPAR_COMMON_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_1_INTR
	#define XPAR_COMMON_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_0_INTR XPAR_MICROBLAZE_2_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_1_INTR
#elif RUNTIME_ID == 2
	#define XPAR_COMMON_AXI_INTC_FIT_TIMER_INTERRUPT_INTR XPAR_MICROBLAZE_3_AXI_INTC_FIT_TIMER_1_INTERRUPT_INTR
	#define XPAR_COMMON_AXI_INTC_ENCLAVE_MAILBOX_INTERRUPT_INTR XPAR_MICROBLAZE_3_AXI_INTC_ENCLAVE1_PS_MAILBOX_INTERRUPT_1_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_1WRI_0_INTERRUPT_2_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_3WRI_0_INTERRUPT_2_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_3WRI_2_INTERRUPT_1_INTR
	#define XPAR_COMMON_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_3WRI_1_INTERRUPT_CTRL_FIXED_INTR
	#define XPAR_COMMON_AXI_INTC_Q_STORAGE_DATA_OUT_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_1WRI_1_INTERRUPT_2_INTR
	#define XPAR_COMMON_AXI_INTC_Q_STORAGE_DATA_IN_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_OCTOPOS_MAILBOX_4WRI_0_INTERRUPT_2_INTR
	#define XPAR_COMMON_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_2_INTR
	#define XPAR_COMMON_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_0_INTR XPAR_MICROBLAZE_3_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_2_INTR
#endif

#ifdef ARCH_SEC_HW_BOOT
int		p_runtime = 0;
int		q_runtime = 0;
int		q_os = 0;
#else
extern int		p_runtime;
extern int		q_runtime;
extern int		q_os;
#endif

uint8_t 		load_buf[MAILBOX_QUEUE_MSG_SIZE - 1];
extern bool 	still_running;
extern int 		change_queue;
extern bool 	secure_ipc_mode;

sem_t 			interrupts[NUM_QUEUES + 1];
sem_t 			interrupt_change;

sem_t 			load_app_sem,
				runtime_wakeup,
				syscall_wakeup,
				secure_ipc_receive_sem;

OCTOPOS_XMbox 	Mbox_out,
				Mbox_keyboard,
				Mbox_Runtime1,
				Mbox_Runtime2,
				Mbox_sys,
				Mbox_storage_cmd_in,
				Mbox_storage_cmd_out,
				Mbox_storage_data_in,
				Mbox_storage_data_out;

static XIntc 	intc;
cbuf_handle_t   cbuf_keyboard, cbuf_runtime;

OCTOPOS_XMbox*	Mbox_regs[NUM_QUEUES + 1];
UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1] = {0};
_Bool			MBOX_PENDING_STA[NUM_QUEUES + 1] = {0};

_Bool			runtime_inited = FALSE;
_Bool			runtime_terminated = FALSE;
_Bool			need_to_store_context = FALSE;

int write_syscall_response(uint8_t *buf);
int write_to_shell(char *data, int size);
int inform_os_of_termination(void);
void close_runtime(void);
void *store_context(void *data);

void mailbox_yield_to_previous_owner(uint8_t queue_id)
{
	_SEC_HW_ASSERT_VOID(queue_id <= NUM_QUEUES + 1)

	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];

	_SEC_HW_DEBUG("Before yield: queue%d:%08x", queue_id, octopos_mailbox_get_status_reg(queue_ptr));
	/* This delay waits for the receiver to finish reading */
	/* FIXME: replace with a reliable waiting mechanism */
	usleep(100);
	octopos_mailbox_deduct_and_set_owner(queue_ptr, P_PREVIOUS);

	_SEC_HW_DEBUG("After yield: queue%d:%08x",
			queue_id,
			octopos_mailbox_get_status_reg(queue_ptr));
}

int mailbox_attest_queue_access(uint8_t queue_id, limit_t count,
		timeout_t timeout)
{
	_SEC_HW_ASSERT_NON_VOID(queue_id <= NUM_QUEUES + 1)

	_Bool result = TRUE;
	u8 factor = MAILBOX_QUEUE_MSG_SIZE / 4;
	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];

	result &= octopos_mailbox_attest_owner_fast(queue_ptr);
	result &= octopos_mailbox_attest_quota_limit(queue_ptr,
			count * factor);

	/* FIXME: implement timeout attestation */

	return result;
}

int mailbox_attest_queue_owner(uint8_t queue_id, uint8_t owner)
{
	_SEC_HW_ASSERT_NON_VOID(queue_id <= NUM_QUEUES + 1)

	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];

	return octopos_mailbox_attest_owner(queue_ptr, OMboxIds[queue_id][owner]);
}

u8 mailbox_get_queue_owner(uint8_t queue_id)
{
	_SEC_HW_ASSERT_NON_VOID(queue_id <= NUM_QUEUES + 1)

	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];

	return octopos_mailbox_get_owner(queue_ptr);
}

/* In case the other runtime refuses to yield, we forcefully
 * deplete the quota by repeatedly reading the mailbox.
 */
void mailbox_force_ownership(uint8_t queue_id, uint8_t owner)
{
	_SEC_HW_ERROR("forcing a yield on queue %d", queue_id);
	_SEC_HW_ASSERT_VOID(queue_id <= NUM_QUEUES + 1)

	u32 bytes_read;
	uint8_t *message_buffer = calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));

	while(!mailbox_attest_queue_owner(q_runtime, P_OS)){
		usleep(10);
		OCTOPOS_XMbox_Read(Mbox_regs[queue_id],
				(u32*)(message_buffer),
				MAILBOX_QUEUE_MSG_SIZE,
				&bytes_read);
	}

	free(message_buffer);
}

void mailbox_change_queue_access_bottom_half(uint8_t queue_id)
{
	/* Threshold registers will need to be reinitialized
	 * every time it switches ownership
	 */
	switch (queue_id) {
		case Q_KEYBOARD:
			OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_keyboard, MAILBOX_DEFAULT_RX_THRESHOLD);
			OCTOPOS_XMbox_SetInterruptEnable(&Mbox_keyboard, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;

		case Q_SERIAL_OUT:
			OCTOPOS_XMbox_SetSendThreshold(&Mbox_out, 0);
			OCTOPOS_XMbox_SetInterruptEnable(&Mbox_out, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);
			break;

		case Q_RUNTIME1:
			OCTOPOS_XMbox_SetSendThreshold(&Mbox_Runtime1, 0);
			OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_Runtime1, MAILBOX_DEFAULT_RX_THRESHOLD);
			OCTOPOS_XMbox_SetInterruptEnable(&Mbox_Runtime1, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;

		case Q_RUNTIME2:
			OCTOPOS_XMbox_SetSendThreshold(&Mbox_Runtime2, 0);
			OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_Runtime2, MAILBOX_DEFAULT_RX_THRESHOLD);
			OCTOPOS_XMbox_SetInterruptEnable(&Mbox_Runtime2, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;

		case Q_STORAGE_DATA_OUT:
			OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_storage_data_out, MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
			OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_data_out, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;

		case Q_STORAGE_DATA_IN:
			OCTOPOS_XMbox_SetSendThreshold(&Mbox_storage_data_in, 0);
			OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_data_in, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);
			break;

		case Q_STORAGE_CMD_OUT:
			OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_storage_cmd_out, MAILBOX_DEFAULT_RX_THRESHOLD);
			OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_cmd_out, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;

		case Q_STORAGE_CMD_IN:
			OCTOPOS_XMbox_SetSendThreshold(&Mbox_storage_cmd_in, 0);
			OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_cmd_in, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);
			break;

		default:
			_SEC_HW_ERROR("unknown/unsupported queue %d", queue_id);
	}
}

static void _runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{ //FIXME: large queue
	sem_wait_impatient_receive_buf(&interrupts[queue_id], Mbox_regs[queue_id], (u8*) buf);
}

static void _runtime_send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	sem_wait_impatient_send(&interrupts[queue_id], Mbox_regs[queue_id], (u32*) buf);
}

static void _runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	sem_wait_impatient_send_large(&interrupts[queue_id], Mbox_regs[queue_id], (u32*) buf);
}

void runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_recv_msg_from_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE);
}

void runtime_send_msg_on_queue(uint8_t *buf, uint8_t queue_id)
{
	/* The reader may concurrently read. In such cases, the mailbox may generate
	 * multiple OCTOPOS_XMB_IX_STA interrupts. We raise this flag to avoid duplicate 
	 * sem_posts in the interrupt handler. 
	 */
	MBOX_PENDING_STA[queue_id] = TRUE;
	return _runtime_send_msg_on_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE);
}

void runtime_recv_msg_from_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_recv_msg_from_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_send_msg_on_queue_large(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE_LARGE);
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
	sem_wait(&syscall_wakeup);
}

void wait_for_app_load(void)
{
	sem_wait(&load_app_sem);
}

void load_application_arch(char *msg, struct runtime_api *api)
{
	char output_buf[64];    
	int num_chars = 0;     

	if (msg[strlen(msg) - 1] == '\r' || msg[strlen(msg) - 1] == '\n')
			msg[strlen(msg) - 1] = '\0';

	void* app_main = preloaded_app(msg);

	if (!app_main) {
		_SEC_HW_DEBUG("app %s does not exist", msg);
		
		memset(output_buf, 0x0, 64);                                        
		num_chars = snprintf(output_buf, 61, "app %s does not exist\r\n", msg);        
		write_to_shell(output_buf, num_chars);

		return;
	}

	_SEC_HW_DEBUG("loading %s: %p", msg, app_main);

	/* This is to clear semaphore posted by stale syscall responses */
	// if (_mb_restarted)
	sem_init(&syscall_wakeup, 0, 0);

	((void(*)(struct runtime_api*))app_main)(api);
}

static void context_switch() __attribute__((noinline));
static void context_switch()
{
	int Status;
	if (need_to_store_context) {
		store_context(NULL);
	}
	
	while(1) sleep(1);
}

static void context_switch_begin() __attribute__((noinline));
static void context_switch_begin()
{
	context_switch();
}

static void handle_fixed_timer_interrupts(void* ignored)
{
	int 		bytes_read;

	if (runtime_terminated) {
		runtime_terminated = FALSE;
		runtime_inited = FALSE;
		/* r14: address to return from interrupt */
		__asm__ __volatile__ ("or r14,r0,%0\n" :: "d" (&context_switch_begin));
		return;
	}

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
		_SEC_HW_DEBUG("RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG");
		write_syscall_response(buf);
		sem_post(&syscall_wakeup);
	} else if (buf[0] == RUNTIME_QUEUE_EXEC_APP_TAG) {
		_SEC_HW_DEBUG("RUNTIME_QUEUE_EXEC_APP_TAG");
		memcpy(load_buf, &buf[1], MAILBOX_QUEUE_MSG_SIZE - 1);
		sem_post(&load_app_sem);
	} else if (buf[0] == RUNTIME_QUEUE_CONTEXT_SWITCH_TAG) {
		_SEC_HW_DEBUG("RUNTIME_QUEUE_CONTEXT_SWITCH_TAG");
		need_to_store_context = TRUE;
		close_runtime();
	} else {
		_SEC_HW_ERROR("received invalid message (%d)", buf[0]);
	}
	free(buf);
}

static void handle_octopos_mailbox_interrupts(void* callback_ref)
{
	uint8_t queue_id = (int) callback_ref;
	octopos_mailbox_clear_interrupt(Mbox_ctrl_regs[queue_id]);
	_SEC_HW_DEBUG("change interrupt from %d", queue_id);
	if (queue_id == change_queue) {
		sem_post(&interrupt_change);
	}

	mailbox_change_queue_access_bottom_half(queue_id);
}

static void handle_mailbox_interrupts(void* callback_ref)
{
	u32			mask = 0;
	u8			queue_id = (int) callback_ref;

	if (Mbox_ctrl_regs[queue_id] && Xil_In32(Mbox_ctrl_regs[queue_id]) == 0xdeadbeef)
		/* Runtime may have lost access to the OctopOS mailbox */
		return;
	mask = OCTOPOS_XMbox_GetInterruptStatus(Mbox_regs[queue_id]);
	OCTOPOS_XMbox_ClearInterrupt(Mbox_regs[queue_id], mask);

	/* the hardware mailbox will not deliver an interrupt unless the queue
	 * is free of stale messages. Therefore, we sem_init the count to default
	 * when receive an interrupt.
	 */
	if (mask & OCTOPOS_XMB_IX_STA) {
		if (queue_id == Q_SERIAL_OUT) {
			/* Serial Out */
			if (MBOX_PENDING_STA[Q_SERIAL_OUT]) {
				/* ignore extra interrupt generated by hardware */
				sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE - 1);
				sem_post(&interrupts[Q_SERIAL_OUT]);
				MBOX_PENDING_STA[Q_SERIAL_OUT] = FALSE;
			}
		} else if (queue_id == q_os) {
			/* Syscall request */
			if (MBOX_PENDING_STA[q_os]) {
				sem_init(&interrupts[q_os], 0, MAILBOX_QUEUE_SIZE - 1);
				sem_post(&interrupts[q_os]);
				MBOX_PENDING_STA[q_os] = FALSE;
			}
		} else if (queue_id == Q_STORAGE_DATA_IN) {
			/* storage data in queue */
			sem_post(&interrupts[Q_STORAGE_DATA_IN]);
		} else if (queue_id == Q_STORAGE_CMD_IN) {
			/* storage cmd in queue */
			sem_post(&interrupts[Q_STORAGE_CMD_IN]);
		} else if (queue_id != q_runtime) {
			/* IPC to other runtime */
			if (queue_id == Q_RUNTIME1) {
				if (MBOX_PENDING_STA[Q_RUNTIME1]) {
					sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE - 1);
					sem_post(&interrupts[Q_RUNTIME1]);
					MBOX_PENDING_STA[Q_RUNTIME1] = FALSE;
				}
			} else if (queue_id == Q_RUNTIME2) {
				if (MBOX_PENDING_STA[Q_RUNTIME2]) {
					sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE - 1);
					sem_post(&interrupts[Q_RUNTIME2]);
					MBOX_PENDING_STA[Q_RUNTIME2] = FALSE;
				}
			} else {
				_SEC_HW_ERROR("Error: invalid interrupt from %d", queue_id);
			}
		} else {
			_SEC_HW_ERROR("Error: invalid interrupt from %d", queue_id);
		}
	} else if (mask & OCTOPOS_XMB_IX_RTA) {
		if (queue_id == Q_KEYBOARD) {
			/* Keyboard */
			sem_init(&interrupts[Q_KEYBOARD], 0, 0);
			sem_post(&interrupts[Q_KEYBOARD]);
		} else if (queue_id == q_runtime) {
			/* Runtime queue */
			if (!secure_ipc_mode) {
				sem_init(&runtime_wakeup, 0, 0);
				sem_post(&runtime_wakeup);
			} else {
				sem_init(&secure_ipc_receive_sem, 0, 0);
				sem_post(&secure_ipc_receive_sem);
			}
		} else if (queue_id == Q_STORAGE_DATA_OUT) {
			/* storage data out queue */
			sem_post(&interrupts[Q_STORAGE_DATA_OUT]);
		} else if (queue_id == Q_STORAGE_CMD_OUT) {
			/* storage cmd out queue */
			sem_post(&interrupts[Q_STORAGE_CMD_OUT]);
		} else {
			_SEC_HW_ERROR("Error: invalid interrupt from %d", queue_id);
		}
	} else if (mask & OCTOPOS_XMB_IX_ERR) {
		_SEC_HW_ERROR("interrupt type: OCTOPOS_XMB_IX_ERR, from %d", queue_id);
		_SEC_HW_DEBUG("status register: %ld", OCTOPOS_XMbox_GetStatus(Mbox_regs[queue_id]));
	} else {
		_SEC_HW_ERROR("interrupt type unknown, mask %ld, from %d", mask, queue_id);
	}
}

void *run_app(void *load_buf);

void runtime_core()
{
	run_app(load_buf);
}

/* Initializes the runtime and its mailbox */
int init_runtime(int runtime_id)
{
	int				Status;
	OCTOPOS_XMbox_Config	*ConfigPtr_out,
					*ConfigPtr_keyboard,
					*ConfigPtr_Runtime1,
					*ConfigPtr_Runtime2,
					*ConfigPtr_sys, 
					*Config_storage_cmd_in,
					*Config_storage_cmd_out,
					*Config_storage_data_in, 
					*Config_storage_data_out;

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

	ConfigPtr_sys = OCTOPOS_XMbox_LookupConfig(XPAR_RUNTIME_OS_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_sys, ConfigPtr_sys, ConfigPtr_sys->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	ConfigPtr_keyboard = OCTOPOS_XMbox_LookupConfig(XPAR_RUNTIME_KEYBOARD_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_keyboard, ConfigPtr_keyboard, ConfigPtr_keyboard->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}
	ConfigPtr_out = OCTOPOS_XMbox_LookupConfig(XPAR_RUNTIME_SERIAL_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_out, ConfigPtr_out, ConfigPtr_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}
	ConfigPtr_Runtime1 = OCTOPOS_XMbox_LookupConfig(XPAR_RUNTIME_RUNTIME1_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_Runtime1, ConfigPtr_Runtime1, ConfigPtr_Runtime1->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}
	ConfigPtr_Runtime2 = OCTOPOS_XMbox_LookupConfig(XPAR_RUNTIME_RUNTIME2_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_Runtime2, ConfigPtr_Runtime2, ConfigPtr_Runtime2->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Config_storage_data_in = OCTOPOS_XMbox_LookupConfig(XPAR_RUNTIME_STORAGE_DATA_IN_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_data_in, Config_storage_data_in, Config_storage_data_in->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Config_storage_data_out = OCTOPOS_XMbox_LookupConfig(XPAR_RUNTIME_STORAGE_DATA_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_data_out, Config_storage_data_out, Config_storage_data_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Config_storage_cmd_in = OCTOPOS_XMbox_LookupConfig(XPAR_RUNTIME_STORAGE_CMD_IN_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_cmd_in, Config_storage_cmd_in, Config_storage_cmd_in->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Config_storage_cmd_out = OCTOPOS_XMbox_LookupConfig(XPAR_RUNTIME_STORAGE_CMD_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_cmd_out, Config_storage_cmd_out, Config_storage_cmd_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Mbox_regs[q_os] = &Mbox_sys;
	Mbox_regs[Q_RUNTIME1] = &Mbox_Runtime1;
	Mbox_regs[Q_RUNTIME2] = &Mbox_Runtime2;
	Mbox_regs[Q_KEYBOARD] = &Mbox_keyboard;
	Mbox_regs[Q_SERIAL_OUT] = &Mbox_out;
	Mbox_regs[Q_STORAGE_DATA_IN] = &Mbox_storage_data_in;
	Mbox_regs[Q_STORAGE_DATA_OUT] = &Mbox_storage_data_out;
	Mbox_regs[Q_STORAGE_CMD_IN] = &Mbox_storage_cmd_in;
	Mbox_regs[Q_STORAGE_CMD_OUT] = &Mbox_storage_cmd_out;

	Mbox_ctrl_regs[Q_KEYBOARD] = OCTOPOS_ENCLAVE_MAILBOX_1WRI_0_BASEADDR;
	Mbox_ctrl_regs[Q_SERIAL_OUT] = OCTOPOS_ENCLAVE_MAILBOX_3WRI_0_BASEADDR;
	Mbox_ctrl_regs[Q_RUNTIME1] = OCTOPOS_ENCLAVE_MAILBOX_3WRI_2_BASEADDR;
	Mbox_ctrl_regs[Q_RUNTIME2] = OCTOPOS_ENCLAVE_MAILBOX_3WRI_1_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_DATA_IN] = OCTOPOS_ENCLAVE_Q_STORAGE_DATA_IN_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_DATA_OUT] = OCTOPOS_ENCLAVE_Q_STORAGE_DATA_OUT_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_CMD_IN] = OCTOPOS_ENCLAVE_Q_STORAGE_IN_2_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_CMD_OUT] = OCTOPOS_ENCLAVE_Q_STORAGE_OUT_2_BASEADDR;

	/* OctopOS mailbox maps must be initialized before setting up interrupts. */
	OMboxIds_init();

	OCTOPOS_XMbox_SetReceiveThreshold(Mbox_regs[q_runtime], MAILBOX_MAX_COMMAND_SIZE);
	OCTOPOS_XMbox_SetInterruptEnable(Mbox_regs[q_runtime], OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_sys, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_sys, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

#ifndef ARCH_SEC_HW_BOOT

	Xil_ExceptionInit();
	Xil_ExceptionEnable();

	Status = XIntc_Initialize(&intc, XPAR_INTC_SINGLE_DEVICE_ID);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		XPAR_COMMON_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*) Q_KEYBOARD);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		XPAR_COMMON_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*) Q_SERIAL_OUT);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		XPAR_COMMON_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*) Q_RUNTIME1);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		XPAR_COMMON_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*) Q_RUNTIME2);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		XPAR_COMMON_AXI_INTC_ENCLAVE_MAILBOX_INTERRUPT_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*) q_os);
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

	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[p_runtime][Q_SERIAL_OUT],
		(XInterruptHandler)handle_octopos_mailbox_interrupts,
		(void*) Q_SERIAL_OUT);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[p_runtime][Q_KEYBOARD],
		(XInterruptHandler)handle_octopos_mailbox_interrupts,
		(void*) Q_KEYBOARD);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		XPAR_COMMON_AXI_INTC_Q_STORAGE_DATA_OUT_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*) Q_STORAGE_DATA_OUT);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		XPAR_COMMON_AXI_INTC_Q_STORAGE_DATA_IN_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*) Q_STORAGE_DATA_IN);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		XPAR_COMMON_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*) Q_STORAGE_CMD_OUT);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		XPAR_COMMON_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*) Q_STORAGE_CMD_IN);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[p_runtime][Q_STORAGE_DATA_OUT],
		(XInterruptHandler)handle_octopos_mailbox_interrupts,
		(void*) Q_STORAGE_DATA_OUT);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}


	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[p_runtime][Q_STORAGE_DATA_IN],
		(XInterruptHandler)handle_octopos_mailbox_interrupts,
		(void*) Q_STORAGE_DATA_IN);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}


	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[p_runtime][Q_STORAGE_CMD_IN],
		(XInterruptHandler)handle_octopos_mailbox_interrupts,
		(void*) Q_STORAGE_CMD_IN);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}


	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[p_runtime][Q_STORAGE_CMD_OUT],
		(XInterruptHandler)handle_octopos_mailbox_interrupts,
		(void*) Q_STORAGE_CMD_OUT);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_MAILBOX_0_INTERRUPT_0_INTR);
	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_MAILBOX_1_INTERRUPT_0_INTR);
	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_MAILBOX_2_INTERRUPT_0_INTR);
	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_MAILBOX_3_INTERRUPT_0_INTR);
	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_ENCLAVE_MAILBOX_INTERRUPT_INTR);
	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_FIT_TIMER_INTERRUPT_INTR);
	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_Q_STORAGE_DATA_OUT_INTERRUPT_0_INTR);
	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_Q_STORAGE_DATA_IN_INTERRUPT_0_INTR);
	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_Q_STORAGE_OUT_2_INTERRUPT_0_INTR);
	XIntc_Enable(&intc, XPAR_COMMON_AXI_INTC_Q_STORAGE_IN_2_INTERRUPT_0_INTR);
	XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_RUNTIME1]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_RUNTIME2]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_SERIAL_OUT]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_KEYBOARD]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_STORAGE_DATA_OUT]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_STORAGE_DATA_IN]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_STORAGE_CMD_OUT]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[p_runtime][Q_STORAGE_CMD_IN]);

	Status = XIntc_Start(&intc, XIN_REAL_MODE);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}
#endif

	sem_init(&interrupts[q_os], 0, MAILBOX_QUEUE_SIZE);
	/* Q_RUNTIME semaphores are not used directly because there is
	 * an indirection layer on top of it.
	 *
	 * Below is a list of event semaphores:
	 * 
	 * runtime_wakeup: runtime queue (non secure ipc mode) receives 
	 *                 a message from OS, awaiting the fixed timer
	 *                 to decode.
	 * secure_ipc_receive_sem: keep track of the secure ipc receives
	 * syscall_wakeup: runtime queue (non secure ipc mode) receives 
	 *                 a syscall response.
	 * Q_RUNTIME (target): keep track of the secure ipc sends
	 */
	sem_init(&interrupts[q_runtime], 0, 0);
	sem_init(&interrupts[Q_KEYBOARD], 0, 0);
	sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
	sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, MAILBOX_QUEUE_MSG_SIZE_LARGE);
	sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, 0);
	sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, MAILBOX_QUEUE_SIZE);

	sem_init(&secure_ipc_receive_sem, 0, 0);
	sem_init(&load_app_sem, 0, 0);
	sem_init(&syscall_wakeup, 0, 0);

#ifndef ARCH_SEC_HW_BOOT
	preloaded_app_init();
#endif

	runtime_inited = TRUE;

	return XST_SUCCESS;
}

void close_runtime(void)
{
	preloaded_app_destroy();
	runtime_terminated = TRUE;
}

#endif
