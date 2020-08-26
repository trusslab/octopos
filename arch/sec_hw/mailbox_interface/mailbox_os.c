/*
 * Based on https://xilinx-wiki.atlassian.net/wiki/spaces/A/pages/18841941/Zynq+UltraScale+MPSoC+-+IPI+Messaging+Example
 */

/* OctopOS OS mailbox interface */
#ifdef ARCH_SEC_HW_OS
#include <stdio.h>
#include <stdlib.h>
#include "xil_printf.h"
#include "xstatus.h"
#include "xmbox.h"
#include "xparameters.h"
#include "xil_exception.h"
#include "xscugic.h"
#include "xttcps.h"
#include "xipipsu.h"
#include "xintc.h"

#include "arch/sec_hw.h"
#include "arch/semaphore.h"
#include "arch/ring_buffer.h"
#include "arch/octopos_mbox.h"
#include "arch/octopos_mbox_owner_map.h"

#include "octopos/error.h"
#include "octopos/mailbox.h"
#include "os/scheduler.h"

#define RESP_AND_MSG_NUM_OFFSET		0x1U
#define IPI_HEADER_OFFSET			0x0U
#define IPI_HEADER					0x1E0000 /* 1E - Target Module ID */

XScuGic			irq_controller;
//XScuGic 		gic_controller;
XIpiPsu 		ipi_pmu_inst;
XIntc			intc;

XMbox			Mbox_output, 
				Mbox_keyboard, 
				Mbox_OS1, 
				Mbox_OS2, 
				Mbox_runtime1, 
				Mbox_runtime2,
				Mbox_storage_cmd_in,
				Mbox_storage_cmd_out,
				Mbox_storage_data_in,
				Mbox_storage_data_out;

sem_t			interrupts[NUM_QUEUES + 1];
sem_t			interrupt_input;
sem_t			availables[NUM_QUEUES + 1];

cbuf_handle_t	cbuf_keyboard;

XMbox*			Mbox_regs[NUM_QUEUES + 1];
UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1];

int is_queue_available(uint8_t queue_id)
{
	int available;

	sem_getvalue(&availables[queue_id], &available);
	return available;
}

void wait_for_queue_availability(uint8_t queue_id)
{
	sem_wait(&availables[queue_id]);
}

void mark_queue_unavailable(uint8_t queue_id)
{
	sem_init(&availables[queue_id], 0, 0);
}

int send_output(uint8_t *buf)
{
	int ret = is_queue_available(Q_SERIAL_OUT);

	if (!ret)
		sem_wait(&availables[Q_SERIAL_OUT]);

	sem_wait_impatient_send(&interrupts[Q_SERIAL_OUT], &Mbox_output, (u32*) buf);

	_SEC_HW_DEBUG("Q_SERIAL_OUT = %d", interrupts[Q_SERIAL_OUT].count);
	return 0;
}

static uint8_t *sketch_buffer[NUM_QUEUES + 1];
static u32 sketch_buffer_offset[NUM_QUEUES + 1];

_Bool handle_partial_message(uint8_t *message_buffer, uint8_t *queue_id, u32 bytes_read) 
{
	/* Same handling logic as in semaphore.c
	 * If the message is incomplete due to sync issues, try to collect
	 * the rest of the message in the next read.
	 */
	_SEC_HW_DEBUG1("queue %d read only %d bytes, should be %d bytes",
		*queue_id, bytes_read, MAILBOX_QUEUE_MSG_SIZE);
	if (!sketch_buffer[*queue_id]) {
		_SEC_HW_DEBUG1("new sktech_buffer", *queue_id);
		sketch_buffer_offset[*queue_id] = bytes_read;
		sketch_buffer[*queue_id] = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
		memcpy(sketch_buffer[*queue_id], message_buffer, bytes_read);
		*queue_id = 0;
		return FALSE;
	} else {
		/* There is already a incomplete message on the sketch_buffer */
		if (bytes_read + sketch_buffer_offset[*queue_id] > MAILBOX_QUEUE_MSG_SIZE) {
			_SEC_HW_ERROR("mailbox corrupted: buffer overflow");
			_SEC_HW_ASSERT_NON_VOID(FALSE)
		}

		memcpy(sketch_buffer[*queue_id] + sketch_buffer_offset[*queue_id],
				message_buffer, bytes_read);
		if (bytes_read + sketch_buffer_offset[*queue_id] == MAILBOX_QUEUE_MSG_SIZE) {
			/* This read completes the message */
			_SEC_HW_DEBUG1("complete sketch_buffer");
			memcpy(message_buffer, sketch_buffer[*queue_id], MAILBOX_QUEUE_MSG_SIZE);
			free(sketch_buffer[*queue_id]);
			sketch_buffer[*queue_id] = NULL;
			return TRUE;
		} else {
			/* The message is still incomplete after this read */
			_SEC_HW_DEBUG1("partially full sketch_buffer");
			*queue_id = 0;
			return FALSE;
		}

	}
}

/* reads from Q_OS's and Q_KEYBOARD */
int recv_input(uint8_t *buf, uint8_t *queue_id)
{
	int             is_keyboard = 0, is_os1 = 0, is_os2 = 0;
	static uint8_t  turn = Q_OS1;
	uint8_t          *message_buffer;
	u32		        bytes_read;

	XMbox*          InstancePtr = NULL;

	InstancePtr = sem_wait_impatient_receive_multiple(&interrupt_input, 3, &Mbox_keyboard, &Mbox_OS1, &Mbox_OS2);

	_SEC_HW_ASSERT_NON_VOID(InstancePtr);

		if (InstancePtr == &Mbox_keyboard) {
			sem_post(&interrupts[Q_KEYBOARD]);
			is_keyboard = 1;
		} else if (InstancePtr == &Mbox_OS1) {
			sem_post(&interrupts[Q_OS1]);
			is_os1 = 1;
		} else if (InstancePtr == &Mbox_OS2) {
			sem_post(&interrupts[Q_OS2]);
			is_os2 = 1;
		}

	if (is_keyboard) {
		sem_wait(&interrupts[Q_KEYBOARD]);
		*queue_id = Q_KEYBOARD;
	} else {
		if (is_os1 && !is_os2) {
			sem_wait(&interrupts[Q_OS1]);
			*queue_id = Q_OS1;
			turn = Q_OS2;
		} else if (is_os2 && !is_os1) {
			sem_wait(&interrupts[Q_OS2]);
			*queue_id = Q_OS2;
			turn = Q_OS1;
		} else { /* is_os1 && is_os2 */
			sem_wait(&interrupts[turn]);
			*queue_id = turn;
			if (turn == Q_OS1)
				turn = Q_OS2;
			else
				turn = Q_OS1;
		}
	}

	switch (*queue_id) {
	case Q_KEYBOARD:
		message_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));

#ifdef HW_MAILBOX_BLOCKING
		XMbox_ReadBlocking(&Mbox_keyboard, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE);
#else
		if (sketch_buffer[*queue_id])
			XMbox_Read(&Mbox_keyboard,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE - sketch_buffer_offset[*queue_id],
					&bytes_read);
		else
			XMbox_Read(&Mbox_keyboard,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE,
					&bytes_read);

		if (bytes_read != MAILBOX_QUEUE_MSG_SIZE && 
			!handle_partial_message(message_buffer, queue_id, bytes_read))
				return 0;
#endif

		memcpy(buf ,message_buffer, MAILBOX_QUEUE_MSG_SIZE);
		free((void*) message_buffer);
		break;

	case Q_OS1:
		message_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));

#ifdef HW_MAILBOX_BLOCKING
		XMbox_ReadBlocking(&Mbox_OS1, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE);
#else
		if (sketch_buffer[*queue_id])
			XMbox_Read(&Mbox_OS1,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE - sketch_buffer_offset[*queue_id],
					&bytes_read);
		else
			XMbox_Read(&Mbox_OS1,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE,
					&bytes_read);

		if (bytes_read != MAILBOX_QUEUE_MSG_SIZE && 
			!handle_partial_message(message_buffer, queue_id, bytes_read))
				return 0;
#endif

		memcpy(buf ,message_buffer, MAILBOX_QUEUE_MSG_SIZE);

		free((void*) message_buffer);
		break;
	case Q_OS2:
		message_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
		
#ifdef HW_MAILBOX_BLOCKING
		XMbox_ReadBlocking(&Mbox_OS2, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE);
#else
		if (sketch_buffer[*queue_id])
			XMbox_Read(&Mbox_OS2,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE - sketch_buffer_offset[*queue_id],
					&bytes_read);
		else
			XMbox_Read(&Mbox_OS2,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE,
					&bytes_read);

		if (bytes_read != MAILBOX_QUEUE_MSG_SIZE && 
			!handle_partial_message(message_buffer, queue_id, bytes_read))
				return 0;
#endif

		memcpy(buf ,message_buffer, MAILBOX_QUEUE_MSG_SIZE);

		free((void*) message_buffer);
		break;
	default:
		break;
	}

	return 0;
}

static int send_msg_to_runtime_queue(uint8_t runtime_queue_id, uint8_t *buf)
{
	sem_wait_impatient_send(&interrupts[runtime_queue_id], Mbox_regs[runtime_queue_id], (u32*) buf);
	return 0;
}

int check_avail_and_send_msg_to_runtime(uint8_t runtime_proc_id, uint8_t *buf)
{
	uint8_t runtime_queue_id = get_runtime_queue_id(runtime_proc_id);
	if (!runtime_queue_id) {
		return ERR_INVALID;
	}

	int ret = is_queue_available(runtime_queue_id);
	if (!ret) {
		return ERR_AVAILABLE;
	}

	send_msg_to_runtime_queue(runtime_queue_id, buf);

	return 0;
}

/* Only to be used for queues that OS writes to */
/* FIXME: busy-waiting */
void wait_until_empty(uint8_t queue_id, int queue_size)
{
	int left;

	while (1) {
		sem_getvalue(&interrupts[queue_id], &left);
		if (left == queue_size)
			break;
	}
}

void _mailbox_print_queue_status(uint8_t runtime_proc_id)
{
	uint8_t queue_id = get_runtime_queue_id(runtime_proc_id);
	if (!queue_id) {
		return;
	}   

	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];
	_SEC_HW_ERROR("queue %d: ctrl reg %p", queue_id, queue_ptr);
	_SEC_HW_ERROR("queue %d: ctrl reg content %08x", queue_id, octopos_mailbox_get_status_reg(queue_ptr));
}

void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint16_t count)
{
	_SEC_HW_ASSERT_VOID(queue_id <= NUM_QUEUES + 1)

	u8 factor = MAILBOX_QUEUE_MSG_SIZE / 4;
	u32 reg = 0;
	
	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];
	_SEC_HW_DEBUG("queue %d: ctrl reg %p", queue_id, queue_ptr);

	reg = octopos_mailbox_calc_owner(reg, OMboxIds[queue_id][proc_id]);
	reg = octopos_mailbox_calc_quota_limit(reg, count * factor);
	reg = octopos_mailbox_calc_time_limit(reg, MAX_OCTOPOS_MAILBOX_QUOTE);

	_SEC_HW_DEBUG("Before yielding: %08x", octopos_mailbox_get_status_reg(queue_ptr));

	octopos_mailbox_set_status_reg(queue_ptr, reg);

	_SEC_HW_DEBUG("After yielding: %08x", octopos_mailbox_get_status_reg(queue_ptr));
}


int send_msg_to_storage_no_response(uint8_t *buf)
{
	sem_wait_impatient_send(
		&interrupts[Q_STORAGE_CMD_IN], 
		Mbox_regs[Q_STORAGE_CMD_IN], 
		(u32*) buf);
	return 0;
}

int get_response_from_storage(uint8_t *buf)
{
	sem_wait_impatient_receive_buf(
		&interrupts[Q_STORAGE_CMD_OUT], 
		Mbox_regs[Q_STORAGE_CMD_OUT],
		(uint8_t*) buf);
	return 0;
}

void read_from_storage_data_queue(uint8_t *buf)
{
	sem_wait_impatient_receive_buf_large(
		&interrupts[Q_STORAGE_DATA_OUT], 
		Mbox_regs[Q_STORAGE_DATA_OUT],
		(uint8_t*) buf);
}

void write_to_storage_data_queue(uint8_t *buf)
{
	sem_wait_impatient_send_large(
			&interrupts[Q_STORAGE_DATA_IN],
		Mbox_regs[Q_STORAGE_DATA_IN],
		(u32*) buf);
}

int send_cmd_to_untrusted(uint8_t *buf)
{
	//TODO: Implement
	return 0;
}

void mailbox_change_queue_access_bottom_half(uint8_t queue_id)
{
	/* Threshold registers will need to be reinitialized
	 * every time it switches ownership
	 */
	switch (queue_id) {
		case Q_KEYBOARD:
		case Q_STORAGE_CMD_OUT:
			XMbox_SetReceiveThreshold(Mbox_regs[queue_id], MAILBOX_DEFAULT_RX_THRESHOLD);
			XMbox_SetInterruptEnable(Mbox_regs[queue_id], XMB_IX_RTA | XMB_IX_ERR);
			break;
		case Q_STORAGE_DATA_OUT:
			XMbox_SetReceiveThreshold(Mbox_regs[queue_id], MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
			XMbox_SetInterruptEnable(Mbox_regs[queue_id], XMB_IX_RTA | XMB_IX_ERR);
			break;

		case Q_SERIAL_OUT:
		case Q_RUNTIME1:
		case Q_RUNTIME2:
		case Q_STORAGE_CMD_IN:
		case Q_STORAGE_DATA_IN:
			XMbox_SetSendThreshold(Mbox_regs[queue_id], 0);
			XMbox_SetInterruptEnable(Mbox_regs[queue_id], XMB_IX_STA | XMB_IX_ERR);
			break;

		default:
			_SEC_HW_ERROR("unknown/unsupported queue %d", queue_id);
	}
}

/* When the queue ownerships are switched back to the OS, we
 * need to initialize the interrupts.
 */
static void handle_change_queue_interrupts(void* callback_ref)
{
	uint8_t queue_id = (int) callback_ref;
	_SEC_HW_DEBUG("from %d", queue_id);

	sem_post(&availables[queue_id]);

	mailbox_change_queue_access_bottom_half(queue_id);
	octopos_mailbox_clear_interrupt(Mbox_ctrl_regs[queue_id]);
}

void Rpu_IpiHandler(XIpiPsu *IpiInstPtr)
{
	u32 RegVal;

	/* Check if the IPI is from the expected source i.e., PMU channel-1 */
	RegVal = Xil_In32(0xFF310010U);
	if((RegVal & (u32)XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK) == 0U) {
		xil_printf("RPU: Received IPI from invalid source, ISR:%x\r\n", RegVal);
		return;
	} else {
		/* Valid IPI. Clear the appropriate bit in the respective ISR */
		Xil_Out32(0xFF310010U, (RegVal & (u32)XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK));

	}
}

static void handle_mailbox_interrupts(void* callback_ref) 
{
	u32         mask;
	XMbox       *mbox_inst = (XMbox *)callback_ref;

	_SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
	mask = XMbox_GetInterruptStatus(mbox_inst);

	if (mask & XMB_IX_STA) {
		_SEC_HW_DEBUG("interrupt type: XMB_IX_STA");
		if (callback_ref == &Mbox_output) {
			/* Serial Out */
			_SEC_HW_DEBUG("from Mbox_output");

			sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
			sem_post(&availables[Q_SERIAL_OUT]);
			sem_post(&interrupts[Q_SERIAL_OUT]);
			_SEC_HW_DEBUG("Q_SERIAL_OUT = %d", interrupts[Q_SERIAL_OUT].count);
		} else if (callback_ref == &Mbox_runtime1) {
			/* Runtime 1 */
			_SEC_HW_DEBUG("from Runtime1");

			sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE);
			sem_post(&availables[Q_RUNTIME1]);
			sem_post(&interrupts[Q_RUNTIME1]);
			_SEC_HW_DEBUG("Q_RUNTIME1 = %d", interrupts[Q_RUNTIME1].count);
		} else if (callback_ref == &Mbox_runtime2) {
			/* Runtime 2 */
			_SEC_HW_DEBUG("from Runtime2");

			sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE);
			sem_post(&availables[Q_RUNTIME2]);
			sem_post(&interrupts[Q_RUNTIME2]);
			_SEC_HW_DEBUG("Q_RUNTIME2 = %d", interrupts[Q_RUNTIME2].count);
		} else if (callback_ref == &Mbox_storage_data_in) {
			/* Storage data in */
			_SEC_HW_DEBUG("from Mbox_storage_data_in");

			sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
			sem_post(&availables[Q_STORAGE_DATA_IN]);
			sem_post(&interrupts[Q_STORAGE_DATA_IN]);
		} else if (callback_ref == &Mbox_storage_cmd_in) {
			_SEC_HW_DEBUG("from Mbox_storage_cmd_in");
			
			sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, MAILBOX_QUEUE_SIZE);
			sem_post(&availables[Q_STORAGE_CMD_IN]);
			sem_post(&interrupts[Q_STORAGE_CMD_IN]);
		}
		
	} else if (mask & XMB_IX_RTA) {
		_SEC_HW_DEBUG("interrupt type: XMB_IX_RTA");
		if (callback_ref == &Mbox_keyboard) {
			/* Keyboard */
			_SEC_HW_DEBUG("from Mbox_keyboard");

			sem_init(&interrupts[Q_KEYBOARD], 0, 0);
			sem_post(&availables[Q_KEYBOARD]);
			sem_post(&interrupts[Q_KEYBOARD]);
			sem_post(&interrupt_input);
		} else if (callback_ref == &Mbox_OS1) {
			/* OS1 */
			_SEC_HW_DEBUG("from Mbox_OS1");

			sem_post(&availables[Q_OS1]);
			sem_post(&interrupts[Q_OS1]);
			sem_post(&interrupt_input);
		} else if (callback_ref == &Mbox_OS2) {
			/* OS2 */
			_SEC_HW_DEBUG("from Mbox_OS2");

			sem_post(&availables[Q_OS2]);
			sem_post(&interrupts[Q_OS2]);
			sem_post(&interrupt_input);
		} else if (callback_ref == &Mbox_storage_data_out) {
			/* Storage data out */
			_SEC_HW_DEBUG("from Mbox_storage_data_out");

			sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
			sem_post(&availables[Q_STORAGE_DATA_OUT]);
			sem_post(&interrupts[Q_STORAGE_DATA_OUT]);
		} else if (callback_ref == &Mbox_storage_cmd_out) {
			/* Storage cmd out */
			_SEC_HW_DEBUG("from Mbox_storage_cmd_out");

			sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, 0);
			sem_post(&availables[Q_STORAGE_CMD_OUT]);
			sem_post(&interrupts[Q_STORAGE_CMD_OUT]);
		}
	} else if (mask & XMB_IX_ERR) {
		_SEC_HW_ERROR("interrupt type: XMB_IX_ERR, from %p", callback_ref);
	} else {
		_SEC_HW_ERROR("interrupt type unknown, mask %d, from %p", mask, callback_ref);
	}

	XMbox_ClearInterrupt(mbox_inst, mask);

	_SEC_HW_DEBUG("interrupt cleared");
//  _SEC_HW_DEBUG("STATE register: (in decimal) %d",
//          Xil_In32((mbox_inst->Config.BaseAddress) + (0x10)));
//  _SEC_HW_DEBUG("IS register: (in decimal) %d",
//          Xil_In32((mbox_inst->Config.BaseAddress) + (0x20)));
//  _SEC_HW_DEBUG("IE register: (in decimal) %d",
//          Xil_In32((mbox_inst->Config.BaseAddress) + (0x24)));
//  _SEC_HW_DEBUG("IP register: (in decimal) %d",
//          Xil_In32((mbox_inst->Config.BaseAddress) + (0x28)));
}

static void handle_fixed_timer_interrupts(void* ignored)
{
	update_timer_ticks();
	sched_next_app();
}

int init_os_mailbox(void) 
{
	int				Status;
	uint32_t		irqNo;

	XMbox_Config	*ConfigPtr, *ConfigPtr2, *ConfigPtr3, *ConfigPtr4,
					*ConfigPtr_runtime1, *ConfigPtr_runtime2, *Config_storage_cmd_in,
					*Config_storage_cmd_out, *Config_storage_data_in, *Config_storage_data_out;
	XIpiPsu_Config	*ipi_psu_config;

	init_platform();

	ConfigPtr = XMbox_LookupConfig(XPAR_MBOX_0_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_output, ConfigPtr, ConfigPtr->BaseAddress);
	if (Status != XST_SUCCESS) 
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MBOX_0_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr2 = XMbox_LookupConfig(XPAR_MBOX_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_keyboard, ConfigPtr2, ConfigPtr2->BaseAddress);
	if (Status != XST_SUCCESS) 
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MBOX_1_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr3 = XMbox_LookupConfig(XPAR_ENCLAVE0_PS_MAILBOX_IF_0_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_OS1, ConfigPtr3, ConfigPtr3->BaseAddress);
	if (Status != XST_SUCCESS) 
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_ENCLAVE0_PS_MAILBOX_IF_0_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr4 = XMbox_LookupConfig(XPAR_ENCLAVE1_PS_MAILBOX_IF_0_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_OS2, ConfigPtr4, ConfigPtr4->BaseAddress);
	if (Status != XST_SUCCESS) 
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_ENCLAVE1_PS_MAILBOX_IF_0_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr_runtime1 = XMbox_LookupConfig(XPAR_MBOX_2_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_runtime1, ConfigPtr_runtime1, ConfigPtr_runtime1->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MBOX_2_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr_runtime2 = XMbox_LookupConfig(XPAR_MBOX_3_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_runtime2, ConfigPtr_runtime2, ConfigPtr_runtime2->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MBOX_3_DEVICE_ID);
		return -XST_FAILURE;
	}

	Config_storage_data_in = XMbox_LookupConfig(XPAR_MBOX_4_DEVICE_ID);
	Status = XMbox_CfgInitialize(
		&Mbox_storage_data_in, 
		Config_storage_data_in,
		Config_storage_data_in->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MBOX_4_DEVICE_ID);
		return -XST_FAILURE;
	}

	Config_storage_data_out = XMbox_LookupConfig(XPAR_MBOX_5_DEVICE_ID);
	Status = XMbox_CfgInitialize(
		&Mbox_storage_data_out, 
		Config_storage_data_out,
		Config_storage_data_out->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MBOX_5_DEVICE_ID);
		return -XST_FAILURE;
	}

	Config_storage_cmd_in = XMbox_LookupConfig(XPAR_MBOX_6_DEVICE_ID);
	Status = XMbox_CfgInitialize(
		&Mbox_storage_cmd_in, 
		Config_storage_cmd_in,
		Config_storage_cmd_in->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MBOX_6_DEVICE_ID);
		return -XST_FAILURE;
	}

	Config_storage_cmd_out = XMbox_LookupConfig(XPAR_MBOX_7_DEVICE_ID);
	Status = XMbox_CfgInitialize(
		&Mbox_storage_cmd_out, 
		Config_storage_cmd_out,
		Config_storage_cmd_out->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("XMbox_CfgInitialize %d failed", XPAR_MBOX_7_DEVICE_ID);
		return -XST_FAILURE;
	}

	/* OctopOS mailbox maps must be initialized before setting up interrupts. */
	OMboxIds_init();

	XMbox_SetSendThreshold(&Mbox_output, 0);
	XMbox_SetInterruptEnable(&Mbox_output, XMB_IX_STA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_keyboard, MAILBOX_DEFAULT_RX_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_keyboard, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_OS1, MAILBOX_DEFAULT_RX_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_OS1, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_OS2, MAILBOX_DEFAULT_RX_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_OS2, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetSendThreshold(&Mbox_runtime1, 0);
	XMbox_SetInterruptEnable(&Mbox_runtime1, XMB_IX_STA | XMB_IX_ERR);

	XMbox_SetSendThreshold(&Mbox_runtime2, 0);
	XMbox_SetInterruptEnable(&Mbox_runtime2, XMB_IX_STA | XMB_IX_ERR);

	XMbox_SetSendThreshold(&Mbox_storage_cmd_in, 0);
	XMbox_SetInterruptEnable(&Mbox_storage_cmd_in, XMB_IX_STA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_storage_cmd_out, MAILBOX_DEFAULT_RX_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_storage_cmd_out, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_storage_data_out, MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
	XMbox_SetInterruptEnable(&Mbox_storage_data_out, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetSendThreshold(&Mbox_storage_data_in, 0);
	XMbox_SetInterruptEnable(&Mbox_storage_data_in, XMB_IX_STA | XMB_IX_ERR);

	Xil_ExceptionInit();

	XScuGic_Config *IntcConfig;
	IntcConfig = XScuGic_LookupConfig(XPAR_SCUGIC_SINGLE_DEVICE_ID);
	if (IntcConfig == NULL) {
		_SEC_HW_ERROR("XScuGic_LookupConfig failed");
		return -XST_FAILURE;
	}

	Status = XScuGic_CfgInitialize(&irq_controller, IntcConfig, IntcConfig->CpuBaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XScuGic_CfgInitialize failed");
		return -XST_FAILURE;
	}

	Xil_ExceptionRegisterHandler(XIL_EXCEPTION_ID_IRQ_INT,
			(Xil_ExceptionHandler) XScuGic_InterruptHandler,
			&irq_controller);
	Xil_ExceptionEnable();

	irqNo = XPAR_FABRIC_MAILBOX_1_INTERRUPT_1_INTR;
	XScuGic_Connect(&irq_controller, irqNo, handle_mailbox_interrupts, (void *)&Mbox_output);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = XPAR_FABRIC_MAILBOX_0_INTERRUPT_1_INTR;
	XScuGic_Connect(&irq_controller, irqNo, handle_mailbox_interrupts, (void *)&Mbox_keyboard);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = XPAR_FABRIC_ENCLAVE0_PS_MAILBOX_INTERRUPT_0_INTR;
	XScuGic_Connect(&irq_controller, irqNo, handle_mailbox_interrupts, (void *)&Mbox_OS1);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = XPAR_FABRIC_ENCLAVE1_PS_MAILBOX_INTERRUPT_0_INTR;
	XScuGic_Connect(&irq_controller, irqNo, handle_mailbox_interrupts, (void *)&Mbox_OS2);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = XPAR_FABRIC_MAILBOX_2_INTERRUPT_1_INTR;
	XScuGic_Connect(&irq_controller, irqNo, handle_mailbox_interrupts, (void *)&Mbox_runtime1);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = XPAR_FABRIC_MAILBOX_3_INTERRUPT_1_INTR;
	XScuGic_Connect(&irq_controller, irqNo, handle_mailbox_interrupts, (void *)&Mbox_runtime2);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = OMboxCtrlIntrs[P_OS][Q_RUNTIME1];
	XScuGic_Connect(&irq_controller, irqNo, handle_change_queue_interrupts, (void *)Q_RUNTIME1);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = OMboxCtrlIntrs[P_OS][Q_RUNTIME2];
	XScuGic_Connect(&irq_controller, irqNo, handle_change_queue_interrupts, (void *)Q_RUNTIME2);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = OMboxCtrlIntrs[P_OS][Q_SERIAL_OUT];
	XScuGic_Connect(&irq_controller, irqNo, handle_change_queue_interrupts, (void *)Q_SERIAL_OUT);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = OMboxCtrlIntrs[P_OS][Q_KEYBOARD];
	XScuGic_Connect(&irq_controller, irqNo, handle_change_queue_interrupts, (void *)Q_KEYBOARD);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	irqNo = XPAR_FABRIC_FIT_TIMER_2_INTERRUPT_INTR;
	XScuGic_Connect(&irq_controller, irqNo, handle_fixed_timer_interrupts, 0);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x3);

	XScuGic_Connect(&irq_controller,
			XPAR_PSU_IPI_1_INT_ID,
			(Xil_ExceptionHandler)Rpu_IpiHandler,
			&ipi_pmu_inst);
	XScuGic_Enable(&irq_controller, XPAR_PSU_IPI_1_INT_ID);

	/* Enable interrupts in the processor */
	Xil_ExceptionEnableMask(XIL_EXCEPTION_IRQ);

	/* Initialize extra interrupt lines through XIntc */
	Status = XIntc_Initialize(&intc, XPAR_XI_INTC_STORAGE_DEVICE_ID);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Initialize %d failed", XPAR_XI_INTC_STORAGE_DEVICE_ID);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
		XPAR_XI_INTC_STORAGE_Q_STORAGE_IN_2_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_storage_cmd_in);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			XPAR_XI_INTC_STORAGE_Q_STORAGE_IN_2_INTERRUPT_0_INTR);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_XI_INTC_STORAGE_Q_STORAGE_IN_2_INTERRUPT_0_INTR);

	Status = XIntc_Connect(&intc, 
		XPAR_XI_INTC_STORAGE_Q_STORAGE_OUT_2_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_storage_cmd_out);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			XPAR_XI_INTC_STORAGE_Q_STORAGE_OUT_2_INTERRUPT_0_INTR);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_XI_INTC_STORAGE_Q_STORAGE_OUT_2_INTERRUPT_0_INTR);

	Status = XIntc_Connect(&intc, 
		XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_IN_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_storage_data_in);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_IN_INTERRUPT_0_INTR);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_IN_INTERRUPT_0_INTR);

	Status = XIntc_Connect(&intc, 
		XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_OUT_INTERRUPT_0_INTR,
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_storage_data_out);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_OUT_INTERRUPT_0_INTR);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_OUT_INTERRUPT_0_INTR);

	Status = XIntc_Connect(&intc, 
		XPAR_XI_INTC_STORAGE_Q_STORAGE_IN_2_INTERRUPT_CTRL0_INTR,
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_CMD_IN);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			XPAR_XI_INTC_STORAGE_Q_STORAGE_IN_2_INTERRUPT_CTRL0_INTR);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_XI_INTC_STORAGE_Q_STORAGE_IN_2_INTERRUPT_CTRL0_INTR);

	Status = XIntc_Connect(&intc, 
		XPAR_XI_INTC_STORAGE_Q_STORAGE_OUT_2_INTERRUPT_CTRL0_INTR,
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_CMD_OUT);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			XPAR_XI_INTC_STORAGE_Q_STORAGE_OUT_2_INTERRUPT_CTRL0_INTR);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_XI_INTC_STORAGE_Q_STORAGE_OUT_2_INTERRUPT_CTRL0_INTR);

	Status = XIntc_Connect(&intc, 
		XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_IN_INTERRUPT_CTRL0_INTR,
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_DATA_IN);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_IN_INTERRUPT_CTRL0_INTR);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_IN_INTERRUPT_CTRL0_INTR);

	Status = XIntc_Connect(&intc, 
		XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_OUT_INTERRUPT_CTRL0_INTR,
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_DATA_OUT);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed", 
			XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_OUT_INTERRUPT_CTRL0_INTR);
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, XPAR_XI_INTC_STORAGE_Q_STORAGE_DATA_OUT_INTERRUPT_CTRL0_INTR);

	Status = XIntc_Start(&intc, XIN_REAL_MODE);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Start failed");
		return XST_FAILURE;
	}

	irqNo = 138U;
	XScuGic_Connect(&irq_controller, irqNo, (Xil_InterruptHandler) XIntc_InterruptHandler, (void *)&intc);
	XScuGic_Enable(&irq_controller, irqNo);
	XScuGic_InterruptMaptoCpu(&irq_controller, XPAR_CPU_ID, irqNo);
	XScuGic_SetPriorityTriggerType(&irq_controller, irqNo, 0xA0, 0x1);

	/* Initialize pointers for bookkeeping */
	Mbox_regs[Q_OS1] = &Mbox_OS1;
	Mbox_regs[Q_OS2] = &Mbox_OS2;
	Mbox_regs[Q_RUNTIME1] = &Mbox_runtime1;
	Mbox_regs[Q_RUNTIME2] = &Mbox_runtime2;
	Mbox_regs[Q_KEYBOARD] = &Mbox_keyboard;
	Mbox_regs[Q_SERIAL_OUT] = &Mbox_output;
	Mbox_regs[Q_STORAGE_CMD_IN] = &Mbox_storage_cmd_in;
	Mbox_regs[Q_STORAGE_CMD_OUT] = &Mbox_storage_cmd_out;
	Mbox_regs[Q_STORAGE_DATA_OUT] = &Mbox_storage_data_out;
	Mbox_regs[Q_STORAGE_DATA_IN] = &Mbox_storage_data_in;

	Mbox_ctrl_regs[Q_KEYBOARD] = OCTOPOS_MAILBOX_OS_1WRI_0_BASEADDR;
	Mbox_ctrl_regs[Q_SERIAL_OUT] = OCTOPOS_MAILBOX_OS_3WRI_0_BASEADDR;
	Mbox_ctrl_regs[Q_RUNTIME1] = OCTOPOS_MAILBOX_OS_3WRI_2_BASEADDR;
	Mbox_ctrl_regs[Q_RUNTIME2] = OCTOPOS_MAILBOX_OS_3WRI_1_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_CMD_IN] = OCTOPOS_OS_Q_STORAGE_IN_2_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_CMD_OUT] = OCTOPOS_OS_Q_STORAGE_OUT_2_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_DATA_OUT] = OCTOPOS_OS_Q_STORAGE_DATA_OUT_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_DATA_IN] = OCTOPOS_OS_Q_STORAGE_DATA_IN_BASEADDR;

	/* Initialize semaphores */
	sem_init(&interrupts[Q_OS1], 0, 0);
	sem_init(&interrupts[Q_OS2], 0, 0);
	sem_init(&interrupts[Q_KEYBOARD], 0, 0);
	sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
	sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, 0);
	sem_init(&interrupts[Q_SENSOR], 0, 0);
	sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE);

	sem_init(&availables[Q_KEYBOARD], 0, 1);
	sem_init(&availables[Q_SERIAL_OUT], 0, 1);
	sem_init(&availables[Q_STORAGE_DATA_IN], 0, 1);
	sem_init(&availables[Q_STORAGE_DATA_OUT], 0, 1);
	sem_init(&availables[Q_STORAGE_CMD_IN], 0, 1);
	sem_init(&availables[Q_STORAGE_CMD_OUT], 0, 1);
	sem_init(&availables[Q_SENSOR], 0, 1);
	sem_init(&availables[Q_RUNTIME1], 0, 1);
	sem_init(&availables[Q_RUNTIME2], 0, 1);

	/* Initialize keyboard circular buffer */
	cbuf_keyboard = circular_buf_get_instance(MAILBOX_QUEUE_SIZE);

	/* Initialize PMU IPI */
	u32 pmu_ipi_status = XST_FAILURE;

	ipi_psu_config = XIpiPsu_LookupConfig(XPAR_XIPIPSU_0_DEVICE_ID);
	if (ipi_psu_config == NULL) {
		_SEC_HW_ERROR("RPU: Error: Ipi Init failed");
		return -XST_FAILURE;
	}

	pmu_ipi_status = XIpiPsu_CfgInitialize(
			&ipi_pmu_inst,
			ipi_psu_config,
			ipi_psu_config->BaseAddress);

	if (pmu_ipi_status != XST_SUCCESS) {
		_SEC_HW_ERROR("RPU: Error: IPI Config failed");
		return -XST_FAILURE;
	}

	/* Enable IPI from PMU to RPU_0 */
	Xil_Out32(0xFF310018U, 0xF0000U);

	return XST_SUCCESS;
}

void close_os_mailbox(void)
{
	circular_buf_free(cbuf_keyboard);

	cleanup_platform();
}   
#endif
