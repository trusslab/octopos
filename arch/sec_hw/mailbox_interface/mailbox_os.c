/* OctopOS OS mailbox interface */
#ifdef ARCH_SEC_HW_OS
#include <stdio.h>
#include <stdlib.h>
#include "xil_printf.h"
#include "xstatus.h"
#include "arch/octopos_xmbox.h"
#include "xparameters.h"
#include "xil_exception.h"
#include "xintc.h"
#include "xgpio.h"
#include "sleep.h"

#include "arch/sec_hw.h"
#include "arch/semaphore.h"
#include "arch/ring_buffer.h"
#include "arch/octopos_mbox.h"
#include "arch/octopos_mbox_owner_map.h"
#include "arch/mailbox_os.h"

#include "octopos/error.h"
#include "octopos/mailbox.h"
#include "os/scheduler.h"

XIntc			intc;

OCTOPOS_XMbox	Mbox_output, 
				Mbox_keyboard, 
				Mbox_OS1, 
				Mbox_OS2, 
				Mbox_runtime1, 
				Mbox_runtime2,
				Mbox_storage_cmd_in,
				Mbox_storage_cmd_out,
				Mbox_storage_data_in,
				Mbox_storage_data_out,
				Mbox_untrusted,
				Mbox_osu;

sem_t			interrupts[NUM_QUEUES + 1];
sem_t			interrupt_input;
sem_t			availables[NUM_QUEUES + 1];

cbuf_handle_t	cbuf_keyboard;

OCTOPOS_XMbox*			Mbox_regs[NUM_QUEUES + 1];
UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1] = {0};

XGpio reset_gpio_0;

int is_queue_available(uint8_t queue_id)
{
	int available;

	sem_getvalue(&availables[queue_id], &available);
	return available;
}

void wait_for_queue_availability(uint8_t queue_id)
{
	sem_wait(&availables[queue_id]);
	sem_init(&availables[queue_id], 0, 1);
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
	int             is_keyboard = 0, is_os1 = 0, is_os2 = 0, is_osu = 0; 
	static uint8_t  turn = Q_OS1;
	uint8_t          *message_buffer;
	u32		        bytes_read;

	OCTOPOS_XMbox*          InstancePtr = NULL;

	InstancePtr = sem_wait_impatient_receive_multiple(
		&interrupt_input, 
		4, 
		&Mbox_keyboard, 
		&Mbox_OS1, 
		&Mbox_OS2,
		&Mbox_osu);

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
	} else if (InstancePtr == &Mbox_osu) {
		sem_post(&interrupts[Q_OSU]);
		is_osu = 1;
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
		} else if (is_os1 && is_os2) {
			sem_wait(&interrupts[turn]);
			*queue_id = turn;
			if (turn == Q_OS1)
				turn = Q_OS2;
			else
				turn = Q_OS1;
		} else if (is_osu) {
			sem_wait(&interrupts[Q_OSU]);
			*queue_id = Q_OSU;
		}
	}

	switch (*queue_id) {
		/* FIXME: duplicate code in this switch case */
	case Q_KEYBOARD:
		message_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));

#ifdef HW_MAILBOX_BLOCKING
		OCTOPOS_XMbox_ReadBlocking(&Mbox_keyboard, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE);
#else
		if (sketch_buffer[*queue_id])
			OCTOPOS_XMbox_Read(&Mbox_keyboard,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE - sketch_buffer_offset[*queue_id],
					&bytes_read);
		else
			OCTOPOS_XMbox_Read(&Mbox_keyboard,
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
		OCTOPOS_XMbox_ReadBlocking(&Mbox_OS1, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE);
#else
		if (sketch_buffer[*queue_id])
			OCTOPOS_XMbox_Read(&Mbox_OS1,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE - sketch_buffer_offset[*queue_id],
					&bytes_read);
		else
			OCTOPOS_XMbox_Read(&Mbox_OS1,
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
		OCTOPOS_XMbox_ReadBlocking(&Mbox_OS2, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE);
#else
		if (sketch_buffer[*queue_id])
			OCTOPOS_XMbox_Read(&Mbox_OS2,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE - sketch_buffer_offset[*queue_id],
					&bytes_read);
		else
			OCTOPOS_XMbox_Read(&Mbox_OS2,
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
	case Q_OSU:
		message_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
		
#ifndef HW_MAILBOX_BLOCKING
		OCTOPOS_XMbox_ReadBlocking(&Mbox_osu, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE);
#else
		if (sketch_buffer[*queue_id])
			OCTOPOS_XMbox_Read(&Mbox_osu,
					(u32*)(message_buffer),
					MAILBOX_QUEUE_MSG_SIZE - sketch_buffer_offset[*queue_id],
					&bytes_read);
		else
			OCTOPOS_XMbox_Read(&Mbox_osu,
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

	_SEC_HW_DEBUG("%02X %02X %02X %02X %02X %02X %02X %02X",
			buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
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

/*
 * Compares limit and timeout to the max vals allowed and use
 * the max vals if larger.
 */
void mailbox_delegate_queue_access(uint8_t queue_id, uint8_t proc_id,
				   limit_t limit, timeout_t timeout)
{
	u8 factor = MAILBOX_QUEUE_MSG_SIZE / 4;
	mailbox_state_reg_t new_state;

	_SEC_HW_ASSERT_VOID(queue_id <= NUM_QUEUES + 1)

	new_state.owner = OMboxIds[queue_id][proc_id];

	if (limit > MAILBOX_MAX_LIMIT_VAL / factor)
		new_state.limit = MAILBOX_MAX_LIMIT_VAL;
	else
		new_state.limit = limit * factor;

	if (timeout > MAILBOX_MAX_TIMEOUT_VAL)
		new_state.timeout = MAILBOX_MAX_TIMEOUT_VAL;
	else
		new_state.timeout = timeout;

	UINTPTR queue_ptr = Mbox_ctrl_regs[queue_id];
	_SEC_HW_DEBUG("queue %d: ctrl reg %p", queue_id, queue_ptr);
	_SEC_HW_DEBUG("Writing: %08x", new_state);
	_SEC_HW_DEBUG("Before yielding: %08x", octopos_mailbox_get_status_reg(queue_ptr));

	octopos_mailbox_set_status_reg(queue_ptr, *(u32 *) (&new_state));

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

int send_cmd_to_network(uint8_t *buf) 
{
	//TODO: Implement
}

int send_cmd_to_untrusted(uint8_t *buf)
{
	sem_wait_impatient_send(
		&interrupts[Q_UNTRUSTED], 
		Mbox_regs[Q_UNTRUSTED], 
		(u32*) buf);
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
			OCTOPOS_XMbox_SetReceiveThreshold(Mbox_regs[queue_id], MAILBOX_DEFAULT_RX_THRESHOLD);
			OCTOPOS_XMbox_SetInterruptEnable(Mbox_regs[queue_id], OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;
		case Q_STORAGE_DATA_OUT:
			OCTOPOS_XMbox_SetReceiveThreshold(Mbox_regs[queue_id], MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
			OCTOPOS_XMbox_SetInterruptEnable(Mbox_regs[queue_id], OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;

		case Q_SERIAL_OUT:
		case Q_RUNTIME1:
		case Q_RUNTIME2:
		case Q_STORAGE_CMD_IN:
		case Q_STORAGE_DATA_IN:
			OCTOPOS_XMbox_SetSendThreshold(Mbox_regs[queue_id], 0);
			OCTOPOS_XMbox_SetInterruptEnable(Mbox_regs[queue_id], OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);
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

static void handle_mailbox_interrupts(void* callback_ref) 
{
	u32         mask;
	OCTOPOS_XMbox       *mbox_inst = (OCTOPOS_XMbox *)callback_ref;

	_SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
	mask = OCTOPOS_XMbox_GetInterruptStatus(mbox_inst);

	if (mask & OCTOPOS_XMB_IX_STA) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_STA");
		if (callback_ref == &Mbox_output) {
			/* Serial Out */
			_SEC_HW_DEBUG("from Mbox_output");

			sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
			sem_post(&availables[Q_SERIAL_OUT]);
			_SEC_HW_DEBUG("Q_SERIAL_OUT = %d", interrupts[Q_SERIAL_OUT].count);
		} else if (callback_ref == &Mbox_runtime1) {
			/* Runtime 1 */
			_SEC_HW_DEBUG("from Runtime1");

			sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE);
			sem_post(&availables[Q_RUNTIME1]);
			_SEC_HW_DEBUG("Q_RUNTIME1 = %d", interrupts[Q_RUNTIME1].count);
		} else if (callback_ref == &Mbox_runtime2) {
			/* Runtime 2 */
			_SEC_HW_DEBUG("from Runtime2");

			sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE);
			sem_post(&availables[Q_RUNTIME2]);
			_SEC_HW_DEBUG("Q_RUNTIME2 = %d", interrupts[Q_RUNTIME2].count);
		} else if (callback_ref == &Mbox_untrusted) {
			/* Runtime 2 */
			_SEC_HW_DEBUG("from Untrusted");

			sem_init(&interrupts[Q_UNTRUSTED], 0, MAILBOX_QUEUE_SIZE);
			sem_post(&availables[Q_UNTRUSTED]);
			_SEC_HW_DEBUG("Q_UNTRUSTED = %d", interrupts[Q_UNTRUSTED].count);
		}  else if (callback_ref == &Mbox_storage_data_in) {
			/* Storage data in */
			_SEC_HW_DEBUG("from Mbox_storage_data_in");

			sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
			sem_post(&availables[Q_STORAGE_DATA_IN]);
		} else if (callback_ref == &Mbox_storage_cmd_in) {
			_SEC_HW_DEBUG("from Mbox_storage_cmd_in");
			
			sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, MAILBOX_QUEUE_SIZE);
			sem_post(&availables[Q_STORAGE_CMD_IN]);
		}
		
	} else if (mask & OCTOPOS_XMB_IX_RTA) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_RTA");
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
		} else if (callback_ref == &Mbox_osu) {
			/* OSU */
			_SEC_HW_DEBUG("from Mbox_osu");

			sem_post(&availables[Q_OSU]);
			sem_post(&interrupts[Q_OSU]);
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
	} else if (mask & OCTOPOS_XMB_IX_ERR) {
		_SEC_HW_ERROR("interrupt type: OCTOPOS_XMB_IX_ERR, from %p", callback_ref);
	} else {
		_SEC_HW_ERROR("interrupt type unknown, mask %d, from %p", mask, callback_ref);
	}

	OCTOPOS_XMbox_ClearInterrupt(mbox_inst, mask);

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

	OCTOPOS_XMbox_Config	*ConfigPtr, *ConfigPtr2, *ConfigPtr3, *ConfigPtr4,
					*ConfigPtr_runtime1, *ConfigPtr_runtime2, *Config_storage_cmd_in,
					*Config_storage_cmd_out, *Config_storage_data_in, *Config_storage_data_out,
					*Config_untrusted, *Config_osu;

	init_platform();
	OMboxIds_init();

	/* Wait until all other PL cores are loaded */
	sleep(1);

	ConfigPtr = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_SERIAL_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_output, ConfigPtr, ConfigPtr->BaseAddress);
	if (Status != XST_SUCCESS) 
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_SERIAL_OUT_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr2 = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_KEYBOARD_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_keyboard, ConfigPtr2, ConfigPtr2->BaseAddress);
	if (Status != XST_SUCCESS) 
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_KEYBOARD_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr3 = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_ENCLAVE0_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_OS1, ConfigPtr3, ConfigPtr3->BaseAddress);
	if (Status != XST_SUCCESS) 
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_ENCLAVE0_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr4 = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_ENCLAVE1_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_OS2, ConfigPtr4, ConfigPtr4->BaseAddress);
	if (Status != XST_SUCCESS) 
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_ENCLAVE1_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr_runtime1 = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_RUNTIME1_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_runtime1, ConfigPtr_runtime1, ConfigPtr_runtime1->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_RUNTIME1_DEVICE_ID);
		return -XST_FAILURE;
	}

	ConfigPtr_runtime2 = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_RUNTIME2_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_runtime2, ConfigPtr_runtime2, ConfigPtr_runtime2->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_RUNTIME2_DEVICE_ID);
		return -XST_FAILURE;
	}

	Config_storage_data_in = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_STORAGE_DATA_IN_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(
		&Mbox_storage_data_in, 
		Config_storage_data_in,
		Config_storage_data_in->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_STORAGE_DATA_IN_DEVICE_ID);
		return -XST_FAILURE;
	}

	Config_storage_data_out = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(
		&Mbox_storage_data_out, 
		Config_storage_data_out,
		Config_storage_data_out->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_DEVICE_ID);
		return -XST_FAILURE;
	}

	Config_storage_cmd_in = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_CMD_IN_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(
		&Mbox_storage_cmd_in, 
		Config_storage_cmd_in,
		Config_storage_cmd_in->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_CMD_IN_DEVICE_ID);
		return -XST_FAILURE;
	}

	Config_storage_cmd_out = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_CMD_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(
		&Mbox_storage_cmd_out, 
		Config_storage_cmd_out,
		Config_storage_cmd_out->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_CMD_OUT_DEVICE_ID);
		return -XST_FAILURE;
	}

	Config_untrusted = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_UNTRUSTED_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(
		&Mbox_untrusted, 
		Config_untrusted,
		Config_untrusted->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_UNTRUSTED_DEVICE_ID);
		return -XST_FAILURE;
	}
	
	Config_osu = OCTOPOS_XMbox_LookupConfig(XPAR_OS_MBOX_Q_OSU_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(
		&Mbox_osu, 
		Config_osu,
		Config_osu->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_OS_MBOX_Q_OSU_DEVICE_ID);
		return -XST_FAILURE;
	}

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_output, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_output, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_keyboard, MAILBOX_DEFAULT_RX_THRESHOLD);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_keyboard, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_OS1, MAILBOX_DEFAULT_RX_THRESHOLD);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_OS1, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_OS2, MAILBOX_DEFAULT_RX_THRESHOLD);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_OS2, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_osu, MAILBOX_DEFAULT_RX_THRESHOLD);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_osu, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_runtime1, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_runtime1, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_runtime2, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_runtime2, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_untrusted, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_untrusted, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_storage_cmd_in, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_cmd_in, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_storage_cmd_out, MAILBOX_DEFAULT_RX_THRESHOLD);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_cmd_out, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_storage_data_out, MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_data_out, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_storage_data_in, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_storage_data_in, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

	Xil_ExceptionInit();
	Xil_ExceptionEnable();

	Status = XIntc_Initialize(&intc, XPAR_INTC_SINGLE_DEVICE_ID);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxIntrs[P_OS][Q_SERIAL_OUT],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void *)&Mbox_output);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxIntrs[P_OS][Q_KEYBOARD],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void *)&Mbox_keyboard);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxIntrs[P_OS][Q_OS1],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void *)&Mbox_OS1);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxIntrs[P_OS][Q_OS2],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void *)&Mbox_OS2);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxIntrs[P_OS][Q_RUNTIME1],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void *)&Mbox_runtime1);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxIntrs[P_OS][Q_RUNTIME2],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void *)&Mbox_runtime2);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			OMboxCtrlIntrs[P_OS][Q_RUNTIME1],
		(XInterruptHandler)handle_change_queue_interrupts,
		(void *)Q_RUNTIME1);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			OMboxCtrlIntrs[P_OS][Q_RUNTIME2],
		(XInterruptHandler)handle_change_queue_interrupts,
		(void *)Q_RUNTIME2);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxIntrs[P_OS][Q_UNTRUSTED],
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_untrusted);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxIntrs[P_OS][Q_OSU],
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_osu);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			OMboxCtrlIntrs[P_OS][Q_SERIAL_OUT],
		(XInterruptHandler)handle_change_queue_interrupts,
		(void *)Q_SERIAL_OUT);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			OMboxCtrlIntrs[P_OS][Q_KEYBOARD],
		(XInterruptHandler)handle_change_queue_interrupts,
		(void *)Q_KEYBOARD);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			XPAR_MICROBLAZE_6_AXI_INTC_FIT_TIMER_2_INTERRUPT_INTR,
		(XInterruptHandler)handle_fixed_timer_interrupts,
		(void *)0);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxIntrs[P_OS][Q_STORAGE_CMD_IN],
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_storage_cmd_in);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxIntrs[P_OS][Q_STORAGE_CMD_OUT],
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_storage_cmd_out);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxIntrs[P_OS][Q_STORAGE_DATA_IN],
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_storage_data_in);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxIntrs[P_OS][Q_STORAGE_DATA_OUT],
		(XInterruptHandler)handle_mailbox_interrupts, 
		(void*)&Mbox_storage_data_out);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxCtrlIntrs[P_OS][Q_STORAGE_CMD_IN],
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_CMD_IN);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxCtrlIntrs[P_OS][Q_STORAGE_CMD_OUT],
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_CMD_OUT);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxCtrlIntrs[P_OS][Q_STORAGE_DATA_IN],
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_DATA_IN);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc, 
			OMboxCtrlIntrs[P_OS][Q_STORAGE_DATA_OUT],
		(XInterruptHandler)handle_change_queue_interrupts, 
		(void*)Q_STORAGE_DATA_OUT);
	if (Status != XST_SUCCESS) {
		return XST_FAILURE;
	}

	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_STORAGE_CMD_IN]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_STORAGE_CMD_OUT]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_STORAGE_DATA_IN]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_STORAGE_DATA_OUT]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_SERIAL_OUT]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_KEYBOARD]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_OS1]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_OS2]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_OSU]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_RUNTIME1]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_RUNTIME2]);
	XIntc_Enable(&intc, OMboxIntrs[P_OS][Q_UNTRUSTED]);
	XIntc_Enable(&intc, XPAR_MICROBLAZE_6_AXI_INTC_FIT_TIMER_2_INTERRUPT_INTR);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_OS][Q_SERIAL_OUT]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_OS][Q_KEYBOARD]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_OS][Q_RUNTIME1]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_OS][Q_RUNTIME2]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_OS][Q_STORAGE_CMD_IN]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_OS][Q_STORAGE_CMD_OUT]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_OS][Q_STORAGE_DATA_IN]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_OS][Q_STORAGE_DATA_OUT]);

	Status = XIntc_Start(&intc, XIN_REAL_MODE);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Start failed");
		return XST_FAILURE;
	}

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
	Mbox_regs[Q_UNTRUSTED] = &Mbox_untrusted;
	Mbox_regs[Q_OSU] = &Mbox_osu;

	Mbox_ctrl_regs[Q_KEYBOARD] = OCTOPOS_OS_Q_KEYBOARD_BASEADDR;
	Mbox_ctrl_regs[Q_SERIAL_OUT] = OCTOPOS_OS_Q_SERIAL_OUT_BASEADDR;
	Mbox_ctrl_regs[Q_RUNTIME1] = OCTOPOS_OS_Q_RUNTIME1_BASEADDR;
	Mbox_ctrl_regs[Q_RUNTIME2] = OCTOPOS_OS_Q_RUNTIME2_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_CMD_IN] = OCTOPOS_OS_Q_STORAGE_IN_2_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_CMD_OUT] = OCTOPOS_OS_Q_STORAGE_OUT_2_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_DATA_OUT] = OCTOPOS_OS_Q_STORAGE_DATA_OUT_BASEADDR;
	Mbox_ctrl_regs[Q_STORAGE_DATA_IN] = OCTOPOS_OS_Q_STORAGE_DATA_IN_BASEADDR;

	/* Initialize semaphores */
	sem_init(&interrupts[Q_OS1], 0, 0);
	sem_init(&interrupts[Q_OS2], 0, 0);
	sem_init(&interrupts[Q_OSU], 0, 0);
	sem_init(&interrupts[Q_KEYBOARD], 0, 0);
	sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
	sem_init(&interrupts[Q_STORAGE_CMD_IN], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_CMD_OUT], 0, 0);
	sem_init(&interrupts[Q_SENSOR], 0, 0);
	sem_init(&interrupts[Q_RUNTIME1], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_RUNTIME2], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_UNTRUSTED], 0, MAILBOX_QUEUE_SIZE);

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

	/* Initialize GPIO. This is an ad-hoc impl of secure reset */
	Status = XGpio_Initialize(&reset_gpio_0, XPAR_AXI_GPIO_1_DEVICE_ID);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("Error: XGpio_initialize failed");
		return -XST_FAILURE;
	}

	XGpio_SetDataDirection(&reset_gpio_0, 1, 0x0);
	XGpio_SetDataDirection(&reset_gpio_0, 2, 0x0);

	return XST_SUCCESS;
}

void close_os_mailbox(void)
{
	circular_buf_free(cbuf_keyboard);

	cleanup_platform();
}   
#endif
