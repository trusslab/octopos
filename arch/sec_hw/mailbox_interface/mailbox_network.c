/* OctopOS Network mailbox interface */
#ifdef ARCH_SEC_HW_NETWORK
#include <stdio.h>
#include <stdlib.h>
#include "xil_printf.h"
#include "sleep.h"
#include "xstatus.h"
#include "xintc.h"

#include "arch/sec_hw.h"
#include "arch/semaphore.h"
#include "arch/octopos_xmbox.h"
#include "arch/ring_buffer.h"
#include "arch/octopos_mbox_owner_map.h"
#include "arch/octopos_mbox.h"

#include "octopos/mailbox.h"
#include "octopos/error.h"

extern void network_stack_init(void);
extern void platform_enable_interrupts2();


OCTOPOS_XMbox	Mbox_network_cmd_in,
		Mbox_network_cmd_out,
		Mbox_network_data_in,
		Mbox_network_data_out,
		Mbox_storage_data_out;

XIntc		intc;
sem_t		interrupts[NUM_QUEUES + 1];
OCTOPOS_XMbox*  Mbox_regs[NUM_QUEUES + 1];
UINTPTR		Mbox_ctrl_regs[NUM_QUEUES + 1];

/* FIXME: static buffer for FPGA and will not be freed by free_pkb function */
uint8_t		*dbuf;
uint8_t		send_buf[MAILBOX_QUEUE_MSG_SIZE_LARGE - 2];


void read_data_from_queue(uint8_t *buf, uint8_t queue_id)
{
	OCTOPOS_XMbox_ReadBlocking(Mbox_regs[queue_id], (u32*) buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void write_data_to_queue(uint8_t *buf, uint8_t queue_id)
{
	OCTOPOS_XMbox_WriteBlocking(Mbox_regs[queue_id], (u32*) buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

#ifndef ARCH_SEC_HW_BOOT
void mailbox_change_queue_access_bottom_half(uint8_t queue_id)
{
	/* Threshold registers will need to be reinitialized
	 * every time it switches ownership
	 */
	switch (queue_id) {
		case Q_NETWORK_CMD_OUT:
		case Q_NETWORK_DATA_OUT:
			OCTOPOS_XMbox_SetSendThreshold(Mbox_regs[queue_id], 0);
			OCTOPOS_XMbox_SetInterruptEnable(Mbox_regs[queue_id], OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);
			break;
		case Q_NETWORK_CMD_IN:
			OCTOPOS_XMbox_SetReceiveThreshold(Mbox_regs[queue_id], MAILBOX_DEFAULT_RX_THRESHOLD);
			OCTOPOS_XMbox_SetInterruptEnable(Mbox_regs[queue_id], OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);
			break;
		case Q_NETWORK_DATA_IN:
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
	// printf("%s: [0]\n", __func__);

	mailbox_change_queue_access_bottom_half(queue_id);
	octopos_mailbox_clear_interrupt(Mbox_ctrl_regs[queue_id]);
}

static void handle_mailbox_interrupts(void* callback_ref)
{
	u32		mask;
	OCTOPOS_XMbox	*mbox_inst = (OCTOPOS_XMbox *)callback_ref;

	_SEC_HW_DEBUG("Mailbox ref: %p", callback_ref);
	mask = OCTOPOS_XMbox_GetInterruptStatus(mbox_inst);

	if (mask & OCTOPOS_XMB_IX_STA) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_STA");
		if (callback_ref == &Mbox_network_cmd_out) {
			sem_post(&interrupts[Q_NETWORK_CMD_OUT]);
		} else if (callback_ref == &Mbox_network_data_out) {
			sem_post(&interrupts[Q_NETWORK_DATA_OUT]);
		}
	} else if (mask & OCTOPOS_XMB_IX_RTA) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_RTA");
		if (callback_ref == &Mbox_network_cmd_in) {
			sem_post(&interrupts[Q_NETWORK_CMD_IN]);
		} else if (callback_ref == &Mbox_network_data_in) {
			// FIXME: polling replace interrupt
			sem_post(&interrupts[Q_NETWORK_DATA_IN]);
			//Based on the behaviour of
			//handle_mailbox_interrupts in mailbox_network.c of umode
			sem_post(&interrupts[Q_NETWORK_CMD_IN]);
		}
	} else if (mask & OCTOPOS_XMB_IX_ERR) {
		_SEC_HW_DEBUG("interrupt type: OCTOPOS_XMB_IX_ERR, from %p", callback_ref);
	} else {
		_SEC_HW_DEBUG("interrupt type unknown, mask %d, from %p", mask, callback_ref);
	}

	OCTOPOS_XMbox_ClearInterrupt(mbox_inst, mask);
	_SEC_HW_DEBUG("interrupt cleared");
}

/* FIXME: identical copy form storage.c */
void send_received_packet(uint8_t *buf, uint8_t queue_id)
{
	// sem_wait(&interrupts[queue_id]);
	switch(queue_id) {
        case Q_NETWORK_DATA_OUT:
		OCTOPOS_XMbox_WriteBlocking(&Mbox_network_data_out,
			(u32*) buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
           break;
        case Q_NETWORK_CMD_OUT:
		OCTOPOS_XMbox_WriteBlocking(&Mbox_network_cmd_out,
			(u32*) buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
           break;
        default :
           printf("%s: Error: Invalid queue_id\n", __func__);
	   return;
     }
}

void send_response(uint8_t *buf, uint8_t queue_id)
{
        sem_wait(&interrupts[queue_id]);

        switch(queue_id) {
		case Q_NETWORK_DATA_OUT:
			OCTOPOS_XMbox_WriteBlocking(&Mbox_network_data_out,
				(u32*) buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
			break;
		case Q_NETWORK_CMD_OUT:
			OCTOPOS_XMbox_WriteBlocking(&Mbox_network_cmd_out,
				(u32*) buf, MAILBOX_QUEUE_MSG_SIZE);
			break;
		default :
			printf("%s: Error: Invalid queue_id\n", __func__);
			return;
        }
}

extern void process_cmd(uint8_t *buf, u8 owner_id);
void network_event_loop(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	int is_data_queue = 0;

	u32 status_reg = 0;
	u32 owner_id = 0;
	UINTPTR qptr = Mbox_ctrl_regs[Q_NETWORK_CMD_IN];

	uint16_t data_size;
	uint16_t max_size = MAILBOX_QUEUE_MSG_SIZE_LARGE - 2;

	int count = 0;
	// FIXME: debug info
	printf("%p, %p, %p\r\n", &count, dbuf, send_buf);

	while(1) {
//		printf("%s: in while loop waiting to receive\n", __func__);
//		while(OCTOPOS_XMbox_IsEmpty((OCTOPOS_XMbox*) &Mbox_network_cmd_in) &&
//				OCTOPOS_XMbox_IsEmpty((OCTOPOS_XMbox*) &Mbox_network_data_in));
		is_data_queue = OCTOPOS_XMbox_IsEmpty((OCTOPOS_XMbox*) &Mbox_network_cmd_in);
//		is_data_queue = !OCTOPOS_XMbox_IsEmpty((OCTOPOS_XMbox*) &Mbox_network_data_in);
//		printf("received!\n");
//      	sem_wait(&interrupts[Q_NETWORK_CMD_IN]);
//		sem_getvalue(&interrupts[Q_NETWORK_DATA_IN], &is_data_queue);
		if (!is_data_queue) {
			memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
			OCTOPOS_XMbox_ReadBlocking(&Mbox_network_cmd_in,
				(u32*) buf, MAILBOX_QUEUE_MSG_SIZE);
			status_reg = octopos_mailbox_get_status_reg(qptr);
			owner_id = (status_reg & 0xFF000000)>>24;
			// printf("status_reg is : %x ; owenr_id = %x\n\r",status_reg, owner_id);
			process_cmd(buf, owner_id);
			OCTOPOS_XMbox_WriteBlocking(&Mbox_network_cmd_out,
				(u32*) buf, MAILBOX_QUEUE_MSG_SIZE);
		} else {
			// FIXME: debug info
			++count;
			// sem_wait(&interrupts[Q_NETWORK_DATA_IN]);
			OCTOPOS_XMbox_ReadBlocking(&Mbox_network_data_in,
				(u32*) dbuf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
			// FIXME: debug info
			if (dbuf[0] != 86 && dbuf[0] != 87) {
				printf("Read from dbuf [%u, %u, %u, ...]\r\n", dbuf[0], dbuf[1], dbuf[2]);
				while (1) {
					if (count > 0) printf("??\r\n");
					count = 0;
				}
			}
			data_size = *((uint16_t *) &dbuf[0]);
			if (data_size > max_size) {
				printf("Error: size not supported data_size=%d\n", data_size);
				exit(-1);
				return;
			}
			memcpy(send_buf, dbuf + 2, MAILBOX_QUEUE_MSG_SIZE_LARGE-2);
			// FIXME: debug change of send_packet
			send_packet(dbuf);
			send_packet(send_buf, data_size);
			memset(dbuf, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE);
			if (dbuf[0] != 0 || dbuf[128] != 0 || dbuf[318] != 0)
				printf("!!!\r\n");
			memset(send_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE-2);
		}
	}
}
#endif

int init_network(void)
{
	int			Status;
	OCTOPOS_XMbox_Config	*Config_cmd_out,
				*Config_cmd_in,
				*Config_Data_out,
				*Config_Data_in,
				*Config_Storage_Data_out;

//	init_platform();
#ifndef ARCH_SEC_HW_BOOT

	/* Initialize OCTOPOS_XMbox */
	Config_cmd_in = OCTOPOS_XMbox_LookupConfig(XPAR_NETWORK_MBOX_CMD_IN_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_network_cmd_in, Config_cmd_in, Config_cmd_in->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_NETWORK_MBOX_CMD_IN_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_cmd_out = OCTOPOS_XMbox_LookupConfig(XPAR_NETWORK_MBOX_CMD_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_network_cmd_out, Config_cmd_out, Config_cmd_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_NETWORK_MBOX_CMD_OUT_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_Data_in = OCTOPOS_XMbox_LookupConfig(XPAR_NETWORK_MBOX_DATA_IN_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_network_data_in, Config_Data_in, Config_Data_in->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_NETWORK_MBOX_DATA_IN_DEVICE_ID);
		return XST_FAILURE;
	}

	Config_Data_out = OCTOPOS_XMbox_LookupConfig(XPAR_NETWORK_MBOX_DATA_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_network_data_out, Config_Data_out, Config_Data_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_STORAGE_MBOX_DATA_OUT_DEVICE_ID);
		return XST_FAILURE;
	}


//	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_network_cmd_in, MAILBOX_DEFAULT_RX_THRESHOLD);
//	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_network_cmd_in, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_network_cmd_out, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_network_cmd_out, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);

//	OCTOPOS_XMbox_SetReceiveThreshold(&Mbox_network_data_in, MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
//	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_network_data_in, OCTOPOS_XMB_IX_RTA | OCTOPOS_XMB_IX_ERR);

	OCTOPOS_XMbox_SetSendThreshold(&Mbox_network_data_out, 0);
	OCTOPOS_XMbox_SetInterruptEnable(&Mbox_network_data_out, OCTOPOS_XMB_IX_STA | OCTOPOS_XMB_IX_ERR);


	/* OctopOS mailbox maps must be initialized before setting up interrupts. */
	OMboxIds_init();

	/* Initialize pointers for bookkeeping */
	Mbox_regs[Q_NETWORK_CMD_IN] = &Mbox_network_cmd_in;
	Mbox_regs[Q_NETWORK_CMD_OUT] = &Mbox_network_cmd_out;
	Mbox_regs[Q_NETWORK_DATA_OUT] = &Mbox_network_data_out;
	Mbox_regs[Q_NETWORK_DATA_IN] = &Mbox_network_data_in;

	Mbox_ctrl_regs[Q_NETWORK_CMD_IN] = OCTOPOS_NETWORK_Q_NETWORK_IN_2_BASEADDR;
	Mbox_ctrl_regs[Q_NETWORK_CMD_OUT] = OCTOPOS_NETWORK_Q_NETWORK_OUT_2_BASEADDR;
	Mbox_ctrl_regs[Q_NETWORK_DATA_OUT] = OCTOPOS_NETWORK_Q_NETWORK_DATA_OUT_BASEADDR;
	Mbox_ctrl_regs[Q_NETWORK_DATA_IN] = OCTOPOS_NETWORK_Q_NETWORK_DATA_IN_BASEADDR;

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
			OMboxIntrs[P_NETWORK][Q_NETWORK_DATA_OUT],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_network_data_out);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				OMboxIntrs[P_NETWORK][Q_NETWORK_DATA_OUT]);
		return XST_FAILURE;
	}

//	Status = XIntc_Connect(&intc,
//			OMboxIntrs[P_NETWORK][Q_NETWORK_DATA_IN],
//		(XInterruptHandler)handle_mailbox_interrupts,
//		(void*)&Mbox_network_data_in);
//	if (Status != XST_SUCCESS) {
//		_SEC_HW_ERROR("XIntc_Connect %d failed",
//				OMboxIntrs[P_NETWORK][Q_NETWORK_DATA_IN]);
//		return XST_FAILURE;
//	}

	Status = XIntc_Connect(&intc,
			OMboxIntrs[P_NETWORK][Q_NETWORK_CMD_OUT],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_network_cmd_out);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				OMboxIntrs[P_NETWORK][Q_NETWORK_CMD_OUT]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
			OMboxIntrs[P_NETWORK][Q_NETWORK_CMD_IN],
		(XInterruptHandler)handle_mailbox_interrupts,
		(void*)&Mbox_network_cmd_in);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
				OMboxIntrs[P_NETWORK][Q_NETWORK_CMD_IN]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_CMD_IN],
		(XInterruptHandler)handle_change_queue_interrupts,
		(void*)Q_NETWORK_CMD_IN);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
			OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_CMD_IN]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_CMD_OUT],
		(XInterruptHandler)handle_change_queue_interrupts,
		(void*)Q_NETWORK_CMD_OUT);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
			OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_CMD_OUT]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_DATA_IN],
		(XInterruptHandler)handle_change_queue_interrupts,
		(void*)Q_NETWORK_DATA_IN);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
			OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_DATA_IN]);
		return XST_FAILURE;
	}

	Status = XIntc_Connect(&intc,
		OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_DATA_OUT],
		(XInterruptHandler)handle_change_queue_interrupts,
		(void*)Q_NETWORK_DATA_OUT);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Connect %d failed",
			OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_DATA_OUT]);
		return XST_FAILURE;
	}

	Status = XIntc_Start(&intc, XIN_REAL_MODE);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("XIntc_Start failed");
		return XST_FAILURE;
	}

	/* Enable interrupts */
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_DATA_OUT]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_DATA_IN]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_CMD_OUT]);
	XIntc_Enable(&intc, OMboxCtrlIntrs[P_NETWORK][Q_NETWORK_CMD_IN]);
	XIntc_Enable(&intc, OMboxIntrs[P_NETWORK][Q_NETWORK_DATA_OUT]);
//	XIntc_Enable(&intc, OMboxIntrs[P_NETWORK][Q_NETWORK_DATA_IN]);
	XIntc_Enable(&intc, OMboxIntrs[P_NETWORK][Q_NETWORK_CMD_OUT]);
//	XIntc_Enable(&intc, OMboxIntrs[P_NETWORK][Q_NETWORK_CMD_IN]);

	platform_setup_interrupts2(&intc);

	Xil_ExceptionInit();
	Xil_ExceptionEnable();

	sem_init(&interrupts[Q_NETWORK_DATA_IN], 0, 0);
	sem_init(&interrupts[Q_NETWORK_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_NETWORK_CMD_IN], 0, 0);
	sem_init(&interrupts[Q_NETWORK_CMD_OUT], 0, MAILBOX_QUEUE_SIZE);

	network_stack_init();
	printf("net init done\n\r");
#else
	print("Network init for bootloader\n\r");
	Config_Storage_Data_out = OCTOPOS_XMbox_LookupConfig(XPAR_NETWORK_STORAGE_MBOX_DATA_OUT_DEVICE_ID);
	Status = OCTOPOS_XMbox_CfgInitialize(&Mbox_storage_data_out, Config_Storage_Data_out, Config_Storage_Data_out->BaseAddress);
	if (Status != XST_SUCCESS) {
		_SEC_HW_ERROR("OCTOPOS_XMbox_CfgInitialize %d failed", XPAR_NETWORK_MBOX_DATA_IN_DEVICE_ID);
		return XST_FAILURE;
	}
	Mbox_regs[Q_STORAGE_DATA_OUT] = &Mbox_storage_data_out;
	Mbox_ctrl_regs[Q_STORAGE_DATA_OUT] = OCTOPOS_NETWORK_Q_STORAGE_DATA_OUT_BASEADDR;
	print("Network init for bootloader done\n\r");
#endif

	return XST_SUCCESS;
}

void close_network(void)
{
 //       cleanup_platform();
}
#endif
