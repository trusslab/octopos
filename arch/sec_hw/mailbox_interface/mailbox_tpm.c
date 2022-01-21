#ifdef ARCH_SEC_HW_TPM

#include <stdio.h>
#include "platform.h"
#include "xil_printf.h"
#include "xmbox.h"
#include "xparameters.h"
#include "sleep.h"

XMbox	Mbox_serial,
		Mbox_keyboard,
		Mbox_enclave0,
		Mbox_enclave1,
		Mbox_storage,
		Mbox_network,
		Mbox_os;

/* ported from tpm.h */
#define LOCALITY_BASE		0x80
#define LOCALITY_OS		(LOCALITY_BASE)
#define LOCALITY_KEYBOARD	(LOCALITY_BASE + 0x01)
#define LOCALITY_SERIAL_OUT	(LOCALITY_BASE + 0x02)
#define LOCALITY_STORAGE	(LOCALITY_BASE + 0x03)
#define LOCALITY_NETWORK	(LOCALITY_BASE + 0x04)
#define LOCALITY_BLUETOOTH	(LOCALITY_BASE + 0x05)
#define LOCALITY_RUNTIME1	(LOCALITY_BASE + 0x06)
#define LOCALITY_RUNTIME2	(LOCALITY_BASE + 0x07)
#define LOCALITY_UNTRUSTED	(LOCALITY_BASE + 0x08)
#define LOCALITY_PMU		(LOCALITY_BASE + 0x09)

/* ported from mailbox.h */
#define MAILBOX_QUEUE_MSG_SIZE		64
/* processor IDs */
#define	P_OS			1
#define	P_KEYBOARD		2
#define	P_SERIAL_OUT		3
#define	P_STORAGE		4
#define	P_NETWORK		5
#define	P_BLUETOOTH		6
#define	P_RUNTIME1		7
#define	P_RUNTIME2		8
#define P_UNTRUSTED		9
#define NUM_PROCESSORS		9
#define ALL_PROCESSORS		10
/* FIXME: just used for using the TPM API in PMU. */
#define P_PMU			10
#define INVALID_PROCESSOR	11

/* TPM mailbox uses poll mode */
#define MBOX_TPM_SHA256_HASH_THRESHOLD 0

/* enable TPM */
#define USE_TPM

/* return 1 char from serial */
uint8_t get_tpm_response()
{
#ifdef USE_TPM
	return (uint8_t) getchar();
#else
	return 0xFF;
#endif
}

uint8_t get_locality_from_pid(int pid)
{
	switch (pid) {
	case P_OS:
		return LOCALITY_OS;
	case P_KEYBOARD:
		return LOCALITY_KEYBOARD;
	case P_SERIAL_OUT:
		return LOCALITY_SERIAL_OUT;
	case P_STORAGE:
		return LOCALITY_STORAGE;
	case P_NETWORK:
		return LOCALITY_NETWORK;
	// case P_BLUETOOTH:
	// 	return LOCALITY_BLUETOOTH;
	case P_RUNTIME1:
		return LOCALITY_RUNTIME1;
	case P_RUNTIME2:
		return LOCALITY_RUNTIME2;
	default:
		return 0;
	}
}

static void handle_mailbox_interrupts(void* callback_ref)
{
	u32 mask;
	XMbox *mbox_inst = (XMbox *)callback_ref;
	int pid = -1;
	uint8_t buf[32];
	uint8_t response;
	char good[4] = {0xFF, 0xFF, 0xFF, 0xFF};
	char bad[4] = {0xDD, 0xDD, 0xDD, 0xDD};

	mask = XMbox_GetInterruptStatus(mbox_inst);

	if (mask & XMB_IX_STA) {
		_SEC_HW_DEBUG("interrupt type: XMB_IX_STA");
	} else if (mask & XMB_IX_RTA) {
		_SEC_HW_DEBUG("interrupt type: XMB_IX_RTA");
		XMbox_ReadBlocking(mbox_inst, (u32*)(buf), 32);

		if (callback_ref == &Mbox_serial) {
			pid = P_SERIAL_OUT;
		} else if (callback_ref == &Mbox_keyboard) {
			pid = P_KEYBOARD;
		} else if (callback_ref == &Mbox_enclave0) {
			pid = P_RUNTIME1;
		} else if (callback_ref == &Mbox_enclave1) {
			pid = P_RUNTIME2;
		} else if (callback_ref == &Mbox_storage) {
			pid = P_STORAGE;
		} else if (callback_ref == &Mbox_network) {
			pid = P_NETWORK;
		} else if (callback_ref == &Mbox_os) {
			pid = P_OS;
		} else {
			while(1); /* Should never happen */
		}
	} else if (mask & XMB_IX_ERR) {
		_SEC_HW_DEBUG(
			"interrupt type: XMB_IX_ERR, from %p", callback_ref);
	} else {
		_SEC_HW_DEBUG(
			"interrupt type unknown, mask %d, from %p",
			mask, callback_ref);
	}

	if (pid >= 0) {
		printf("%c", get_locality_from_pid(pid));

		for (int i = 0; i < 32; i++) {
			printf("%c", buf[i]);
		}
	}

	response = get_tpm_response();
	if (response == 0xFF)
		XMbox_WriteBlocking(mbox_inst, (u32*)good, 4);
	else
		XMbox_WriteBlocking(mbox_inst, (u32*)bad, 4);

	XMbox_ClearInterrupt(mbox_inst, mask);
}

/* adapted from octopos semaphore.c */
XMbox* sem_wait_impatient_receive_multiple(int mb_count, ...)
{
	XMbox*			InstancePtr = NULL;
	uint32_t		args_ptrs[mb_count];
	_Bool			has_new = FALSE;

		va_list args;
		va_start(args, mb_count);

		for (int i = 0; i < mb_count; ++i) {
			InstancePtr = va_arg(args, XMbox*);
			args_ptrs[i] = (uint32_t) InstancePtr;
		}

		va_end(args);

		while (!has_new) {
			for (int i = 0; i < mb_count; ++i) {
				if (!XMbox_IsEmpty((XMbox*) args_ptrs[i])) {
					has_new = TRUE;
					InstancePtr = (XMbox*) args_ptrs[i];
					break;
				}
			}
		}

		return InstancePtr;
}


int init_tpm_mailbox(void)
{
	int Status;
	XMbox_Config *ConfigPtr, *ConfigPtr2, 
		*ConfigPtr3, *ConfigPtr4,
		*ConfigPtr5, *ConfigPtr6, *ConfigPtr7;

	ConfigPtr = XMbox_LookupConfig(
		XPAR_TPM_SUBSYS_MAILBOX_TPM_ENCLAVE0_IF_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_enclave0, 
		ConfigPtr, ConfigPtr->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		while(1);
		return -XST_FAILURE;
	}

	ConfigPtr2 = XMbox_LookupConfig(
		XPAR_TPM_SUBSYS_MAILBOX_TPM_ENCLAVE1_IF_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_enclave1, 
		ConfigPtr2, ConfigPtr2->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		while(1);
		return -XST_FAILURE;
	}

	ConfigPtr3 = XMbox_LookupConfig(
		XPAR_TPM_SUBSYS_MAILBOX_TPM_NET_IF_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_network, 
		ConfigPtr3, ConfigPtr3->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		while(1);
		return -XST_FAILURE;
	}

	ConfigPtr4 = XMbox_LookupConfig(
		XPAR_TPM_SUBSYS_MAILBOX_TPM_OS_IF_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_os, 
		ConfigPtr4, ConfigPtr4->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		while(1);
		return -XST_FAILURE;
	}

	ConfigPtr5 = XMbox_LookupConfig(
		XPAR_TPM_SUBSYS_MAILBOX_TPM_STORAGE_IF_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_storage,
	 ConfigPtr5, ConfigPtr5->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		while(1);
		return -XST_FAILURE;
	}

	ConfigPtr6 = XMbox_LookupConfig(
		XPAR_TPM_SUBSYS_MAILBOX_TPM_KEYBOARD_IF_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(&Mbox_keyboard,
	 ConfigPtr6, ConfigPtr6->BaseAddress);
	if (Status != XST_SUCCESS)
	{
		while(1);
		return -XST_FAILURE;
	}

	ConfigPtr7 = XMbox_LookupConfig(
		XPAR_TPM_SUBSYS_MAILBOX_TPM_SERIAL_IF_1_DEVICE_ID);
	Status = XMbox_CfgInitialize(
		&Mbox_serial,
		ConfigPtr7,
		ConfigPtr7->BaseAddress
		);
	if (Status != XST_SUCCESS)
	{
		while(1);
		return -XST_FAILURE;
	}


	XMbox_SetReceiveThreshold(&Mbox_serial, MBOX_TPM_SHA256_HASH_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_serial, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_keyboard, MBOX_TPM_SHA256_HASH_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_keyboard, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_enclave0, MBOX_TPM_SHA256_HASH_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_enclave0, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_enclave1, MBOX_TPM_SHA256_HASH_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_enclave1, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_network, MBOX_TPM_SHA256_HASH_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_network, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_os, MBOX_TPM_SHA256_HASH_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_os, XMB_IX_RTA | XMB_IX_ERR);

	XMbox_SetReceiveThreshold(&Mbox_storage, MBOX_TPM_SHA256_HASH_THRESHOLD);
	XMbox_SetInterruptEnable(&Mbox_storage, XMB_IX_RTA | XMB_IX_ERR);

	return XST_SUCCESS;
}

int main()
{
	int ret;
	XMbox* mbox_inst = NULL;
	uint8_t buf[32];
	uint8_t response;
	char good[4] = {0xFF, 0xFF, 0xFF, 0xFF};
	char bad[4] = {0xDD, 0xDD, 0xDD, 0xDD};
	int pid = -1;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

    init_platform();

	ret = init_tpm_mailbox();
	if (ret != XST_SUCCESS) {
		while(1); // DEBUG HANG
		return 0;
	}

	while(1) {
		mbox_inst = sem_wait_impatient_receive_multiple(7,
			&Mbox_serial,
			&Mbox_keyboard,
			&Mbox_enclave0,
			&Mbox_enclave1,
			&Mbox_storage,
			&Mbox_network,
			&Mbox_os);

		XMbox_ReadBlocking(mbox_inst, (u32*)(buf), 32);

		if (mbox_inst == &Mbox_serial) {
			pid = P_SERIAL_OUT;
		} else if (mbox_inst == &Mbox_keyboard) {
			pid = P_KEYBOARD;
		} else if (mbox_inst == &Mbox_enclave0) {
			pid = P_RUNTIME1;
		} else if (mbox_inst == &Mbox_enclave1) {
			pid = P_RUNTIME2;
		} else if (mbox_inst == &Mbox_storage) {
			pid = P_STORAGE;
		} else if (mbox_inst == &Mbox_network) {
			pid = P_NETWORK;
		} else if (mbox_inst == &Mbox_os) {
			pid = P_OS;
		}

		printf("%c", get_locality_from_pid(pid));

		for (int i = 0; i < 32; i++) {
			printf("%c", buf[i]);
		}

		response = get_tpm_response();
		if (response == 0xFF)
			XMbox_WriteBlocking(mbox_inst, (u32*)good, 4);
		else
			XMbox_WriteBlocking(mbox_inst, (u32*)bad, 4);
	}

    cleanup_platform();
    return 0;
}

#endif