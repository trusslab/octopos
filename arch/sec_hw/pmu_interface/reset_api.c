#ifdef 	ARCH_SEC_HW_OS

#include "sleep.h"

#include <octopos/mailbox.h>
#include <octopos/error.h>
#include <arch/sec_hw.h>
#include <arch/pmu.h>
#include <arch/mem_layout.h>

int pmu_reset_proc(uint8_t proc_id)
{
	unsigned int * reset_reg = 0;
	unsigned int status;

	switch (proc_id) {
	case P_KEYBOARD:
		reset_reg = (unsigned int *) RESET_MODULE_KEYBOARD;
		break;

	case P_SERIAL_OUT:
		reset_reg = (unsigned int *) RESET_MODULE_SERIALOUT;
		break;

	case P_STORAGE:
		reset_reg = (unsigned int *) RESET_MODULE_STORAGE;
		break;

	case P_NETWORK:
		reset_reg = (unsigned int *) RESET_MODULE_ETHERNET;
		break;

	case P_RUNTIME1:
		reset_reg = (unsigned int *) RESET_MODULE_ENCLAVE0;
		break;

	case P_RUNTIME2:
		reset_reg = (unsigned int *) RESET_MODULE_ENCLAVE1;
		break;

	case P_BLUETOOTH:
	case P_OS:
	case P_UNTRUSTED:
	default:
		printf("Error: %s: unexpected proc_id (%d)\n", __func__,
		       proc_id);
		return 0;
	}

	if (!reset_reg)
		return ERR_INVALID;

	/* write reset command */
	*reset_reg = RESET_BURN_VALUE_1;
	*reset_reg = RESET_BURN_VALUE_2;

	for (int i = 0; i++; i < RESET_WAIT_CYCLE) {
		asm("nop");
	}

	status = *(RESET_MODULE_STATUS_OFFSET + reset_reg);

	if (status == RESET_STATUS_SUCCESS) {
		return 0;
	} else if (status == RESET_STATUS_FAILED) {
		printf("Error: %s: resource busy\r\n", __func__);
		return ERR_AVAILABLE;
	} else {
		printf("Error: %s: unexpected status (%08x)\r\n", 
			__func__, status);
		return ERR_FAULT;
	}

	return ERR_FAULT;
}

#endif
