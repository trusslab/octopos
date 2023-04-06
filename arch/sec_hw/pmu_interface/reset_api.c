/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef 	ARCH_SEC_HW_OS

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
		reset_reg = 0;
		printf("Error: %s: unexpected proc_id (%d)\n", __func__,
		       proc_id);
	}

	if (!reset_reg)
		return ERR_INVALID;

	/* write reset command */
	*reset_reg = RESET_BURN_VALUE_1;
	octopos_usleep(1);
	*reset_reg = RESET_BURN_VALUE_2;
	octopos_usleep(1);

	// printf("ADDR: %08x, %08x\r\n", reset_reg, (reset_reg + 1));

	status = *(reset_reg + 1);

	if (status == RESET_STATUS_SUCCESS) {
		return 0;
	} else if (status == RESET_STATUS_FAILED) {
		printf("Error: %s: resource busy\r\n", __func__);
		return ERR_AVAILABLE;
	} else {
		/* FIXME: incorrect return status. need to check hardware IP */
		return 0;
		printf("Error: %s: unexpected status (%08x)\r\n", 
			__func__, status);
		return ERR_FAULT;
	}

	return ERR_FAULT;
}

#endif
