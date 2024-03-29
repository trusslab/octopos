/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#if !defined(ARCH_SEC_HW_BOOT)

/* OctopOS OS support for boot, reboot, processor reset, and shutdown */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <octopos/mailbox.h>
#include <octopos/runtime.h>
#include <octopos/error.h>
#include <os/file_system.h>
#include <os/storage.h>
#include <os/scheduler.h>
#include <arch/mailbox_os.h>
#include <arch/pmu.h>

#ifdef ARCH_SEC_HW
#include "arch/sec_hw.h"
#include "arch/octopos_xmbox.h"

#define ARCH_SEC_HW_EVALUATION

extern OCTOPOS_XMbox* Mbox_regs[NUM_QUEUES + 1];
extern UINTPTR Mbox_ctrl_regs[NUM_QUEUES + 1];
extern long long global_counter;

u32 octopos_mailbox_get_status_reg(UINTPTR base);
#endif

int untrusted_needs_help_with_boot = 0;

static void help_boot_proc(uint8_t proc_id, char *filename)
{
#ifdef ARCH_UMODE
	char signature_filename[128];
#endif

	/* Help with reading the image off of storage */
	uint32_t fd = file_system_open_file(filename, FILE_OPEN_MODE);
	uint32_t num_blocks = file_system_get_file_num_blocks(fd);
	file_system_read_file_blocks(fd, 0, num_blocks, proc_id);
	file_system_read_file_blocks_late();
	file_system_close_file(fd);
	wait_for_storage();

#ifdef ARCH_SEC_HW
	/* FIXME: unnecessary check */
	while(0xdeadbeef == 
		octopos_mailbox_get_status_reg(Mbox_ctrl_regs[Q_STORAGE_DATA_OUT]));
	OCTOPOS_XMbox_Flush(Mbox_regs[Q_STORAGE_DATA_OUT]);
#endif

#ifdef ARCH_UMODE
	/* Help with reading the signature file needed for secure boot. */
	strcpy(signature_filename, filename);
	strcat(signature_filename, "_signature");

	fd = file_system_open_file(signature_filename, FILE_OPEN_MODE);
	num_blocks = file_system_get_file_num_blocks(fd);
	file_system_read_file_blocks(fd, 0, num_blocks, proc_id);
	file_system_read_file_blocks_late();
	file_system_close_file(fd);
	wait_for_storage();
#endif
}

static void help_boot_keyboard_proc(void)
{
	help_boot_proc(P_KEYBOARD, (char *) "keyboard");
}

static void help_boot_serial_out_proc(void)
{
	help_boot_proc(P_SERIAL_OUT, (char *) "serial_out");
}

static void help_boot_network_proc(void)
{
	help_boot_proc(P_NETWORK, (char *) "network");
}

static void help_boot_bluetooth_proc(void)
{
	help_boot_proc(P_BLUETOOTH, (char *) "bluetooth");
}

void help_boot_runtime_proc(uint8_t runtime_proc_id)
{
#ifndef ARCH_SEC_HW
	help_boot_proc(runtime_proc_id, (char *) "runtime");
#else
	if (runtime_proc_id == P_RUNTIME1)
		help_boot_proc(runtime_proc_id, (char *) "runtime1");
	else if (runtime_proc_id == P_RUNTIME2)
		help_boot_proc(runtime_proc_id, (char *) "runtime2");
	else
		SEC_HW_DEBUG_HANG();
#endif
}

static void help_boot_untrusted_proc(void)
{
	help_boot_proc(P_UNTRUSTED, (char *) "linux");
}

void help_boot_procs(int boot_untrusted)
{
#ifdef ARCH_SEC_HW_EVALUATION
	printf("init done\r\n");
	global_counter = 0;
#endif /* ARCH_SEC_HW_EVALUATION */

	help_boot_keyboard_proc();

#ifdef ARCH_SEC_HW_EVALUATION
	printf("keyboard %d\r\n", global_counter);
	global_counter = 0;
#endif /* ARCH_SEC_HW_EVALUATION */

	help_boot_serial_out_proc();

#ifdef ARCH_SEC_HW_EVALUATION
	printf("serial %d\r\n", global_counter);
	global_counter = 0;
#endif /* ARCH_SEC_HW_EVALUATION */

	help_boot_network_proc();

#ifdef ARCH_SEC_HW_EVALUATION
	printf("net %d\r\n", global_counter);
#endif /* ARCH_SEC_HW_EVALUATION */

#ifndef ARCH_SEC_HW
	help_boot_bluetooth_proc();
#endif /* ARCH_SEC_HW */

#ifdef ARCH_SEC_HW_EVALUATION
	global_counter = 0;
#endif /* ARCH_SEC_HW_EVALUATION */

	help_boot_runtime_proc(P_RUNTIME1);

#ifdef ARCH_SEC_HW_EVALUATION
	printf("enclave0 %d\r\n", global_counter);
	global_counter = 0;
#endif /* ARCH_SEC_HW_EVALUATION */

	help_boot_runtime_proc(P_RUNTIME2);

#ifdef ARCH_SEC_HW_EVALUATION
	printf("enclave1 %d\r\n", global_counter);
	global_counter = 0;
#endif /* ARCH_SEC_HW_EVALUATION */

	if (boot_untrusted)
		help_boot_untrusted_proc();
	
#ifdef ARCH_SEC_HW_EVALUATION
	printf("linux %d\r\n", global_counter);
#endif /* ARCH_SEC_HW_EVALUATION */
}

int reset_proc(uint8_t proc_id)
{
	int ret;

	if (proc_id == P_STORAGE) {
		printf("Error: %s: unexpected proc_id (storage).\n", __func__);
		return ERR_UNEXPECTED;
	}

	ret = pmu_reset_proc(proc_id);
	if (ret)
		return ret;	

	if (proc_id == P_RUNTIME1 || proc_id == P_RUNTIME2) {
		/* set the state of runtime procs to resetting */
		sched_runtime_reset(proc_id);
		help_boot_runtime_proc(proc_id);
	} else if (proc_id == P_KEYBOARD) {
		help_boot_keyboard_proc();
	} else if (proc_id == P_SERIAL_OUT) {
		help_boot_serial_out_proc();
		/* Making sure serial_out boots completely before we return
		 * to shell, which will send output commands to it.
		 * If these commands are received by its bootloader, it will
		 * confuse it.
		 */
		while (!is_queue_available(Q_STORAGE_DATA_OUT));
	} else if (proc_id == P_NETWORK) {
		help_boot_network_proc();
	} else if (proc_id == P_BLUETOOTH) {
		help_boot_bluetooth_proc();
		/* Making sure bluetooth boots completely before we return
		 * to the syscall handler, which will send a bind command to it.
		 * If this command is received by its bootloader, it will
		 * confuse it.
		 */
		while (!is_queue_available(Q_STORAGE_DATA_OUT));
	} else if (proc_id == P_UNTRUSTED) {
		if (!untrusted_needs_help_with_boot) {
			untrusted_needs_help_with_boot = 1;
			return 1;
		} else {
			help_boot_untrusted_proc();
			untrusted_needs_help_with_boot = 0;
		}
	}
	return 0;
}

int reset_proc_simple(uint8_t proc_id)
{
	int ret;

	ret = pmu_reset_proc(proc_id);
	
	return ret;	
}

int reboot_system(void)
{
	int ret = 0;

#ifndef ARCH_SEC_HW
	/* send a reboot cmd to PMU */
	ret = pmu_reboot();
#endif
	return ret;
}

int halt_system(void)
{
	int ret = 0;
	
#ifndef ARCH_SEC_HW
	/* send a shutdown cmd to PMU */
	/* FIXME: there is a race condition here.
	 * Our halt cmd sent to the untrusted domain might trigger the PMU
	 * to reboot it before PMU receives the shutdown cmd.
	 */
	ret = pmu_shutdown();
#endif
	return ret;
}

#endif
