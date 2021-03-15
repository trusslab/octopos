#ifndef ARCH_SEC_HW_OS

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

int untrusted_needs_help_with_boot = 0;

static void help_boot_proc(uint8_t proc_id, char *filename)
{
#ifdef ARCH_UMODE
	char signature_filename[128];
#endif

	/* Help with reading the image off of storage. */
	uint32_t fd = file_system_open_file(filename, FILE_OPEN_MODE);
	uint32_t num_blocks = file_system_get_file_num_blocks(fd);
	file_system_read_file_blocks(fd, 0, num_blocks, proc_id);
	file_system_read_file_blocks_late();
	file_system_close_file(fd);
	wait_for_storage();

#ifdef ARCH_UMODE
	printf("%s [1]\n", __func__);
	/* Help with reading the signature file needed for secure boot. */
	strcpy(signature_filename, filename);
	strcat(signature_filename, "_signature");

	fd = file_system_open_file(signature_filename, FILE_OPEN_MODE);
	printf("%s [3]: fd = %d\n", __func__, fd);
	num_blocks = file_system_get_file_num_blocks(fd);
	printf("%s [4]: num_blocks = %d\n", __func__, num_blocks);
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
	help_boot_proc(runtime_proc_id, (char *) "runtime");
}

static void help_boot_untrusted_proc(void)
{
	help_boot_proc(P_UNTRUSTED, (char *) "linux");
}

void help_boot_procs(int boot_untrusted)
{
	help_boot_keyboard_proc();
	help_boot_serial_out_proc();
	help_boot_network_proc();
	help_boot_bluetooth_proc();
	help_boot_runtime_proc(P_RUNTIME1);
	help_boot_runtime_proc(P_RUNTIME2);
	if (boot_untrusted)
		help_boot_untrusted_proc();
}

int reset_proc(uint8_t proc_id)
{
	int ret;

	if (proc_id == P_STORAGE) {
		printf("Error: %s: unexpected proc_id (storage).\n", __func__);
		return ERR_UNEXPECTED;
		//close_file_system();
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
	int ret;

	/* send a reboot cmd to PMU */
	ret = pmu_reboot();

	return ret;
}

int halt_system(void)
{
	int ret;

	/* send a shutdown cmd to PMU */
	/* FIXME: there is a race condition here.
	 * Our halt cmd sent to the untrusted domain might trigger the PMU
	 * to reboot it before PMU receives the shutdown cmd.
	 */
	ret = pmu_shutdown();

	return ret;
}

#endif
