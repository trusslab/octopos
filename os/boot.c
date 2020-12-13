/* OctopOS OS support for boot, reboot, processor reset, and shutdown */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <octopos/mailbox.h>
#include <octopos/runtime.h>
#include <os/file_system.h>
#include <os/storage.h>
#include <os/scheduler.h>
#include <tpm/hash.h>
#include <arch/mailbox_os.h>
#include <arch/pmu.h> 

int untrusted_needs_help_with_boot = 0;

void delegate_tpm_data_in_queue(uint8_t proc_id)
{
	wait_for_queue_availability(Q_TPM_IN);
	mark_queue_unavailable(Q_TPM_IN);
	mailbox_delegate_queue_access(Q_TPM_IN, proc_id,
				      TPM_EXTEND_HASH_NUM_MAILBOX_MSGS,
				      MAILBOX_DEFAULT_TIMEOUT_VAL);
}

static void help_boot_proc(uint8_t proc_id, char *filename)
{
	/* Help with reading the image off of storage */
	uint32_t fd = file_system_open_file(filename, FILE_OPEN_MODE);
	uint32_t num_blocks = file_system_get_file_num_blocks(fd);
	file_system_read_file_blocks(fd, 0, num_blocks, proc_id);
	file_system_read_file_blocks_late();
	file_system_close_file(fd);

	/* Help with sending measurements to TPM */
	if (proc_id != P_UNTRUSTED)
		delegate_tpm_data_in_queue(proc_id);
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
	printf("%s [1]\n", __func__);

	if (proc_id == P_STORAGE)
		close_file_system();

	ret = pmu_reset_proc(proc_id);
	if (ret)
		return ret;	
	printf("%s [2]\n", __func__);

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
	} else if (proc_id == P_STORAGE) {
		uint32_t partition_size = initialize_storage();
		initialize_file_system(partition_size);
	} else if (proc_id == P_UNTRUSTED) {
		if (!untrusted_needs_help_with_boot) {
			untrusted_needs_help_with_boot = 1;
			printf("%s [3]\n", __func__);
			return 1;
		} else {
			help_boot_untrusted_proc();
			untrusted_needs_help_with_boot = 0;
		}
	}
	printf("%s [4]\n", __func__);

	return 0;
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
