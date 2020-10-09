/* OctopOS OS */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <octopos/mailbox.h>
#include <os/scheduler.h>
#include <os/shell.h>
#include <os/file_system.h>
#include <os/syscall.h>
#include <os/storage.h>
#include <arch/mailbox_os.h>
#include <arch/pmu.h> 
#include <arch/defines.h>

static void distribute_input(void)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t queue_id;

	memset(input_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	/* FIXME: we should use separate threads for these two */
	recv_input(input_buf, &queue_id);
	if (queue_id == Q_KEYBOARD) {
		shell_process_input((char) input_buf[0]);
	} else if (queue_id == Q_OS1) {
		process_system_call(input_buf, P_RUNTIME1);
	} else if (queue_id == Q_OS2) {
		process_system_call(input_buf, P_RUNTIME2);
	} else if (queue_id == Q_OSU) {
		process_system_call(input_buf, P_UNTRUSTED);
#ifdef ARCH_SEC_HW
	} else if (queue_id == 0) {
#endif
	} else {
		printf("Error (%s): invalid queue_id (%d)\n", __func__, queue_id);
		exit(-1);
	}
}

void help_boot_other_procs(void)
{
	/* keyboard proc */
	printf("%s [1]\n", __func__);
	uint32_t fd = file_system_open_file((char *) "keyboard.so", FILE_OPEN_MODE);
	uint32_t num_blocks = file_system_get_file_num_blocks(fd);
	printf("%s [2]: num_blocks = %d\n", __func__, num_blocks);
	file_system_read_file_blocks(fd, 0, num_blocks, P_KEYBOARD);
	file_system_write_file_blocks_late();
	file_system_close_file(fd);
	printf("%s [3]\n", __func__);

	/* serial_out proc */
	fd = file_system_open_file((char *) "serial_out.so", FILE_OPEN_MODE);
	num_blocks = file_system_get_file_num_blocks(fd);
	file_system_read_file_blocks(fd, 0, num_blocks, P_SERIAL_OUT);
	file_system_write_file_blocks_late();
	file_system_close_file(fd);

	wait_for_storage();
}


int main()
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: OS init\n", __func__);
	printf("%s [0.1]\n", __func__);

	int ret = init_os_mailbox();
	if (ret)
		return ret;
	printf("%s [1]\n", __func__);
	
	//release_tpm_writer(P_SERIAL_OUT);
	//release_tpm_writer(P_STORAGE);
	//release_tpm_writer(P_KEYBOARD);

	connect_to_pmu();
	printf("%s [2]\n", __func__);

	//initialize_shell();
	printf("%s [3]\n", __func__);
	uint32_t partition_size = initialize_storage();
	printf("%s [4]\n", __func__);
#ifdef ARCH_UMODE
	initialize_file_system(partition_size);
#endif
	printf("%s [5]\n", __func__);
	help_boot_other_procs();

	initialize_shell();

	initialize_scheduler();
	printf("%s [6]\n", __func__);

	while (1) {
		distribute_input();
	}

	close_os_mailbox();

	return 0;
}
