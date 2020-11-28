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
#ifndef ARCH_SEC_HW
#include <arch/pmu.h>
#endif
#include <arch/defines.h>

static void distribute_input(void)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t queue_id;

	memset(input_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	/* FIXME: we should use separate threads for these two */
	recv_input(input_buf, &queue_id);
		_SEC_HW_ERROR("queue_id %d %02x", queue_id, queue_id);
	if (queue_id == Q_KEYBOARD) {
		shell_process_input((char) input_buf[0]);
	} else if (queue_id == Q_OS1) {
		process_system_call(input_buf, P_RUNTIME1);
	} else if (queue_id == Q_OS2) {
		process_system_call(input_buf, P_RUNTIME2);
	} else if (queue_id == Q_OSU) {
		_SEC_HW_ERROR("OSU INTR RECEIVED");
		process_system_call(input_buf, P_UNTRUSTED);
#ifdef ARCH_SEC_HW
	} else if (queue_id == 0) {
#endif
	} else {
		printf("Error (%s): invalid queue_id (%d)\n", __func__, queue_id);
		exit(-1);
	}
}

int main()
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: OS init\n", __func__);

	int ret = init_os_mailbox();
	if (ret)
		return ret;

#ifndef ARCH_SEC_HW
	release_tpm_writer(P_SERIAL_OUT);
	release_tpm_writer(P_STORAGE);
	release_tpm_writer(P_KEYBOARD);

	connect_to_pmu();
#endif

	initialize_shell();
	initialize_storage();
#ifdef ARCH_UMODE
	initialize_file_system();
#endif

	initialize_scheduler();

	while (1) {
		distribute_input();
	}

	close_os_mailbox();

	return 0;
}
