#ifndef _ARCH_PMU_H_
#define _ARCH_PMU_H_

/* FIXME: some of the content is used by PMU and some by OS.
 * Use separate header files.
 */

#define FIFO_PMU_TO_OS		"/tmp/octopos_pmu_to_os"
#define FIFO_PMU_FROM_OS	"/tmp/octopos_pmu_from_os"
#define PMU_OS_BUF_SIZE		2
#define PMU_OS_CMD_SHUTDOWN	1
#define PMU_OS_CMD_REBOOT	2
#define PMU_OS_CMD_RESET_PROC	3

#define FIFO_PMU_TO_MAILBOX	"/tmp/octopos_pmu_to_mailbox"
#define FIFO_PMU_FROM_MAILBOX	"/tmp/octopos_pmu_from_mailbox"
#define PMU_MAILBOX_BUF_SIZE			2
#define PMU_MAILBOX_CMD_PAUSE_DELEGATION	1
#define PMU_MAILBOX_CMD_RESUME_DELEGATION	2
#define PMU_MAILBOX_CMD_TERMINATE_CHECK		3
#define PMU_MAILBOX_CMD_RESET_QUEUE		4
#define PMU_MAILBOX_CMD_RESET_PROC_CHECK	5

#define FIFO_MAILBOX_LOG	"/tmp/octopos_mailbox_log"
#define FIFO_TPM_LOG		"/tmp/octopos_tpm_log"
#define FIFO_OS_LOG		"/tmp/octopos_os_log"
#define FIFO_KEYBOARD_LOG	"/tmp/octopos_keyboard_log"
#define FIFO_SERIAL_OUT_LOG	"/tmp/octopos_serial_out_log"
#define FIFO_RUNTIME1_LOG	"/tmp/octopos_runtime1_log"
#define FIFO_RUNTIME2_LOG	"/tmp/octopos_runtime2_log"
#define FIFO_STORAGE_LOG	"/tmp/octopos_storage_log"
#define FIFO_NETWORK_LOG	"/tmp/octopos_network_log"
#define FIFO_UNTRUSTED_LOG	"/tmp/octopos_untrusted_log"
#define FIFO_PMU_LOG		"/tmp/octopos_pmu_log"
#define FIFO_SOCKET_SERVER_LOG	"/tmp/octopos_socket_server_log"

int pmu_shutdown(void);
int pmu_reboot(void);
int pmu_reset_proc(uint8_t proc_id);
void connect_to_pmu(void);

#endif
