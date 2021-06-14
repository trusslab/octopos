/* OctopOS umode PMU */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <termios.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <octopos/mailbox.h>
#include <octopos/error.h>
#include <tpm/tpm.h>
#include <tpm/queue.h>
#include <arch/pmu.h>

int fd_pmu_to_os, fd_pmu_from_os, fd_pmu_to_mailbox, fd_pmu_from_mailbox;

int fd_mailbox_log, fd_tpm_log, fd_os_log, fd_keyboard_log,
    fd_serial_out_log, fd_runtime1_log, fd_runtime2_log, fd_storage_log,
    fd_network_log, fd_bluetooth_log, fd_untrusted_log, fd_pmu_log,
    fd_app_servers_log;

int fd_keyboard, fd_serial_out, fd_untrusted_in;

pid_t mailbox_pid, tpm_server_pid, tpm2_abrmd_pid, os_pid,
      keyboard_pid, serial_out_pid, runtime1_pid, runtime2_pid, storage_pid,
      network_pid, bluetooth_pid, untrusted_pid, socket_server_pid,
      attest_server_pid, bank_server_pid, health_server_pid;

struct termios orig;

int do_restart = 1;
int do_reset_queues = 1;
int num_running_procs = 0;
sem_t reset_done[NUM_PROCESSORS + 2];

int mailbox_ready = 0;

int os_first_boot = 1, keyboard_first_boot = 1, serial_out_first_boot = 1,
    runtime1_first_boot = 1, runtime2_first_boot = 1, storage_first_boot = 1,
    network_first_boot = 1, bluetooth_first_boot = 1, untrusted_first_boot = 1;

static int mailbox_simple_cmd(uint8_t cmd)
{
	uint8_t buf[PMU_MAILBOX_BUF_SIZE];
	uint32_t ret;
	int len;

	if (!mailbox_ready)
		return 0;

	buf[0] = cmd;

	write(fd_pmu_to_mailbox, buf, PMU_MAILBOX_BUF_SIZE);
	len = read(fd_pmu_from_mailbox, &ret, 4);

	if (len != 4)
		return ERR_FAULT;

	return (int) ret;
}

static int mailbox_cmd_arg(uint8_t cmd, uint8_t arg)
{
	uint8_t buf[PMU_MAILBOX_BUF_SIZE];
	uint32_t ret;
	int len;

	if (!mailbox_ready)
		return 0;

	buf[0] = cmd;
	buf[1] = arg;

	write(fd_pmu_to_mailbox, buf, PMU_MAILBOX_BUF_SIZE);
	len = read(fd_pmu_from_mailbox, &ret, 4);

	if (len != 4)
		return ERR_FAULT;

	return (int) ret;
}

static int mailbox_pause_delegation(void)
{
	return mailbox_simple_cmd(PMU_MAILBOX_CMD_PAUSE_DELEGATION);
}

static int mailbox_resume_delegation(void)
{
	return mailbox_simple_cmd(PMU_MAILBOX_CMD_RESUME_DELEGATION);
}

/* Returns 0 if termination allowed */
static int mailbox_terminate_check(void)
{
	return mailbox_simple_cmd(PMU_MAILBOX_CMD_TERMINATE_CHECK);
}

static int mailbox_reset_queue(uint8_t queue_id)
{
	return mailbox_cmd_arg(PMU_MAILBOX_CMD_RESET_QUEUE, queue_id);
}

/* Returns 0 if processor reset allowed */
static int mailbox_proc_reset_check(uint8_t proc_id)
{
	return mailbox_cmd_arg(PMU_MAILBOX_CMD_RESET_PROC_CHECK, proc_id);
}


static int start_proc(char *path, char *const args[], int fd_log,
		      int is_input, int is_output, int is_untrusted)
{
	int pipe_fds[2];

	if (is_input || is_output || is_untrusted)
		pipe(pipe_fds);

	pid_t pid = fork();
	if (pid < 0) {
		printf("%s: Error: failed to fork.\n", __func__);
		return pid;
	}

	if (pid) {
		if (is_input) {
			close(pipe_fds[0]);
			fd_keyboard = pipe_fds[1];
		} else if (is_output) {
			close(pipe_fds[1]);
			fd_serial_out = pipe_fds[0];
		} else if (is_untrusted) {
			close(pipe_fds[0]);
			fd_untrusted_in = pipe_fds[1];
		}
	
		num_running_procs++;

		return pid;
	} else {
		if (is_input) {
			close(pipe_fds[1]);
			dup2(pipe_fds[0], 0);
			dup2(fd_log, 2);
		} else if (is_output) {
			close(pipe_fds[0]);
			dup2(pipe_fds[1], 2);
		} else if (is_untrusted) {
			dup2(pipe_fds[0], 0);
			dup2(fd_log, 2);
		} else {
			dup2(fd_log, 2);
		}

		dup2(fd_log, 1);
		execv(path, args);
		exit(0);
		return 0;
	}
}

static int start_mailbox_proc(void)
{
	int ret;
	char *const args[] = {(char *) "mailbox", NULL};
	char path[] = "./arch/umode/mailbox/mailbox";

	ret = start_proc(path, args, fd_mailbox_log, 0, 0, 0);
	mailbox_ready = 1;

	return ret;
}

static int start_tpm_server_proc(void)
{
	int ret;
	char *const args[] = {(char *) "tpm_server", NULL};
	char path[] = "./external/ibmtpm/tpm_server";
	
	ret = start_proc(path, args, fd_tpm_log, 0, 0, 0);

	return ret;
}

static int start_tpm2_abrmd_proc(void)
{
	int ret;
	/* FIXME: run as tss user (sudo -u tss ...) and remove --allow-root.
	 * see docs/tpm.rst */
	char *const args[] = {(char *) "tpm2-abrmd", (char *) "--tcti=mssim",
			      (char *) "--allow-root", NULL};
	char path[] = "/usr/local/sbin/tpm2-abrmd";
	
	ret = start_proc(path, args, fd_tpm_log, 0, 0, 0);

	return ret;
}

static int start_os_proc(void)
{
	char *const args[] = {(char *) "bootloader_os", (char *) "os", NULL};
	char path[] = "./bootloader/bootloader_os";

	if (!os_first_boot) {
		uint32_t pcr_list[] = {(uint32_t) PROC_TO_PCR(P_OS)};
		tpm_reset_pcrs(pcr_list, 1);
	}

	os_first_boot = 0;

	return start_proc(path, args, fd_os_log, 0, 0, 0);
}

static int start_keyboard_proc(void)
{
	char *const args[] = {(char *) "bootloader_other", (char *) "keyboard",
			      NULL};
	char path[] = "./bootloader/bootloader_other";

	if (!keyboard_first_boot) {
		uint32_t pcr_list[] = {(uint32_t) PROC_TO_PCR(P_KEYBOARD)};
		tpm_reset_pcrs(pcr_list, 1);
	}

	keyboard_first_boot = 0;

	return start_proc(path, args, fd_keyboard_log, 1, 0, 0);
}

static int start_serial_out_proc(void)
{
	char *const args[] = {(char *) "bootloader_other", (char *) "serial_out",
			      NULL};
	char path[] = "./bootloader/bootloader_other";

	if (!serial_out_first_boot) {
		uint32_t pcr_list[] = {(uint32_t) PROC_TO_PCR(P_SERIAL_OUT)};
		tpm_reset_pcrs(pcr_list, 1);
	}

	serial_out_first_boot = 0;

	return start_proc(path, args, fd_serial_out_log, 0, 1, 0);
}

static int start_runtime_proc(char *runtime_id)
{
	int fd_log;
	char *const args[] = {(char *) "bootloader", (char *) "runtime",
			      runtime_id, NULL};
	char path[] = "./bootloader/bootloader_other";
	uint32_t pcr_list[1];

	if (*runtime_id == '1') {
		fd_log = fd_runtime1_log;
		if (!runtime1_first_boot) {
			pcr_list[0] =  (uint32_t) PROC_TO_PCR(P_RUNTIME1);
			tpm_reset_pcrs(pcr_list, 1);
		}

		runtime1_first_boot = 0;
	} else if (*runtime_id == '2') {
		fd_log = fd_runtime2_log;
		if (!runtime2_first_boot) {
			pcr_list[0] =  (uint32_t) PROC_TO_PCR(P_RUNTIME2);
			tpm_reset_pcrs(pcr_list, 1);
		}

		runtime2_first_boot = 0;
	} else {
		printf("Error: %s: invalid runtime ID (%c)\n", __func__,
		       *runtime_id);
		return ERR_INVALID;
	}

	return start_proc(path, args, fd_log, 0, 0, 0);
}

static int start_storage_proc(void)
{
	char *const args[] = {(char *) "bootloader_storage", (char *) "storage",
			      NULL};
	char path[] = "./bootloader/bootloader_storage";

	if (!storage_first_boot) {
		uint32_t pcr_list[] = {(uint32_t) PROC_TO_PCR(P_STORAGE)};
		tpm_reset_pcrs(pcr_list, 1);
	}

	storage_first_boot = 0;

	return start_proc(path, args, fd_storage_log, 0, 0, 0);
}

static int start_network_proc(void)
{
	char *const args[] = {(char *) "bootloader_other", (char *) "network",
			      NULL};
	char path[] = "./bootloader/bootloader_other";

	if (!network_first_boot) {
		uint32_t pcr_list[] = {(uint32_t) PROC_TO_PCR(P_NETWORK)};
		tpm_reset_pcrs(pcr_list, 1);
	}

	network_first_boot = 0;

	return start_proc(path, args, fd_network_log, 0, 0, 0);
}

static int start_bluetooth_proc(void)
{
	char *const args[] = {(char *) "bootloader_other", (char *) "bluetooth",
			      NULL};
	char path[] = "./bootloader/bootloader_other";

	if (!bluetooth_first_boot) {
		uint32_t pcr_list[] = {(uint32_t) PROC_TO_PCR(P_BLUETOOTH)};
		tpm_reset_pcrs(pcr_list, 1);
	}

	bluetooth_first_boot = 0;

	return start_proc(path, args, fd_bluetooth_log, 0, 0, 0);
}

static int start_untrusted_proc(void)
{
	char *const args[] = {(char *) "bootloader_other", (char *) "linux",
		(char *) "root=/dev/octopos_blk",
		(char *) "mem=128M", NULL};
	char path[] = "./bootloader/bootloader_other";

	if (!untrusted_first_boot) {
		uint32_t pcr_list[] = {(uint32_t) PROC_TO_PCR(P_UNTRUSTED)};
		tpm_reset_pcrs(pcr_list, 1);
	}

	untrusted_first_boot = 0;

	return start_proc(path, args, fd_untrusted_log, 0, 0, 1);
}

static int start_socket_server_proc(void)
{
	char *const args[] = {(char *) "socket_server", NULL};
	char path[] = "./applications/socket_client/socket_server";
	return start_proc(path, args, fd_app_servers_log, 0, 0, 0);
}

static int start_attest_server_proc(void)
{
	char *const args[] = {(char *) "attest_server", NULL};
	char path[] = "./applications/attest_client/attest_server";
	return start_proc(path, args, fd_app_servers_log, 0, 0, 0);
}

static int start_bank_server_proc(void)
{
	char *const args[] = {(char *) "bank_server", NULL};
	char path[] = "./applications/bank_client/bank_server";
	return start_proc(path, args, fd_app_servers_log, 0, 0, 0);
}

static int start_health_server_proc(void)
{
	char *const args[] = {(char *) "health_server", NULL};
	char path[] = "./applications/health_client/health_server";
	return start_proc(path, args, fd_app_servers_log, 0, 0, 0);
}

static void start_all_procs(void)
{
	mailbox_pid = start_mailbox_proc();
	tpm_server_pid = start_tpm_server_proc();
	tpm2_abrmd_pid = start_tpm2_abrmd_proc();
	os_pid = start_os_proc();
	keyboard_pid = start_keyboard_proc();
	serial_out_pid = start_serial_out_proc();
	runtime1_pid = start_runtime_proc((char *) "1");
	runtime2_pid = start_runtime_proc((char *) "2");
	storage_pid = start_storage_proc();
	network_pid = start_network_proc();
	bluetooth_pid = start_bluetooth_proc();
	untrusted_pid = start_untrusted_proc();
	/* These servers are not part of OctopOS.
	 * We start them here since they're useful for testing.
	 */
	socket_server_pid = start_socket_server_proc();
	attest_server_pid = start_attest_server_proc();
	bank_server_pid = start_bank_server_proc();
	health_server_pid = start_health_server_proc();
}

static void halt_proc(uint8_t proc_id)
{
	switch (proc_id) {
	case P_KEYBOARD:
		kill(keyboard_pid, SIGKILL);
		break;

	case P_SERIAL_OUT:
		kill(serial_out_pid, SIGKILL);
		break;

	case P_STORAGE:
		kill(storage_pid, SIGKILL);
		break;

	case P_NETWORK:
		kill(network_pid, SIGKILL);
		break;

	case P_BLUETOOTH:
		kill(bluetooth_pid, SIGKILL);
		break;

	case P_RUNTIME1:
		kill(runtime1_pid, SIGKILL);
		break;

	case P_RUNTIME2:
		kill(runtime2_pid, SIGKILL);
		break;

	case P_OS:
		kill(os_pid, SIGKILL);
		break;

	case P_UNTRUSTED: {
		/* Halt the untrusted domain.
		 * We send the halt cmd to it in case it wasn't listening
		 * on the mailbox for the cmd sent from the OS.
		 */
		char cmd1[] = "root\n";
		char cmd2[] = "halt\n";
		write(fd_untrusted_in, cmd1, sizeof(cmd1));
		sleep(1);
		write(fd_untrusted_in, cmd2, sizeof(cmd2));
		break;
		}

	default:
		printf("Error: %s: invalid processor ID (%d)\n", __func__, proc_id);
		break;
	}
}

/*
 * Halts all procs other than the untrusted one.
 */
static void halt_all_procs(void)
{
	mailbox_ready = 0;

	/* Shut down the rest */
	kill(health_server_pid, SIGKILL);
	kill(bank_server_pid, SIGKILL);
	kill(attest_server_pid, SIGKILL);
	kill(socket_server_pid, SIGKILL);

	halt_proc(P_BLUETOOTH);

	halt_proc(P_NETWORK);
	
	halt_proc(P_STORAGE);
	
	halt_proc(P_RUNTIME2);
	
	halt_proc(P_RUNTIME1);
	
	halt_proc(P_SERIAL_OUT);
	
	halt_proc(P_KEYBOARD);
	
	halt_proc(P_OS);
	
	kill(tpm2_abrmd_pid, SIGKILL);
	kill(tpm_server_pid, SIGKILL);

	kill(mailbox_pid, SIGKILL);
}

static void *proc_reboot_handler(void *data)
{
	char proc_name[64];
	int wstatus, ret = 0;
	int reboot_exception = 0;

	while (do_restart || do_reset_queues || num_running_procs) {
		pid_t pid = wait(&wstatus);
		if (!(wstatus == 0 || wstatus == 9))
			continue;
		num_running_procs--;
		if (pid == mailbox_pid) {
			sprintf(proc_name, "Mailbox");
			reboot_exception = 1;
			sem_post(&reset_done[0]);
		} else if (pid == tpm_server_pid) {
			sprintf(proc_name, "TPM_server");
			reboot_exception = 1;
			sem_post(&reset_done[NUM_PROCESSORS + 1]);
		} else if (pid == tpm2_abrmd_pid) {
			sprintf(proc_name, "TPM_abrmd");
			reboot_exception = 1;
			sem_post(&reset_done[NUM_PROCESSORS + 1]);
		} else if (pid == os_pid) {
			sprintf(proc_name, "OS processor");
			if (do_reset_queues) {
				ret = mailbox_reset_queue(Q_OS1);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_OS1\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_OS2);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_OS2\n", __func__);
					goto print;
				}

				mailbox_reset_queue(Q_OSU);
			}

			if (do_restart)
				os_pid = start_os_proc();

			sem_post(&reset_done[P_OS]);
		} else if (pid == keyboard_pid) {
			sprintf(proc_name, "Keyboard processor");
			if (do_reset_queues) {
				ret = mailbox_reset_queue(Q_KEYBOARD);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_KEYBOARD\n", __func__);
					goto print;
				}
			}

			if (do_restart)
				keyboard_pid = start_keyboard_proc();

			sem_post(&reset_done[P_KEYBOARD]);
		} else if (pid == serial_out_pid) {
			sprintf(proc_name, "Serial Out processor");
			if (do_reset_queues) {
				ret = mailbox_reset_queue(Q_SERIAL_OUT);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_SERIAL_OUT\n", __func__);
					goto print;
				}
			}

			if (do_restart)
				serial_out_pid = start_serial_out_proc();

			sem_post(&reset_done[P_SERIAL_OUT]);
		} else if (pid == runtime1_pid) {
			sprintf(proc_name, "Runtime1 processor");
			if (do_reset_queues) {
				ret = mailbox_reset_queue(Q_RUNTIME1);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_RUNTIME1\n", __func__);
					goto print;
				}
			}

			if (do_restart)
				runtime1_pid = start_runtime_proc((char *) "1");

			sem_post(&reset_done[P_RUNTIME1]);
		} else if (pid == runtime2_pid) {
			sprintf(proc_name, "Runtime2 processor");
			if (do_reset_queues) {
				ret = mailbox_reset_queue(Q_RUNTIME2);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_RUNTIME2\n", __func__);
					goto print;
				}
			}

			if (do_restart)
				runtime2_pid = start_runtime_proc((char *) "2");

			sem_post(&reset_done[P_RUNTIME2]);
		} else if (pid == storage_pid) {
			sprintf(proc_name, "Storage processor");
			if (do_reset_queues) {
				ret = mailbox_reset_queue(Q_STORAGE_DATA_IN);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_STORAGE_DATA_IN\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_STORAGE_DATA_OUT);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_STORAGE_DATA_OUT\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_STORAGE_CMD_IN);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_STORAGE_CMD_IN\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_STORAGE_CMD_OUT);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_STORAGE_CMD_OUT\n", __func__);
					goto print;
				}
			}

			if (do_restart)
				storage_pid = start_storage_proc();

			sem_post(&reset_done[P_STORAGE]);
		} else if (pid == network_pid) {
			sprintf(proc_name, "Network processor");
			if (do_reset_queues) {
				ret = mailbox_reset_queue(Q_NETWORK_DATA_IN);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_NETWORK_DATA_IN\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_NETWORK_DATA_OUT);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_NETWORK_DATA_OUT\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_NETWORK_CMD_IN);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_NETWORK_CMD_IN\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_NETWORK_CMD_OUT);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_NETWORK_CMD_OUT\n", __func__);
					goto print;
				}
			}

			if (do_restart)
				network_pid = start_network_proc();

			sem_post(&reset_done[P_NETWORK]);
		} else if (pid == bluetooth_pid) {
			sprintf(proc_name, "Bluetooth processor");
			if (do_reset_queues) {
				ret = mailbox_reset_queue(Q_BLUETOOTH_DATA_IN);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_BLUETOOTH_DATA_IN\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_BLUETOOTH_DATA_OUT);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_BLUETOOTH_DATA_OUT\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_BLUETOOTH_CMD_IN);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_BLUETOOTH_CMD_IN\n", __func__);
					goto print;
				}

				ret = mailbox_reset_queue(Q_BLUETOOTH_CMD_OUT);
				if (ret) {
					printf("Error: %s: couldn't reset "
					       "Q_BLUETOOTH_CMD_OUT\n", __func__);
					goto print;
				}
			}

			if (do_restart)
				bluetooth_pid = start_bluetooth_proc();

			sem_post(&reset_done[P_BLUETOOTH]);
		} else if (pid == untrusted_pid) {
			sprintf(proc_name, "Untrusted processor");
			if (do_reset_queues)
				mailbox_reset_queue(Q_UNTRUSTED);

			if (do_restart)
				untrusted_pid = start_untrusted_proc();

			sem_post(&reset_done[P_UNTRUSTED]);
		} else if (pid == socket_server_pid) {
			sprintf(proc_name, "Socket Server");
			if (do_restart)
				socket_server_pid = start_socket_server_proc();
		} else if (pid == attest_server_pid) {
			sprintf(proc_name, "Attestation Server");
			if (do_restart)
				attest_server_pid = start_attest_server_proc();
		} else if (pid == bank_server_pid) {
			sprintf(proc_name, "Bank Server");
			if (do_restart)
				bank_server_pid = start_bank_server_proc();
		} else if (pid == health_server_pid) {
			sprintf(proc_name, "Health Server");
			if (do_restart)
				health_server_pid = start_health_server_proc();
		} else {
			printf("Error: %s: unknown pid (%d)\n", __func__, pid);
			continue;
		}

print:
		printf("%s terminated (%d)%s%s%s\n", proc_name, wstatus,
		       (do_restart && !reboot_exception) ? " and restarted" : "",
		       do_reset_queues && !reboot_exception ?
		       " -- queues reset" : "",
		       do_reset_queues && ret && !reboot_exception ?
		       ", but unsuccessfully" : "");
	}
	
	return NULL;
}

int main(int argc, char **argv)
{
	fd_set r_fds;
	char buffer[1024];
	int ret, len, i;
	int untrusted_init = 0;
	pthread_t reboot_thread;
	sem_t *sem;

	/*
	 * put tty in raw mode.
	 * see here:
	 * https://www.unix.com/programming/3690-how-programm-tty-devices-under-unix-platform.html#post12226
	 */
        struct termios now;
        setvbuf(stdout, NULL, _IONBF, 0);

	tcgetattr(0, &orig);
        now=orig;
        now.c_lflag &= ~(ISIG|ICANON|ECHO);
        now.c_cc[VMIN]=1;
        now.c_cc[VTIME]=2;
        tcsetattr(0, TCSANOW, &now);
	
	sem_unlink("/tpm_sem");
	sem = sem_open("/tpm_sem", O_CREAT | O_EXCL, 0644, 1);
	if (sem == SEM_FAILED) {
		printf("Error: couldn't create tpm semaphore.\n");
		exit(-1);
	}

	enforce_running_process(P_PMU);

	mkfifo(FIFO_PMU_TO_OS, 0666);
	mkfifo(FIFO_PMU_FROM_OS, 0666);
	mkfifo(FIFO_PMU_TO_MAILBOX, 0666);
	mkfifo(FIFO_PMU_FROM_MAILBOX, 0666);

	mkfifo(FIFO_MAILBOX_LOG, 0666);
	mkfifo(FIFO_TPM_LOG, 0666);
	mkfifo(FIFO_OS_LOG, 0666);
	mkfifo(FIFO_KEYBOARD_LOG, 0666);
	mkfifo(FIFO_SERIAL_OUT_LOG, 0666);
	mkfifo(FIFO_RUNTIME1_LOG, 0666);
	mkfifo(FIFO_RUNTIME2_LOG, 0666);
	mkfifo(FIFO_STORAGE_LOG, 0666);
	mkfifo(FIFO_NETWORK_LOG, 0666);
	mkfifo(FIFO_BLUETOOTH_LOG, 0666);
	mkfifo(FIFO_UNTRUSTED_LOG, 0666);
	mkfifo(FIFO_PMU_LOG, 0666);
	mkfifo(FIFO_APP_SERVERS_LOG, 0666);

	fd_pmu_to_os = open(FIFO_PMU_TO_OS, O_RDWR);
	fd_pmu_from_os = open(FIFO_PMU_FROM_OS, O_RDWR);
	fd_pmu_to_mailbox = open(FIFO_PMU_TO_MAILBOX, O_RDWR);
	fd_pmu_from_mailbox = open(FIFO_PMU_FROM_MAILBOX, O_RDWR);

	fd_mailbox_log = open(FIFO_MAILBOX_LOG, O_RDWR);
	fd_tpm_log = open(FIFO_TPM_LOG, O_RDWR);
	fd_os_log = open(FIFO_OS_LOG, O_RDWR);
	fd_keyboard_log = open(FIFO_KEYBOARD_LOG, O_RDWR);
	fd_serial_out_log = open(FIFO_SERIAL_OUT_LOG, O_RDWR);
	fd_runtime1_log = open(FIFO_RUNTIME1_LOG, O_RDWR);
	fd_runtime2_log = open(FIFO_RUNTIME2_LOG, O_RDWR);
	fd_storage_log = open(FIFO_STORAGE_LOG, O_RDWR);
	fd_network_log = open(FIFO_NETWORK_LOG, O_RDWR);
	fd_bluetooth_log = open(FIFO_BLUETOOTH_LOG, O_RDWR);
	fd_untrusted_log = open(FIFO_UNTRUSTED_LOG, O_RDWR);
	fd_pmu_log = open(FIFO_PMU_LOG, O_RDWR);
	fd_app_servers_log = open(FIFO_APP_SERVERS_LOG, O_RDWR);

	dup2(fd_pmu_log, 1);
	printf("%s: PMU init\n", __func__);

	for (i = 0; i < NUM_PROCESSORS + 1; i++)
		sem_init(&reset_done[i], 0, 0);

	ret = pthread_create(&reboot_thread, NULL, proc_reboot_handler, NULL);
	if (ret) {
		printf("Error: couldn't launch the reboot thread\n");
		goto err_close;
	}

	start_all_procs();
	sem_close(sem);

	while (1) {
		int max_fd;
		FD_ZERO(&r_fds);
		FD_SET(fd_serial_out, &r_fds); 
		FD_SET(0, &r_fds); 
		FD_SET(fd_pmu_from_os, &r_fds); 
		max_fd = fd_serial_out;
		if (fd_pmu_from_os > max_fd)
			max_fd = fd_pmu_from_os;
		select(max_fd + 1, &r_fds, NULL, NULL, NULL);

		if (FD_ISSET(fd_serial_out, &r_fds)) {
			len = read(fd_serial_out, buffer, sizeof(buffer));
			write(2, buffer, len);
		}
		
		if (FD_ISSET(0, &r_fds)) {
			len = read(0, buffer, sizeof(buffer));
			if (!untrusted_init && len == 1 && buffer[0] == '@') {
				untrusted_init = 1;
				char cmd1[] = "root\n";
				char cmd2[] = "ip link set octopos_net up\n";
				char cmd3[] = "ip addr add 10.0.0.1/24 dev octopos_net\n";
				char cmd4[] = "while true; do source /dev/octopos_mailbox | xargs echo \"@\" > /dev/octopos_mailbox; done\n";
				write(fd_untrusted_in, cmd1, sizeof(cmd1));
				sleep(1);
				write(fd_untrusted_in, cmd2, sizeof(cmd2));
				write(fd_untrusted_in, cmd3, sizeof(cmd3));
				write(fd_untrusted_in, cmd4, sizeof(cmd4));
			}
			write(fd_keyboard, buffer, len);
		}
		
		if (FD_ISSET(fd_pmu_from_os, &r_fds)) {
			uint8_t pmu_os_buf[PMU_OS_BUF_SIZE];
			len = read(fd_pmu_from_os, pmu_os_buf, PMU_OS_BUF_SIZE);
			if (len != PMU_OS_BUF_SIZE) {
				printf("Error: %s: invalid command size from the OS (%d)\n",
				       __func__, len);
				continue;
			}

			if (pmu_os_buf[0] == PMU_OS_CMD_SHUTDOWN) {
				printf("%s: shutting down\n", __func__);
				uint32_t cmd_ret = 0;
				ret = mailbox_terminate_check();
				if (!ret) {
					/* allowed */
					/* There are two terminate checks. The first one
					 * is mainly to inform the OS. Here, we need to
					 * send the response back to the OS before we
					 * reboot since the OS needs to help the
					 * untrusted proc to properly halt. Therefore, we
					 * do the first check to inform the OS.
					 * If the check is successful, we then do a second check.
					 * The second check is protected by pausing of all delegations,
					 * therefore, it's safe to shut down if the check passes.
					 *
					 * The side effect of this approach is that we might tell the OS
					 * that we can shut down but later realize that we can't.
					 * That's not a security problem and indeed it's the job of the OS
					 * to not perform any more delegations after our response.
					 * If it does, then the shutdown will fail.
					 */
					write(fd_pmu_to_os, &cmd_ret, 4);

					do_restart = 0;
					do_reset_queues = 0;
					/* Halt the untrusted domain before we disable delegations
					 * since it will need access to the storage service.
					 */
					halt_proc(P_UNTRUSTED);	
					/* Give the untrusted domain time to properly terminate first. */
					sleep(10);

					mailbox_pause_delegation();
					ret = mailbox_terminate_check();
					if (!ret) {
						/* allowed */
						halt_all_procs();
						goto err_join;
					} else {
						/* not allowed */
						printf("Error: %s: shutdown not allowed (second check)\n", __func__);
						do_restart = 1;
						do_reset_queues = 1;
						mailbox_resume_delegation();
					}
				} else {
					/* not allowed */
					printf("Error: %s: shutdown not allowed (first check)\n", __func__);
					cmd_ret = (uint32_t) ERR_PERMISSION;
					write(fd_pmu_to_os, &cmd_ret, 4);
				}
			} else if (pmu_os_buf[0] == PMU_OS_CMD_REBOOT) {
				printf("%s: rebooting\n", __func__);
				uint32_t cmd_ret = 0;
				ret = mailbox_terminate_check();
				if (!ret) {
					/* allowed */
					/* There are two terminate checks. The first one
					 * is mainly to inform the OS. Here, we need to
					 * send the response back to the OS before we
					 * reboot since the OS needs to help the
					 * untrusted proc to properly halt. Therefore, we
					 * do the first check to inform the OS.
					 * If the check is successful, we then do a second check.
					 * The second check is protected by pausing of all delegations,
					 * therefore, it's safe to reboot if the check passes.
					 *
					 * The side effect of this approach is that we might tell the OS
					 * that we can reboot but later realize that we can't.
					 * That's not a security problem and indeed it's the job of the OS
					 * to not perform any more delegations after our response.
					 * If it does, then the reboot will fail.
					 */
					write(fd_pmu_to_os, &cmd_ret, 4);

					do_restart = 0;
					/* Halt the untrusted domain before we disable delegations
					 * since it will need access to the storage service.
					 */
					halt_proc(P_UNTRUSTED);	
					/* Give the untrusted domain time to properly terminate first. */
					sleep(10);

					mailbox_pause_delegation();
					ret = mailbox_terminate_check();
					if (!ret) {
						/* allowed */
						halt_all_procs();
						/* We've used the first sem in the array for the mailbox. */
						sem_wait(&reset_done[0]);
						sem_wait(&reset_done[NUM_PROCESSORS + 1]);
						sem_wait(&reset_done[NUM_PROCESSORS + 1]);
						sem_wait(&reset_done[P_OS]);
						sem_wait(&reset_done[P_KEYBOARD]);
						sem_wait(&reset_done[P_SERIAL_OUT]);
						sem_wait(&reset_done[P_STORAGE]);
						sem_wait(&reset_done[P_NETWORK]);
						sem_wait(&reset_done[P_BLUETOOTH]);
						sem_wait(&reset_done[P_RUNTIME1]);
						sem_wait(&reset_done[P_RUNTIME2]);
						sem_wait(&reset_done[P_UNTRUSTED]);

						do_restart = 1;
						start_all_procs();
					} else {
						/* not allowed */
						printf("Error: %s: reboot not allowed (second check)\n", __func__);
						do_restart = 1;
						mailbox_resume_delegation();
					}
				} 
				else {
					/* not allowed */
					printf("Error: %s: reboot not allowed (first check)\n", __func__);
					cmd_ret = (uint32_t) ERR_PERMISSION;
					write(fd_pmu_to_os, &cmd_ret, 4);
				}
			} else if (pmu_os_buf[0] == PMU_OS_CMD_RESET_PROC) {
				uint32_t cmd_ret = 0;
				uint8_t proc_id = pmu_os_buf[1];
				if (proc_id == P_UNTRUSTED ||
				    proc_id == P_OS) {
					/* We send the response back to the OS before we
					 * reset the proc since the OS needs to help the
					 * untrusted proc to properly halt.
					 */
					write(fd_pmu_to_os, &cmd_ret, 4);
					halt_proc(proc_id);
				} else if (proc_id == P_KEYBOARD ||
					   proc_id == P_SERIAL_OUT ||
					   proc_id == P_STORAGE ||
					   proc_id == P_NETWORK ||
					   proc_id == P_BLUETOOTH ||
					   proc_id == P_RUNTIME1 ||
					   proc_id == P_RUNTIME2) {
					mailbox_pause_delegation();
					ret = mailbox_proc_reset_check(proc_id);
					if (!ret) {
						/* allowed */
						halt_proc(proc_id);
						sem_wait(&reset_done[proc_id]);
					} else {
						/* not allowed */
						cmd_ret = (uint32_t) ERR_PERMISSION;
					}
					mailbox_resume_delegation();
					write(fd_pmu_to_os, &cmd_ret, 4);
				} else {
					printf("Error: %s: invalid processor ID (%d)\n",
					       __func__, proc_id);
					cmd_ret = (uint32_t) ERR_INVALID;
					write(fd_pmu_to_os, &cmd_ret, 4);
				}
			} else {
				printf("Error: %s: invalid command from the OS (%d)\n",
				       __func__, pmu_os_buf[0]);
			}
		}
	}

err_join:
	pthread_join(reboot_thread, NULL);

err_close:

	/* No more pmu logs after this. */
	close(fd_pmu_log);
	close(fd_app_servers_log);
	close(fd_untrusted_log);
	close(fd_bluetooth_log);
	close(fd_network_log);
	close(fd_storage_log);
	close(fd_runtime1_log);
	close(fd_runtime2_log);
	close(fd_serial_out_log);
	close(fd_keyboard_log);
	close(fd_os_log);
	close(fd_tpm_log);
	close(fd_mailbox_log);

	close(fd_pmu_from_mailbox);
	close(fd_pmu_to_mailbox);
	close(fd_pmu_from_os);
	close(fd_pmu_to_os);
	
	remove(FIFO_APP_SERVERS_LOG);
	remove(FIFO_PMU_LOG);
	remove(FIFO_UNTRUSTED_LOG);
	remove(FIFO_BLUETOOTH_LOG);
	remove(FIFO_NETWORK_LOG);
	remove(FIFO_STORAGE_LOG);
	remove(FIFO_RUNTIME1_LOG);
	remove(FIFO_RUNTIME2_LOG);
	remove(FIFO_SERIAL_OUT_LOG);
	remove(FIFO_KEYBOARD_LOG);
	remove(FIFO_OS_LOG);
	remove(FIFO_TPM_LOG);
	remove(FIFO_MAILBOX_LOG);
	
	remove(FIFO_PMU_FROM_MAILBOX);
	remove(FIFO_PMU_TO_MAILBOX);
	remove(FIFO_PMU_FROM_OS);
	remove(FIFO_PMU_TO_OS);

	tcsetattr(0, TCSANOW, &orig);

	return 0;
}
