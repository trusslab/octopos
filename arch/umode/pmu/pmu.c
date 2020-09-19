/* OctopOS umode PMU */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <termios.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <octopos/error.h>
#include <arch/pmu.h>

int fd_pmu_to_os, fd_pmu_from_os, fd_pmu_to_mailbox, fd_pmu_from_mailbox;
int fd_mailbox_log, fd_os_log, fd_keyboard_log, fd_serial_out_log,
    fd_runtime1_log, fd_runtime2_log, fd_storage_log, fd_network_log,
    fd_untrusted_log, fd_pmu_log, fd_socket_server_log;
int fd_keyboard, fd_serial_out, fd_untrusted_in;

struct termios orig;

static int start_proc(char *path, char *const args[], int fd_log,
		      int is_input, int is_output, int is_storage, int is_untrusted)
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
			//fd_untrusted_out = pipe_fds[0];
			close(pipe_fds[0]);
			fd_untrusted_in = pipe_fds[1];
		}

		return pid;
	} else {
		if (is_input) {
			close(pipe_fds[1]);
			dup2(pipe_fds[0], 0);
		} else if (is_output) {
			close(pipe_fds[0]);
			dup2(pipe_fds[1], 2);
		} else if (is_storage) {
			chdir("./storage");
		} else if (is_untrusted) {
			dup2(fd_log, 2);
			//dup2(pipe_fds[1], 1);
			dup2(pipe_fds[0], 0);
		}

		dup2(fd_log, 1);
		execv(path, args);
		exit(0);
		return 0;
	}
}

static int start_mailbox_proc(void)
{
	char *const args[] = {(char *) "mailbox", NULL};
	char path[] = "./arch/umode/mailbox/mailbox";
	return start_proc(path, args, fd_mailbox_log, 0, 0, 0, 0);
}

static int start_os_proc(void)
{
	char *const args[] = {(char *) "os", NULL};
	char path[] = "./os/os";
	return start_proc(path, args, fd_os_log, 0, 0, 0, 0);
}

static int start_keyboard_proc(void)
{
	char *const args[] = {(char *) "keyboard", NULL};
	char path[] = "./keyboard/keyboard";
	return start_proc(path, args, fd_keyboard_log, 1, 0, 0, 0);
}

static int start_serial_out_proc(void)
{
	char *const args[] = {(char *) "serial_out", NULL};
	char path[] = "./serial_out/serial_out";
	return start_proc(path, args, fd_serial_out_log, 0, 1, 0, 0);
}

static int start_runtime_proc(char *runtime_id)
{
	int fd_log;
	char *const args[] = {(char *) "runtime", runtime_id, NULL};
	char path[] = "./runtime/runtime";
	
	if (*runtime_id == '1') {
		fd_log = fd_runtime1_log;
	} else if (*runtime_id == '2') {
		fd_log = fd_runtime2_log;
	} else {
		printf("Error: %s: invalid runtime ID (%c)\n", __func__, *runtime_id);
		return ERR_INVALID;
	}

	return start_proc(path, args, fd_log, 0, 0, 0, 0);
}

static int start_storage_proc(void)
{
	char *const args[] = {(char *) "storage", NULL};
	char path[] = "./storage";
	return start_proc(path, args, fd_storage_log, 0, 0, 1, 0);
}

static int start_network_proc(void)
{
	char *const args[] = {(char *) "network", NULL};
	char path[] = "./network/network";
	return start_proc(path, args, fd_network_log, 0, 0, 0, 0);
}

static int start_untrusted_proc(void)
{
	char *const args[] = {(char *) "linux",
		(char *) "ubda=./arch/umode/untrusted_linux/CentOS6.x-AMD64-root_fs",
		(char *) "mem=128M", NULL};
	char path[] = "./arch/umode/untrusted_linux/linux";
	return start_proc(path, args, fd_untrusted_log, 0, 0, 0, 1);
}

static int start_socket_server_proc(void)
{
	char *const args[] = {(char *) "socket_server", NULL};
	char path[] = "./applications/socket_client/socket_server";
	return start_proc(path, args, fd_socket_server_log, 0, 0, 0, 0);
}

static void sig_handler (int sig)
{
	printf("%s [1]\n", __func__);
}

int main(int argc, char **argv)
{
	pid_t mailbox_pid, os_pid, keyboard_pid, serial_out_pid,
	      runtime1_pid, runtime2_pid, storage_pid, network_pid,
	      untrusted_pid, socket_server_pid;
	fd_set r_fds;
	char buffer[1024];
	int len, status;
	int untrusted_init = 0;
	uint8_t pmu_os_buf[PMU_OS_BUF_SIZE];

	sigset_t emptyset, blockset;
	struct sigaction sa;

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
	
	mkfifo(FIFO_PMU_TO_OS, 0666);
	mkfifo(FIFO_PMU_FROM_OS, 0666);
	//mkfifo(FIFO_PMU_MAILBOX_OUT, 0666);
	//mkfifo(FIFO_PMU_MAILBOX_IN, 0666);

	mkfifo(FIFO_MAILBOX_LOG, 0666);
	mkfifo(FIFO_OS_LOG, 0666);
	mkfifo(FIFO_KEYBOARD_LOG, 0666);
	mkfifo(FIFO_SERIAL_OUT_LOG, 0666);
	mkfifo(FIFO_RUNTIME1_LOG, 0666);
	mkfifo(FIFO_RUNTIME2_LOG, 0666);
	mkfifo(FIFO_STORAGE_LOG, 0666);
	mkfifo(FIFO_NETWORK_LOG, 0666);
	mkfifo(FIFO_UNTRUSTED_LOG, 0666);
	mkfifo(FIFO_PMU_LOG, 0666);
	mkfifo(FIFO_SOCKET_SERVER_LOG, 0666);

	fd_pmu_to_os = open(FIFO_PMU_TO_OS, O_RDWR);
	fd_pmu_from_os = open(FIFO_PMU_FROM_OS, O_RDWR);
	//fd_mailbox_out = open(FIFO_PMU_MAILBOX_OUT, O_WRONLY);
	//fd_mailbox_in = open(FIFO_PMU_MAILBOX_IN, O_RDONLY);

	fd_mailbox_log = open(FIFO_MAILBOX_LOG, O_RDWR);
	fd_os_log = open(FIFO_OS_LOG, O_RDWR);
	fd_keyboard_log = open(FIFO_KEYBOARD_LOG, O_RDWR);
	fd_serial_out_log = open(FIFO_SERIAL_OUT_LOG, O_RDWR);
	fd_runtime1_log = open(FIFO_RUNTIME1_LOG, O_RDWR);
	fd_runtime2_log = open(FIFO_RUNTIME2_LOG, O_RDWR);
	fd_storage_log = open(FIFO_STORAGE_LOG, O_RDWR);
	fd_network_log = open(FIFO_NETWORK_LOG, O_RDWR);
	fd_untrusted_log = open(FIFO_UNTRUSTED_LOG, O_RDWR);
	fd_pmu_log = open(FIFO_PMU_LOG, O_RDWR);
	fd_socket_server_log = open(FIFO_SOCKET_SERVER_LOG, O_RDWR);

	dup2(fd_pmu_log, 1);
	printf("%s [1]: PMU init\n", __func__);

	mailbox_pid = start_mailbox_proc();
	os_pid = start_os_proc();
	keyboard_pid = start_keyboard_proc();
	serial_out_pid = start_serial_out_proc();
	runtime1_pid = start_runtime_proc((char *) "1");
	runtime2_pid = start_runtime_proc((char *) "2");
	storage_pid = start_storage_proc();
	network_pid = start_network_proc();
	untrusted_pid = start_untrusted_proc();
	/* Socket server is not part of OctopOS.
	 * We start it here since it's useful for testing.
	 */
	socket_server_pid = start_socket_server_proc();

	//sleep(15);
	//printf("%s [2]\n", __func__);
	//write(fd_untrusted_in, "root\n", sizeof("root\n"));

	/* see here for how to use pselect:
	 * https://lwn.net/Articles/176911/ 
	 */
        sigemptyset(&blockset);
        sigaddset(&blockset, SIGCHLD);
        sigprocmask(SIG_BLOCK, &blockset, NULL);

        sa.sa_handler = sig_handler;
        sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
        sigaction(SIGCHLD, &sa, NULL);
    
        sigemptyset(&emptyset);
	

	while (1) {
		int ret, max_fd;
		FD_ZERO(&r_fds);
		FD_SET(fd_serial_out, &r_fds); 
		FD_SET(0, &r_fds); 
		//FD_SET(fd_untrusted_out, &r_fds); 
		FD_SET(fd_pmu_from_os, &r_fds); 
		max_fd = fd_serial_out;
		if (fd_pmu_from_os > fd_serial_out)
			max_fd = fd_pmu_from_os;
		printf("%s [2]\n", __func__);
		ret = pselect(max_fd + 1, &r_fds, NULL, NULL, NULL, &emptyset);
		if (ret < 0 && errno == EINTR) { /* signal */
			char proc_name[64];
			pid_t pid = wait(&status);
			if (pid == mailbox_pid) {
				/* FIXME: doesn't really work. Need testing. */
				printf("Error: %s: mailbox terminated! Terminating...", __func__);
				goto err;
			} else if (pid == os_pid) {
				sprintf(proc_name, "OS");
				os_pid = start_os_proc();
			} else if (pid == keyboard_pid) {
				sprintf(proc_name, "Keyboard");
				keyboard_pid = start_keyboard_proc();
			} else if (pid == serial_out_pid) {
				sprintf(proc_name, "Serial Out");
				serial_out_pid = start_serial_out_proc();
			} else if (pid == runtime1_pid) {
				sprintf(proc_name, "Runtime1");
				runtime1_pid = start_runtime_proc((char *) "1");
			} else if (pid == runtime2_pid) {
				sprintf(proc_name, "Runtime2");
				runtime2_pid = start_runtime_proc((char *) "2");
			} else if (pid == storage_pid) {
				sprintf(proc_name, "Storage");
				storage_pid = start_storage_proc();
			} else if (pid == network_pid) {
				sprintf(proc_name, "Network");
				network_pid = start_network_proc();
			} else if (pid == untrusted_pid) {
				sprintf(proc_name, "Untrusted");
				untrusted_pid = start_untrusted_proc();
			} else if (pid == socket_server_pid) {
				sprintf(proc_name, "Socket Server");
				socket_server_pid = start_socket_server_proc();
			} else {
				printf("Error: %s: unknown pid (%d)\n", __func__, pid);
				continue;
			}
			printf("%s processor terminated (%d) and restarted\n", proc_name, status);
		} else {
			if (FD_ISSET(fd_serial_out, &r_fds)) {
				len = read(fd_serial_out, buffer, sizeof(buffer));
				write(2, buffer, len);
			}
			
			if (FD_ISSET(0, &r_fds)) {
				len = read(0, buffer, sizeof(buffer));
				if (!untrusted_init && len == 1 && buffer[0] == '@') {
					printf("%s [3]: initializing untrusted\n", __func__);
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
			
			//if (FD_ISSET(fd_untrusted_out, &r_fds)) {
			//	len = read(fd_untrusted_out, buffer, sizeof(buffer));
			//	printf("%s [3]: len = %d\n", __func__, len);
			//	//if (!strcmp(buffer, "localhost login: ")) {
			//	if (len <= 0)
			//		continue;

			//	write(fd_untrusted_log, buffer, len);
			//	if (len == 17) {
			//		printf("%s [3]: login detected\n", __func__);
			//		write(fd_untrusted_in, "root\n", sizeof("root\n"));
			//	}
			//}

			if (FD_ISSET(fd_pmu_from_os, &r_fds)) {
				printf("%s [4]: shutting down\n", __func__);
				len = read(fd_pmu_from_os, pmu_os_buf, PMU_OS_BUF_SIZE);
				if (pmu_os_buf[0] == PMU_OS_CMD_SHUTDOWN) {
					uint32_t cmd_ret = 0;
					write(fd_pmu_to_os, &cmd_ret, 4);
					goto err;
				} else {
					printf("Error: %s: invalid command from the OS (%d)\n",
					       __func__, pmu_os_buf[0]);
				}
			}
		}
	}

err:
	printf("%s [7]\n", __func__);

	/* Halt the untrusted domain.
	 * We send the halt cmd to it in case it wasn't listening
	 * on the mailbox for the cmd sent from the OS.
	 */
	char cmd1[] = "root\n";
	char cmd2[] = "halt\n";
	write(fd_untrusted_in, cmd1, sizeof(cmd1));
	sleep(1);
	write(fd_untrusted_in, cmd2, sizeof(cmd2));
	sleep(10);
	kill(untrusted_pid, SIGKILL);
	waitpid(untrusted_pid, &status, 0);

	/* Shut down the rest */
	kill(socket_server_pid, SIGKILL);
	waitpid(socket_server_pid, &status, 0);

	kill(network_pid, SIGKILL);
	waitpid(network_pid, &status, 0);
	
	kill(storage_pid, SIGKILL);
	waitpid(storage_pid, &status, 0);
	
	kill(runtime2_pid, SIGKILL);
	waitpid(runtime2_pid, &status, 0);
	
	kill(runtime1_pid, SIGKILL);
	waitpid(runtime1_pid, &status, 0);
	
	kill(serial_out_pid, SIGKILL);
	waitpid(serial_out_pid, &status, 0);
	
	kill(keyboard_pid, SIGKILL);
	waitpid(keyboard_pid, &status, 0);
	
	kill(os_pid, SIGKILL);
	waitpid(os_pid, &status, 0);
	
	kill(mailbox_pid, SIGKILL);
	waitpid(mailbox_pid, &status, 0);

	/* No more pmu logs after this. */
	close(fd_pmu_log);
	close(fd_socket_server_log);
	close(fd_untrusted_log);
	close(fd_network_log);
	close(fd_storage_log);
	close(fd_runtime1_log);
	close(fd_runtime2_log);
	close(fd_serial_out_log);
	close(fd_keyboard_log);
	close(fd_os_log);
	close(fd_mailbox_log);

	//close(fd_mailbox_in);
	//close(fd_mailbox_out);
	close(fd_pmu_from_os);
	close(fd_pmu_to_os);
	
	remove(FIFO_SOCKET_SERVER_LOG);
	remove(FIFO_PMU_LOG);
	remove(FIFO_UNTRUSTED_LOG);
	remove(FIFO_NETWORK_LOG);
	remove(FIFO_STORAGE_LOG);
	remove(FIFO_RUNTIME1_LOG);
	remove(FIFO_RUNTIME2_LOG);
	remove(FIFO_SERIAL_OUT_LOG);
	remove(FIFO_KEYBOARD_LOG);
	remove(FIFO_OS_LOG);
	remove(FIFO_MAILBOX_LOG);
	
	//remove(FIFO_PMU_MAILBOX_IN);
	//remove(FIFO_PMU_MAILBOX_OUT);
	remove(FIFO_PMU_FROM_OS);
	remove(FIFO_PMU_TO_OS);

	tcsetattr(0, TCSANOW, &orig);

	return 0;
}
