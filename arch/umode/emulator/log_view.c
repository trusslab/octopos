/* OctopOS umode emulator log viewer */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arch/mailbox.h>

/* FIXME: move somewhere else */
#define FIFO_MAILBOX_LOG	"/tmp/octopos_mailbox_log"
#define FIFO_OS_LOG		"/tmp/octopos_os_log"
#define FIFO_KEYBOARD_LOG	"/tmp/octopos_keyboard_log"
#define FIFO_SERIAL_OUT_LOG	"/tmp/octopos_serial_out_log"
#define FIFO_RUNTIME1_LOG	"/tmp/octopos_runtime1_log"
#define FIFO_RUNTIME2_LOG	"/tmp/octopos_runtime2_log"
#define FIFO_STORAGE_LOG	"/tmp/octopos_storage_log"
#define FIFO_PMU_LOG		"/tmp/octopos_pmu_log"

#define READ_SIZE	256

int main(int argc, char **argv)
{
	char buffer[READ_SIZE];
	int ret = 0, opt;
	int fd_log;
	
	if (argc != 2) {
		printf("Error: %s: Needs one and only one arg\n", __func__);
		exit(-1);
	}

	opt = getopt(argc, argv, "moku12sp");
	switch (opt) {
	case 'm':
		mkfifo(FIFO_MAILBOX_LOG, 0666);
		fd_log = open(FIFO_MAILBOX_LOG, O_RDONLY);
		printf("Mailbox logs:\n");
		break;
	case 'o':
		mkfifo(FIFO_OS_LOG, 0666);
		fd_log = open(FIFO_OS_LOG, O_RDONLY);
		printf("OS processor logs:\n");
		break;
	case 'k':
		mkfifo(FIFO_KEYBOARD_LOG, 0666);
		fd_log = open(FIFO_KEYBOARD_LOG, O_RDONLY);
		printf("Keyboard processor logs:\n");
		break;
	case 'u':
		mkfifo(FIFO_SERIAL_OUT_LOG, 0666);
		fd_log = open(FIFO_SERIAL_OUT_LOG, O_RDONLY);
		printf("Serial Out processor logs:\n");
		break;
	case '1':
		mkfifo(FIFO_RUNTIME1_LOG, 0666);
		fd_log = open(FIFO_RUNTIME1_LOG, O_RDONLY);
		printf("Runtime1 processor logs:\n");
		break;
	case '2':
		mkfifo(FIFO_RUNTIME2_LOG, 0666);
		fd_log = open(FIFO_RUNTIME2_LOG, O_RDONLY);
		printf("Runtime2 processor logs:\n");
		break;
	case 's': 
		mkfifo(FIFO_STORAGE_LOG, 0666);
		fd_log = open(FIFO_STORAGE_LOG, O_RDONLY);
		printf("Storage processor logs:\n");
		break;
	case 'p': 
		mkfifo(FIFO_PMU_LOG, 0666);
		fd_log = open(FIFO_PMU_LOG, O_RDONLY);
		printf("PMU logs:\n");
		break;
	default:
		printf("Error: %s: Command not supported\n", __func__);
		exit(-1);
        }

	memset(buffer, 0x0, READ_SIZE);

	while (1) {
		ret = read(fd_log, buffer, READ_SIZE);
		if (ret < 0 || ret > READ_SIZE)
			break;

		if (ret == 0)
			continue;

		write(1, buffer, ret);
	}

	close(fd_log);

	switch (opt) {
	case 'm':
		remove(FIFO_MAILBOX_LOG);
		break;
	case 'o':
		remove(FIFO_OS_LOG);
		break;
	case 'k':
		remove(FIFO_KEYBOARD_LOG);
		break;
	case 'u':
		remove(FIFO_SERIAL_OUT_LOG);
		break;
	case '1':
		remove(FIFO_RUNTIME1_LOG);
		break;
	case '2':
		remove(FIFO_RUNTIME2_LOG);
		break;
	case 's': 
		remove(FIFO_STORAGE_LOG);
		break;
	case 'p': 
		remove(FIFO_PMU_LOG);
		break;
	default:
		printf("Error: %s: Command not supported\n", __func__);
		exit(-1);
        }

	return ret;
}
