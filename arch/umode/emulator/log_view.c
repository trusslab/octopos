/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
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
#include <arch/pmu.h>

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

	opt = getopt(argc, argv, "mtokl12snbupv");
	switch (opt) {
	case 'm':
		mkfifo(FIFO_MAILBOX_LOG, 0666);
		fd_log = open(FIFO_MAILBOX_LOG, O_RDONLY);
		printf("Mailbox logs:\n");
		break;
	case 't':
		mkfifo(FIFO_TPM_LOG, 0666);
		fd_log = open(FIFO_TPM_LOG, O_RDONLY);
		printf("TPM logs:\n");
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
	case 'l':
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
	case 'n': 
		mkfifo(FIFO_NETWORK_LOG, 0666);
		fd_log = open(FIFO_NETWORK_LOG, O_RDONLY);
		printf("Network processor logs:\n");
		break;
	case 'b': 
		mkfifo(FIFO_BLUETOOTH_LOG, 0666);
		fd_log = open(FIFO_BLUETOOTH_LOG, O_RDONLY);
		printf("Bluetooth processor logs:\n");
		break;
	case 'u': 
		mkfifo(FIFO_UNTRUSTED_LOG, 0666);
		fd_log = open(FIFO_UNTRUSTED_LOG, O_RDONLY);
		printf("Untrusted processor logs:\n");
		break;
	case 'p': 
		mkfifo(FIFO_PMU_LOG, 0666);
		fd_log = open(FIFO_PMU_LOG, O_RDONLY);
		printf("PMU logs:\n");
		break;
	case 'v': 
		mkfifo(FIFO_APP_SERVERS_LOG, 0666);
		fd_log = open(FIFO_APP_SERVERS_LOG, O_RDONLY);
		printf("Socket server logs:\n");
		break;
	default:
		printf("Error: %s: Command not supported\n", __func__);
		exit(-1);
        }

	memset(buffer, 0x0, READ_SIZE);

	while (1) {
		ret = read(fd_log, buffer, READ_SIZE);
		if (ret <= 0 || ret > READ_SIZE)
			break;

		write(1, buffer, ret);
	}

	close(fd_log);

	switch (opt) {
	case 'm':
		remove(FIFO_MAILBOX_LOG);
		break;
	case 't':
		remove(FIFO_TPM_LOG);
		break;
	case 'o':
		remove(FIFO_OS_LOG);
		break;
	case 'k':
		remove(FIFO_KEYBOARD_LOG);
		break;
	case 'l':
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
	case 'n': 
		remove(FIFO_NETWORK_LOG);
		break;
	case 'b': 
		remove(FIFO_BLUETOOTH_LOG);
		break;
	case 'u': 
		remove(FIFO_UNTRUSTED_LOG);
		break;
	case 'p': 
		remove(FIFO_PMU_LOG);
		break;
	case 'v': 
		remove(FIFO_APP_SERVERS_LOG);
		break;
	default:
		printf("Error: %s: Command not supported\n", __func__);
		exit(-1);
        }

	return ret;
}
