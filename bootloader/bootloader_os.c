/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* OctopOS bootloader for OS */
#if !defined(ARCH_SEC_HW_BOOT) || defined(ARCH_SEC_HW_BOOT_OS)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#ifndef ARCH_SEC_HW_BOOT
#include <dlfcn.h>
#include <semaphore.h>
#include <unistd.h>
#include <tpm/tpm.h>
#else
#include "xil_printf.h"
#include "arch/sec_hw.h"
#include "sleep.h"
#include "xstatus.h"
#endif
#include <stdint.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <os/file_system.h>
#include <os/storage.h>
#include <tpm/hash.h>
#include <arch/mailbox_os.h>

#ifdef ARCH_SEC_HW_BOOT
extern long long reset_tick;
#endif

void prepare_bootloader(char *filename, int argc, char *argv[])
{
	init_os_mailbox();

#ifdef ARCH_SEC_HW_BOOT
	/* FIXME: is there a better way to wait for storage boot? */
	sleep(BOOT_RAM_COPY_TIME_S);
	STORAGE_REBOOT_WAIT();
	printf("wait done\r\n");
#endif

	initialize_storage();
	initialize_file_system(STORAGE_BOOT_PARTITION_SIZE);
}

void bootloader_close_file_system(void)
{
	close_file_system();
}

#ifndef ARCH_SEC_HW_BOOT
extern int fd_out;
extern sem_t interrupts[];

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 *
 * When booting the OS, the bootloader reads the OS image
 * by communicating with the storage service using the
 * storage mailboxes.
 */
int copy_file_from_boot_partition(char *filename, char *path)
{
	uint32_t fd;
	FILE *copy_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int _size;
	int offset;

	fd = file_system_open_file(filename, FILE_OPEN_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file "
		       "system.\n", __func__, filename);
		return -1;
	}

	copy_filep = fopen(path, "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the target file (%s).\n",
		       __func__, path);
		return -1;
	}

	offset = 0;

	while (1) {
		_size = file_system_read_from_file(fd, buf, STORAGE_BLOCK_SIZE,
						   offset);
		if (_size == 0)
			break;

		if (_size < 0 || _size > STORAGE_BLOCK_SIZE) {
			printf("Error: %s: reading file.\n", __func__);
			break;
		}

		fseek(copy_filep, offset, SEEK_SET);
		fwrite(buf, sizeof(uint8_t), _size, copy_filep);

		offset += _size;
	}

	fclose(copy_filep);
	file_system_close_file(fd);

	return 0;
}

void send_measurement_to_tpm(char *path)
{
	enforce_running_process(P_OS);
	tpm_measure_service(path, 1);
	cancel_running_process();
	close_os_mailbox();
}
#else
void os_request_boot_image_by_line(char *filename, char *path);

int copy_file_from_boot_partition(char *filename, char *path)
{
	storage_request_boot_image_by_line(filename, path);
	return 0;
}

#endif /* ARCH_SEC_HW_BOOT */

#endif
