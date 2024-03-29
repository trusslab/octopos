/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* OctopOS bootloader for storage */

#if !defined(ARCH_SEC_HW_BOOT) || defined(ARCH_SEC_HW_BOOT_STORAGE)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#ifndef ARCH_SEC_HW_BOOT
#include <dlfcn.h>
#include <semaphore.h>
#include <unistd.h>
#include <pthread.h>
#include <tpm/tpm.h>
#endif
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <os/file_system.h>
#include <tpm/hash.h>
#ifndef ARCH_SEC_HW_BOOT
#include <arch/mailbox.h>
#else
#include <arch/mailbox_storage.h>
#include "xil_printf.h"
#include "arch/sec_hw.h"
#include "arch/pmod_fop.h"
#include "sleep.h"
#include "xstatus.h"

void storage_request_boot_image_by_line(char *filename);
int write_boot_image_to_storage(int pid, void *ptr);

#endif /* ARCH_SEC_HW_BOOT */

/* compatible fops */
#ifndef ARCH_SEC_HW_BOOT
#define fop_open fopen
#define fop_close fclose
#define fop_seek fseek
#define fop_read fread
#define fop_write fwrite
#else /* ARCH_SEC_HW_BOOT */
#define FILE DFILE
#endif /* ARCH_SEC_HW_BOOT */

extern FILE *filep;
/* FIXME: why should we need the total_blocks in bootloader? */
extern uint32_t total_blocks;

void prepare_bootloader(char *filename, int argc, char *argv[])
{
#ifndef ARCH_SEC_HW_BOOT
	filep = fop_open("./storage/octopos_partition_0_data", "r");
	if (!filep) {
		printf("Error: %s: Couldn't open the boot partition file.\n",
		       __func__);
		exit(-1);
	}
#endif

	/* The added 1 is for the signature.
	 *
	 * FIXME: assumes signature file is less than one block.
	 */
	total_blocks = STORAGE_BOOT_PARTITION_SIZE + 1;
	initialize_file_system(STORAGE_BOOT_PARTITION_SIZE);
}

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 *
 * When booting the storage, the bootloader directly reads the
 * storage image from storage medium itself.
 */
int copy_file_from_boot_partition(char *filename, char *path)
{
#ifndef ARCH_SEC_HW_BOOT
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

	copy_filep = fop_open(path, "w");
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

		fop_seek(copy_filep, offset, SEEK_SET);
		fop_write(buf, sizeof(uint8_t), _size, copy_filep);

		offset += _size;
	}

	fop_close(copy_filep);
	file_system_close_file(fd);

#else /* ARCH_SEC_HW_BOOT */
	storage_request_boot_image_by_line(filename);
#endif /* ARCH_SEC_HW_BOOT */

	return 0;
}

void bootloader_close_file_system(void)
{
	close_file_system();
#ifndef ARCH_SEC_HW_BOOT
	fop_close(filep);
#endif
}

#ifndef ARCH_SEC_HW_BOOT
void send_measurement_to_tpm(char *path)
{
	enforce_running_process(P_STORAGE);
	tpm_measure_service(path, 1);
	cancel_running_process();
}
#endif /* ARCH_SEC_HW_BOOT */

#endif
