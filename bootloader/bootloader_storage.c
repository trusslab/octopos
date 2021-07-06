/* OctopOS bootloader for storage */

/******************************************************************************
*
* Copyright (C) 2009 - 2014 Xilinx, Inc.  All rights reserved.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* Use of the Software is limited solely to applications:
* (a) running on a Xilinx device, or
* (b) that interact with a Xilinx device through a bus or interconnect.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
* XILINX  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
* Except as contained in this notice, the name of the Xilinx shall not be used
* in advertising or otherwise to promote the sale, use or other dealings in
* this Software without prior written authorization from Xilinx.
*
******************************************************************************/

/*
 *      Simple SREC Bootloader
 *      This simple bootloader is provided with Xilinx EDK for you to easily re-use in your
 *      own software project. It is capable of booting an SREC format image file
 *      (Mototorola S-record format), given the location of the image in memory.
 *      In particular, this bootloader is designed for images stored in non-volatile flash
 *      memory that is addressable from the processor.
 *
 *      Please modify the define "FLASH_IMAGE_BASEADDR" in the blconfig.h header file
 *      to point to the memory location from which the bootloader has to pick up the
 *      flash image from.
 *
 *      You can include these sources in your software application project in XPS and
 *      build the project for the processor for which you want the bootload to happen.
 *      You can also subsequently modify these sources to adapt the bootloader for any
 *      specific scenario that you might require it for.
 *
 */

#if !defined(ARCH_SEC_HW_BOOT) || defined(ARCH_SEC_HW_BOOT_STORAGE)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
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
#include "sleep.h"
#include "xstatus.h"

void storage_request_boot_image_by_line();
//int load_boot_image_from_storage(int pid, void *ptr);
int write_boot_image_to_storage(int pid, void *ptr);

#ifdef IMAGE_WRITER_MODE

/* select the target processor (for use by installer only */
// #define TARGET_BOOT_PROCESSOR P_OS
// #define TARGET_BOOT_PROCESSOR P_STORAGE
// #define TARGET_BOOT_PROCESSOR P_RUNTIME1
//#define TARGET_BOOT_PROCESSOR P_KEYBOARD
//#define TARGET_BOOT_PROCESSOR P_SERIAL_OUT
//#define TARGET_BOOT_PROCESSOR P_UNTRUSTED_BOOT_P0
#define TARGET_BOOT_PROCESSOR P_UNTRUSTED_BOOT_P1

/* debug code needed for future storage development */
//uint8_t binary_DEBUG_READ_BACK[KEYBOARD_IMAGE_SIZE + 48] __attribute__ ((aligned(64)));
#if (TARGET_BOOT_PROCESSOR == P_STORAGE)
#include "arch/bin/storage_image.h"
#elif (TARGET_BOOT_PROCESSOR == P_OS)
#include "arch/bin/os_image.h"
#elif (TARGET_BOOT_PROCESSOR == P_RUNTIME1)
#include "arch/bin/runtime1_image.h"
#elif (TARGET_BOOT_PROCESSOR == P_KEYBOARD)
#include "arch/bin/keyboard_image.h"
#elif (TARGET_BOOT_PROCESSOR == P_SERIAL_OUT)
#include "arch/bin/serialout_image.h"
#elif (TARGET_BOOT_PROCESSOR == P_UNTRUSTED_BOOT_P0)
#include "arch/bin/image.bin.0.h"
#elif (TARGET_BOOT_PROCESSOR == P_UNTRUSTED_BOOT_P1)
#include "arch/bin/image.bin.1.h"
#endif

#endif /* IMAGE_WRITER_MODE */
#endif /* ARCH_SEC_HW_BOOT */


#ifndef ARCH_SEC_HW_BOOT
/* in file system wrapper */
extern FILE *filep;
/* FIXME: why should we need the total_blocks in bootloader? */
extern uint32_t total_blocks;

int fd_out, fd_intr;
pthread_t mailbox_thread;

 /* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];
sem_t availables[NUM_QUEUES + 1];

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1)
		read(fd_intr, &interrupt, 1);
}

int init_mailbox(void)
{
	mkfifo(FIFO_STORAGE_OUT, 0666);
	mkfifo(FIFO_STORAGE_INTR, 0666);

	fd_out = open(FIFO_STORAGE_OUT, O_WRONLY);
	fd_intr = open(FIFO_STORAGE_INTR, O_RDONLY);

	int ret = pthread_create(&mailbox_thread, NULL,
				 handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}


	return 0;
}

void close_mailbox(void)
{	
	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);
	
	close(fd_out);
	close(fd_intr);
}
#endif

void prepare_bootloader(char *filename, int argc, char *argv[])
{
#ifndef ARCH_SEC_HW_BOOT
	filep = fopen("./storage/octopos_partition_0_data", "r");
	if (!filep) {
		printf("Error: %s: Couldn't open the boot partition file.\n",
		       __func__);
		exit(-1);
	}

	/* The added 1 is for the signature.
	 *
	 * FIXME: assumes signature file is less than one block.
	 */
	total_blocks = STORAGE_BOOT_PARTITION_SIZE + 1;
	initialize_file_system(STORAGE_BOOT_PARTITION_SIZE);
#else
	int Status;

	Status = init_storage();
	if (Status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return;
	}

#endif
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

#else /* ARCH_SEC_HW_BOOT */

#ifndef IMAGE_WRITER_MODE
	storage_request_boot_image_by_line();
#else /* IMAGE_WRITER_MODE */

	write_boot_image_to_storage(TARGET_BOOT_PROCESSOR, binary);
	/* debug code needed for future use */
//	load_boot_image_from_storage(TARGET_BOOT_PROCESSOR, binary_DEBUG_READ_BACK);
//
//	for (int i = 0; i < KEYBOARD_IMAGE_SIZE; i++) {
//		if (binary[i] != binary_DEBUG_READ_BACK[i])
//			SEC_HW_DEBUG_HANG();
//	}

	SEC_HW_DEBUG_HANG();
#endif /* IMAGE_WRITER_MODE */

#endif /* ARCH_SEC_HW_BOOT */

	return 0;
}

#ifndef ARCH_SEC_HW_BOOT
void bootloader_close_file_system(void)
{
	close_file_system();
	fclose(filep);
}
#endif /* ARCH_SEC_HW_BOOT */

#ifndef ARCH_SEC_HW_BOOT
void send_measurement_to_tpm(char *path)
{
	enforce_running_process(P_STORAGE);
	tpm_measure_service(path);
	cancel_running_process();
	close_mailbox();
}
#endif /* ARCH_SEC_HW_BOOT */

#endif
