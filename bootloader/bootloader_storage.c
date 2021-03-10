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
#endif
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/tpm.h>
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

int load_boot_image_from_storage(int pid, void *ptr);
int write_boot_image_to_storage(int pid, void *ptr);

extern uint32_t boot_image_sizes[NUM_PROCESSORS + 1];
#define TARGET_BOOT_PROCESSOR P_OS

/* if set, switch to image writer mode */
//#define IMAGE_WRITER_MODE

#ifndef IMAGE_WRITER_MODE
uint8_t binary[STORAGE_IMAGE_SIZE + 48] __attribute__ ((aligned(64)));
#else
//uint8_t binary_DEBUG_READ_BACK[OS_IMAGE_SIZE + 48] __attribute__ ((aligned(64)));
//#include "arch/bin/storage_image.h"
#include "arch/bin/os_image.h"
#endif


#endif


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
	int num_tpm_in = 0;

	while (1) {
		read(fd_intr, &interrupt, 1);

		/* FIXME: check the TPM interrupt logic */
		if (interrupt == Q_TPM_IN) {
			sem_post(&interrupts[Q_TPM_IN]);
			/* Block interrupts until the program is loaded.
			 * Otherwise, we might receive some interrupts not
			 * intended for the bootloader.
			 */
			num_tpm_in++;
			if (num_tpm_in == TPM_EXTEND_HASH_NUM_MAILBOX_MSGS) 
				return NULL;
		} else if ((interrupt - NUM_QUEUES) == Q_TPM_IN) {
			sem_post(&availables[Q_TPM_IN]);
		} else {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
	}
}

/* FIXME: copied from bootloader_other.c */
static void send_message_to_tpm(uint8_t* buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_TPM_IN;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

int init_mailbox(void)
{
	/* set the initial value of this one to 0 so that we can use it
	 * to wait for the TPM to read the message.
	 */
	sem_init(&interrupts[Q_TPM_IN], 0, 0);
	sem_init(&availables[Q_TPM_IN], 0, 0);

	mkfifo(FIFO_STORAGE_OUT, 0666);
	mkfifo(FIFO_STORAGE_INTR, 0666);

	fd_out = open(FIFO_STORAGE_OUT, O_WRONLY);
	fd_intr = open(FIFO_STORAGE_INTR, O_RDONLY);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
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
	/* no op */
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

	filep = fopen("./storage/octopos_partition_0_data", "r");
	if (!filep) {
		printf("Error: %s: Couldn't open the boot partition file.\n", __func__);
		return -1;
	}

	total_blocks = STORAGE_BOOT_PARTITION_SIZE;

	initialize_file_system(STORAGE_BOOT_PARTITION_SIZE);

	fd = file_system_open_file(filename, FILE_OPEN_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file system.\n",
		       __func__, filename);
		return -1;
	}

	copy_filep = fopen(path, "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the target file (%s).\n", __func__, path);
		return -1;
	}

	offset = 0;

	while (1) {
		_size = file_system_read_from_file(fd, buf, STORAGE_BLOCK_SIZE, offset);
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

	close_file_system();
	fclose(filep);
#else

#ifndef IMAGE_WRITER_MODE
	load_boot_image_from_storage(P_STORAGE, binary);
#else /* IMAGE_WRITER_MODE */

//#define TARGET_BOOT_PROCESSOR P_STORAGE
	write_boot_image_to_storage(TARGET_BOOT_PROCESSOR, binary);
//	load_boot_image_from_storage(TARGET_BOOT_PROCESSOR, binary_DEBUG_READ_BACK);
//
//	for (int i = 0; i < boot_image_sizes[TARGET_BOOT_PROCESSOR]; i++) {
//		if (binary[i] != binary_DEBUG_READ_BACK[i])
//			SEC_HW_DEBUG_HANG();
//	}

	SEC_HW_DEBUG_HANG();
#endif /* IMAGE_WRITER_MODE */

#endif

	return 0;
}


#ifndef ARCH_SEC_HW_BOOT
void send_measurement_to_tpm(char *path)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	char hash_buf[TPM_EXTEND_HASH_SIZE] = {0};
	int i;

	init_mailbox();

	/* Wait for the TPM mailbox */
	sem_wait(&availables[Q_TPM_IN]);

	hash_file(path, hash_buf);
	buf[0] = TPM_OP_EXTEND;

	/* Note that we assume that two messages are needed to send the hash.
	 * See include/tpm/hash.h
	 */
	memcpy(buf + 1, hash_buf, MAILBOX_QUEUE_MSG_SIZE - 1);
	send_message_to_tpm(buf);
	memcpy(buf, hash_buf + MAILBOX_QUEUE_MSG_SIZE - 1,
	       TPM_EXTEND_HASH_SIZE - MAILBOX_QUEUE_MSG_SIZE + 1);
	send_message_to_tpm(buf);

	/* Wait for TPM to read the messages */
	for (i = 0; i < TPM_EXTEND_HASH_NUM_MAILBOX_MSGS; i++)
		sem_wait(&interrupts[Q_TPM_IN]);

	close_mailbox();
}
#endif


#endif
