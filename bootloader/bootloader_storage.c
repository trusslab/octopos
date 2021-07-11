/* OctopOS bootloader for storage */

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

/* in file system wrapper */
extern FILE *filep;
/* FIXME: why should we need the total_blocks in bootloader? */
extern uint32_t total_blocks;

#ifndef ARCH_SEC_HW_BOOT
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
#ifdef ARCH_SEC_HW_BOOT
	int Status;

	Status = init_storage();
	if (Status != XST_SUCCESS) {
		SEC_HW_DEBUG_HANG();
		return;
	}
#endif

#ifdef ARCH_SEC_HW_BOOT
	filep = fop_open("octopos_partition_0_data", "r");
#else
	filep = fop_open("./storage/octopos_partition_0_data", "r");
#endif
	if (!filep) {
		printf("Error: %s: Couldn't open the boot partition file.\n",
		       __func__);
		while(1);
	}

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
	fop_close(filep);
}

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
