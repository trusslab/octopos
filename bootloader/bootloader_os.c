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
#endif
#include <stdint.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/tpm.h>
#include <os/file_system.h>
#include <os/storage.h>
#include <tpm/hash.h>
#include <arch/mailbox_os.h>
#ifdef ARCH_SEC_HW_BOOT
#include "xil_printf.h"
#include "arch/sec_hw.h"
#include "sleep.h"
#include "xstatus.h"
#endif

#ifndef ARCH_SEC_HW_BOOT
extern int fd_out;
extern sem_t interrupts[];

/* FIXME: copied from bootloader_other.c */
/* FIXME: move to mailbox_os.c or some shared util file*/
static void send_message_to_tpm(uint8_t* buf)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[Q_TPM_IN]);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_TPM_IN;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

void prepare_bootloader(char *filename, int argc, char *argv[])
{
	init_os_mailbox();
	
	/* delegate TPM mailbox to storage */
	mark_queue_unavailable(Q_TPM_IN);
	mailbox_delegate_queue_access(Q_TPM_IN, P_STORAGE,
				      TPM_EXTEND_HASH_NUM_MAILBOX_MSGS,
				      MAILBOX_DEFAULT_TIMEOUT_VAL);

	wait_for_queue_availability(Q_TPM_IN);
	
	initialize_storage();

	initialize_file_system(STORAGE_BOOT_PARTITION_SIZE);
}

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

	return 0;
}

void send_measurement_to_tpm(char *path)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	char hash_buf[TPM_EXTEND_HASH_SIZE] = {0};

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

	/* Wait for TPM to read the message */
	wait_until_empty(Q_TPM_IN, MAILBOX_QUEUE_SIZE);
	
	close_os_mailbox();
}
#else
void os_request_boot_image_by_line(char *filename, char *path);

void prepare_bootloader(char *filename, int argc, char *argv[])
{
	int ret = init_os_mailbox();
	if (ret)
		SEC_HW_DEBUG_HANG();

	// FIXME: is there a better way to wait for storage boot?
	sleep(1);

	initialize_storage();

	initialize_file_system(STORAGE_BOOT_PARTITION_SIZE);
}

int copy_file_from_boot_partition(char *filename, char *path)
{
	os_request_boot_image_by_line(filename, path);
	return 0;
}

#endif

#endif
