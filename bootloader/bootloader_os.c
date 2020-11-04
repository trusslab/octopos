/* OctopOS bootloader for OS */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>
#include <semaphore.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <os/file_system.h>
#include <os/storage.h>
#include <arch/mailbox_os.h>

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
	mailbox_delegate_queue_access(Q_TPM_IN, P_STORAGE, 1,
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

	memcpy(buf, path, strlen(path) + 1);

	send_message_to_tpm(buf);

	/* Wait for TPM to read the message */
	wait_until_empty(Q_TPM_IN, MAILBOX_QUEUE_SIZE);
	
	close_os_mailbox();
}
