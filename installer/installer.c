/* OctopOS installer
 * Helps prepare the boot partition
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <octopos/storage.h>
#include <os/file_system.h>

/* in file system wrapper */
extern FILE *filep;
extern uint32_t total_blocks;

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 * @block_aligned: if non-zero, we will pad the end of the copied file with
 * as many zeros as needed to align it with storage block size.
 */
static int copy_file_from_partition(char *filename, char *copy_path,
				    int block_aligned)
{
	uint32_t fd;
	FILE *copy_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int _size;
	int offset;

	fd = file_system_open_file(filename, FILE_OPEN_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file system"
		       " (copy).\n", __func__, filename);
		return -1;
	}

	copy_filep = fopen(copy_path, "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the target file (%s).\n",
		       __func__, copy_path);
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

		/* Last block */
		if (_size != STORAGE_BLOCK_SIZE)
			break;
	}

	if (block_aligned) {
		int rem = STORAGE_BLOCK_SIZE - _size;

		memset(buf, 0x0, rem);
		fseek(copy_filep, offset, SEEK_SET);
		fwrite(buf, sizeof(uint8_t), rem, copy_filep);
	}

	fclose(copy_filep);
	file_system_close_file(fd);

	return 0;
}

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 */
static int copy_file_to_partition(char *filename, char *path)
{
	uint32_t fd;
	FILE *src_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int _size;
	int offset;

	fd = file_system_open_file(filename, FILE_OPEN_CREATE_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file "
		       "system.\n", __func__, filename);
		return -1;
	}

	src_filep = fopen(path, "r");
	if (!src_filep) {
		printf("Error: %s: Couldn't open the source file (%s).\n",
		       __func__, path);
		return -1;
	}

	offset = 0;

	while (1) { 
		fseek(src_filep, offset, SEEK_SET);
		_size = fread(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE,
			      src_filep);
		if (_size == 0)
			break;

		if (_size < 0 || _size > STORAGE_BLOCK_SIZE) {
			printf("Error: %s: reading file.\n", __func__);
			break;
		}

		file_system_write_to_file(fd, buf, _size, offset);

		offset += _size;
	}

	fclose(src_filep);
	file_system_close_file(fd);

	return 0;
}

int main(int argc, char **argv)
{
	/* create new file or delete existing file */
	filep = fopen("./storage/octopos_partition_0_data", "w");
	if (!filep) {
		printf("Error: %s: Couldn't open the partition file (w).\n",
		       __func__);
		return -1;
	}
	fclose(filep);

	/* open for read and write */
	filep = fopen("./storage/octopos_partition_0_data", "r+");
	if (!filep) {
		printf("Error: %s: Couldn't open the partition file (r+).\n",
		       __func__);
		return -1;
	}

	total_blocks += DIR_DATA_NUM_BLOCKS;

	initialize_file_system(STORAGE_BOOT_PARTITION_SIZE);

	copy_file_to_partition((char *) "keyboard",
			       (char *) "./keyboard/keyboard");
	copy_file_to_partition((char *) "serial_out",
			       (char *) "./serial_out/serial_out");
	copy_file_to_partition((char *) "storage",
			       (char *) "./storage/storage");
	copy_file_to_partition((char *) "os", (char *) "./os/os");
	copy_file_to_partition((char *) "runtime",
			       (char *) "./runtime/runtime");
	copy_file_to_partition((char *) "network",
			       (char *) "./network/network");
	copy_file_to_partition((char *) "bluetooth",
			       (char *) "./bluetooth/bluetooth");
	copy_file_to_partition((char *) "linux",
			       (char *) "./arch/umode/untrusted_linux/linux");
	copy_file_to_partition((char *) "attest_client",
			       (char *) "./applications/bin/attest_client.so");
	copy_file_to_partition((char *) "bank_client",
			       (char *) "./applications/bin/bank_client.so");
	copy_file_to_partition((char *) "fs_loop",
			       (char *) "./applications/bin/fs_loop.so");
	copy_file_to_partition((char *) "fs_test",
			       (char *) "./applications/bin/fs_test.so");
	copy_file_to_partition((char *) "health_client",
			       (char *) "./applications/bin/health_client.so");
	copy_file_to_partition((char *) "ipc_receiver",
			       (char *) "./applications/bin/ipc_receiver.so");
	copy_file_to_partition((char *) "ipc_sender",
			       (char *) "./applications/bin/ipc_sender.so");
	copy_file_to_partition((char *) "secure_interact",
			       (char *) "./applications/bin/secure_interact.so");
	copy_file_to_partition((char *) "secure_login",
			       (char *) "./applications/bin/secure_login.so");
	copy_file_to_partition((char *) "simple_loop",
			       (char *) "./applications/bin/simple_loop.so");
	copy_file_to_partition((char *) "socket_client",
			       (char *) "./applications/bin/socket_client.so");


	/* For testing purposes, copy the files from partition */
	copy_file_from_partition((char *) "keyboard",
				 (char *) "./installer/copy_keyboard", 0);
	copy_file_from_partition((char *) "serial_out",
				 (char *) "./installer/copy_serial_out", 0);
	copy_file_from_partition((char *) "storage",
				 (char *) "./installer/copy_storage", 0);
	copy_file_from_partition((char *) "os",
				 (char *) "./installer/copy_os", 0);
	copy_file_from_partition((char *) "runtime",
				 (char *) "./installer/copy_runtime", 0);
	copy_file_from_partition((char *) "network",
				 (char *) "./installer/copy_network", 0);
	copy_file_from_partition((char *) "bluetooth",
				 (char *) "./installer/copy_bluetooth", 0);
	copy_file_from_partition((char *) "linux",
				 (char *) "./installer/copy_linux", 0);
	copy_file_from_partition((char *) "attest_client",
				 (char *) "./installer/copy_attest_client.so", 0);
	copy_file_from_partition((char *) "bank_client",
				 (char *) "./installer/copy_bank_client.so", 0);
	copy_file_from_partition((char *) "fs_loop",
				 (char *) "./installer/copy_fs_loop.so", 0);
	copy_file_from_partition((char *) "fs_test",
				 (char *) "./installer/copy_fs_test.so", 0);
	copy_file_from_partition((char *) "health_client",
				 (char *) "./installer/copy_health_client.so", 0);
	copy_file_from_partition((char *) "ipc_receiver",
				 (char *) "./installer/copy_ipc_receiver.so", 0);
	copy_file_from_partition((char *) "ipc_sender",
				 (char *) "./installer/copy_ipc_sender.so", 0);
	copy_file_from_partition((char *) "secure_interact",
				 (char *) "./installer/copy_secure_interact.so", 0);
	copy_file_from_partition((char *) "secure_login",
				 (char *) "./installer/copy_secure_login.so", 0);
	copy_file_from_partition((char *) "simple_loop",
				 (char *) "./installer/copy_simple_loop.so", 0);
	copy_file_from_partition((char *) "socket_client",
				 (char *) "./installer/copy_socket_client.so", 0);

	/* For attestation, we need the block-aligned version of some of the
	 * files.
	 * */
	copy_file_from_partition((char *) "keyboard",
				 (char *) "./installer/aligned_keyboard", 1);
	copy_file_from_partition((char *) "serial_out",
				 (char *) "./installer/aligned_serial_out", 1);
	copy_file_from_partition((char *) "runtime",
				 (char *) "./installer/aligned_runtime", 1);
	copy_file_from_partition((char *) "network",
				 (char *) "./installer/aligned_network", 1);
	copy_file_from_partition((char *) "bluetooth",
				 (char *) "./installer/aligned_bluetooth", 1);
	
	printf("installer: total number of written blocks = %d\n", total_blocks);

	close_file_system();
	fclose(filep);

	return 0;
}	
