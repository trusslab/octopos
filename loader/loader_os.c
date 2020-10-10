/* OctopOS loader for OS */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>
#include <octopos/storage.h>
#include <os/file_system.h>
#include <os/storage.h>
#include <arch/mailbox_os.h>

void prepare_loader(char *filename, int argc, char *argv[])
{
	/* no op */
}

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 *
 * When booting the OS, the loader reads the OS image
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
	printf("%s [1]\n", __func__);

	//filep = fopen("./storage/octopos_partition_0_data", "r");
	//if (!filep) {
	//	printf("Error: %s: Couldn't open the boot partition file.\n", __func__);
	//	return -1;
	//}

	/* FIXME: size hard-coded */
	//total_blocks = 2000;
	init_os_mailbox();
	initialize_storage();
	printf("%s [2]\n", __func__);



	/* FIXME: size hard-coded */
	initialize_file_system(2000);
	printf("%s [2.1]\n", __func__);

	fd = file_system_open_file(filename, FILE_OPEN_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file system.\n",
		       __func__, filename);
		return -1;
	}
	printf("%s [2.2]\n", __func__);

	copy_filep = fopen(path, "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the target file (%s).\n", __func__, path);
		return -1;
	}

	offset = 0;
	printf("%s [3]\n", __func__);

	while (1) {
		printf("%s [4]: offset = %d\n", __func__, offset);
		_size = file_system_read_from_file(fd, buf, STORAGE_BLOCK_SIZE, offset);
		printf("%s [5]: _size = %d\n", __func__, _size);
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
	printf("%s [6]\n", __func__);

	fclose(copy_filep);
	file_system_close_file(fd);

	close_file_system();



	//fclose(filep);
	close_os_mailbox();

	return 0;
}
