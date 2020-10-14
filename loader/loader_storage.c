/* OctopOS loader for storage */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>
#include <octopos/storage.h>
#include <os/file_system.h>

/* in file system wrapper */
extern FILE *filep;
/* FIXME: why should we need the total_blocks in loader? */
extern uint32_t total_blocks;

void prepare_loader(char *filename, int argc, char *argv[])
{
	/* no op */
}

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 *
 * When booting the storage, the loader directly reads the
 * storage image from storage medium itself.
 */
int copy_file_from_boot_partition(char *filename, char *path)
{
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

	/* FIXME: size hard-coded */
	total_blocks = 2000;
	initialize_file_system(2000);

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

	fclose(copy_filep);
	file_system_close_file(fd);

	close_file_system();
	fclose(filep);

	return 0;
}

void send_measurement_to_tpm(char *path)
{
	/* no op */
}
