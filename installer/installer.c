/* OctopOS installer
 * Helps prepare the boot partition
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <octopos/storage.h>
#include <os/file_system.h>

/* in file system wrapper */
extern FILE *filep;
extern uint32_t total_blocks;

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 * @copy_path: the path where the file will be copied to for testing
 */
static int copy_file_to_partition(char *filename, char *path, int do_test, char *copy_path)
{
	uint32_t fd;
	FILE *src_filep, *copy_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int _size;
	int offset;

	fd = file_system_open_file(filename, FILE_OPEN_CREATE_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file system.\n",
		       __func__, filename);
		return -1;
	}

	src_filep = fopen(path, "r");
	if (!src_filep) {
		printf("Error: %s: Couldn't open the source file (%s).\n", __func__, path);
		return -1;
	}

	offset = 0;

	while (1) { 
		printf("%s [2]: offset = %d\n", __func__, offset);
		fseek(src_filep, offset, SEEK_SET);
		_size = fread(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, src_filep);
		printf("%s [3]: _size = %d\n", __func__, _size);
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
	
	printf("%s: total number of written blocks = %d\n", __func__, total_blocks);

	if (!do_test)
		return 0;

	/* test start */
	fd = file_system_open_file(filename, FILE_OPEN_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file system (test).\n",
		       __func__, filename);
		return -1;
	}

	copy_filep = fopen(copy_path, "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the target file (%s).\n", __func__, copy_path);
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
	/* test end */

	return 0;
}

int main(int argc, char **argv)
{
	printf("%s [1]\n", __func__);

	//filep = fopen("./storage/octopos_partition_0_data", "r+");
	//if (!filep) {
		//printf("%s: Creating partition file.\n", __func__);
		//filep = fopen("./storage/octopos_partition_0_data", "w");
		//fclose(filep);
		//filep = fopen("./storage/octopos_partition_0_data", "r+");
		//if (!filep) {
	//		printf("Error: %s: Couldn't create/open the partition file.\n", __func__);
	//		return -1;
		//}
	//}

	/* create new file or delete existing file */
	filep = fopen("./storage/octopos_partition_0_data", "w");
	if (!filep) {
		printf("Error: %s: Couldn't open the partition file (w).\n", __func__);
		return -1;
	}
	fclose(filep);

	/* open for read and write */
	filep = fopen("./storage/octopos_partition_0_data", "r+");
	if (!filep) {
		printf("Error: %s: Couldn't open the partition file (r+).\n", __func__);
		return -1;
	}

	total_blocks += DIR_DATA_NUM_BLOCKS;

	/* FIXME: size hard-coded */
	initialize_file_system(2000);

	copy_file_to_partition((char *) "keyboard.so", (char *) "./keyboard/keyboard.so",
			       1, (char *) "./installer/copy_keyboard.so");
	copy_file_to_partition((char *) "serial_out.so", (char *) "./serial_out/serial_out.so",
			       1, (char *) "./installer/copy_serial_out.so");
	copy_file_to_partition((char *) "storage.so", (char *) "./storage/storage.so",
			       1, (char *) "./installer/copy_storage.so");
	copy_file_to_partition((char *) "os.so", (char *) "./os/os.so",
			       1, (char *) "./installer/copy_os.so");
	
	close_file_system();
	fclose(filep);

	return 0;
}	
