/* OctopOS bootloader */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <octopos/mailbox.h>
#include <octopos/syscall.h>

void prepare_bootloader(char *filename, int argc, char *argv[]);
/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 */
int copy_file_from_boot_partition(char *filename, char *path);
void send_measurement_to_tpm(char *path);

int main(int argc, char *argv[])
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: bootloader init\n", __func__);

	if (argc < 2) {
		fprintf(stderr, "Usage: ``bootloader <executable_name> [parameters]''.\n");
		return -1;
	}

	char *name = argv[1];
	char path[128];
	memset(path, 0x0, 128);
	strcpy(path, "./bootloader/");
	strcat(path, name);
	/* FIXME */
	if (!strcmp(name, "runtime"))
		strcat(path, argv[2]);

	prepare_bootloader(name, argc - 2, argv + 2);
	copy_file_from_boot_partition(name, path);

		
	/* Add exec permission for the copied file */
	chmod(path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);

	send_measurement_to_tpm(path);
	
	/* FIXME */
	if (!strcmp(name, "runtime")) {

		/* Create the args for execv */
		char new_name[128];
		memset(new_name, 0x0, 128);
		strcpy(new_name, argv[1]);
		strcat(new_name, argv[2]);
		char *const args[] = {new_name, (char *) argv[2], NULL};
		execv(path, args);
	} else if (!strcmp(name, "linux")) {
		char *const args[] = {name, (char *) argv[2], (char *) argv[3], NULL};
		execv(path, args);
	} else {
		char *const args[] = {name, NULL};
		execv(path, args);
	}
	

	return 0;
}
