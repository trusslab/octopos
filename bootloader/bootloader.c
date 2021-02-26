/* OctopOS bootloader */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#ifndef ARCH_SEC_HW_BOOT
#include <dlfcn.h>
#include <semaphore.h>
#endif
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/syscall.h>

#ifdef ARCH_SEC_HW_BOOT
void init_platform();
void cleanup_platform();
#endif

void prepare_bootloader(char *filename, int argc, char *argv[]);
/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 */
int copy_file_from_boot_partition(char *filename, char *path);
void send_measurement_to_tpm(char *path);

#ifndef ARCH_SEC_HW_BOOT
int main(int argc, char *argv[])
#else
int main()
#endif
{
#ifndef ARCH_SEC_HW_BOOT
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: bootloader init\n", __func__);

	if (argc < 2) {
		fprintf(stderr, "Usage: ``bootloader <executable_name> [parameters]''.\n");
		return -1;
	}

	char *name = argv[1];
#else /* ARCH_SEC_HW_BOOT */

	int runtime_id = 0;
	char *runtime_name[2] = {0};

#ifdef ARCH_SEC_HW_BOOT_STORAGE
	char *name = "storage";
#elif defined(ARCH_SEC_HW_BOOT_KEYBOARD)
	char *name = "keyboard";
#elif defined(ARCH_SEC_HW_BOOT_SERIAL_OUT)
	char *name = "serial_out";
#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_1)
	char *name = "runtime";
	runtime_id = 1;
	runtime_name[0] = '1';
#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_2)
	char *name = "runtime";
	runtime_id = 2;
	runtime_name[0] = '2';
#elif defined(ARCH_SEC_HW_BOOT_OS)
	char *name = "os";
#elif defined(ARCH_SEC_HW_BOOT_NETWORK)
	char *name = "network";
#elif defined(ARCH_SEC_HW_BOOT_LINUX)
	char *name = "linux";
#endif /* ARCH_SEC_HW_BOOT_STORAGE */

#endif /* ARCH_SEC_HW_BOOT */
	char path[128];
	memset(path, 0x0, 128);
	strcpy(path, "./bootloader/");
	strcat(path, name);

#ifndef ARCH_SEC_HW_BOOT
	/* FIXME */
	if (!strcmp(name, "runtime"))
		strcat(path, argv[2]);

	prepare_bootloader(name, argc - 2, argv + 2);
#else
	prepare_bootloader(path, runtime_id, &runtime_name[0]);
#endif

	copy_file_from_boot_partition(name, path);

#ifndef ARCH_SEC_HW_BOOT
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
#else
	/* init_platform() has been called in mailbox_XXX */
	cleanup_platform();
#endif

	return 0;
}
