/* OctopOS loader */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>
#include <semaphore.h>
#include <octopos/mailbox.h>
#include <octopos/syscall.h>

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 */
int copy_file_from_boot_partition(char *filename, char *path);

void load(const char *path, int _argc, char *_argv[])
{
	void *handle;
	int (*fptr)(int, char **);

	handle = dlopen(path, RTLD_LAZY);
	if (!handle) {
		printf("Error: couldn't open process.\n");
		return;
	}

	fptr = (int(*)(int, char **)) dlsym(handle, "main");
	if (!fptr) {
		printf("Error: couldn't find main symbol.\n");
		return;
	}

	(*fptr)(_argc, _argv);
}

int main(int argc, char *argv[])
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: loader init\n", __func__);

	if (argc < 2) {
		fprintf(stderr, "Usage: ``loader <executable_name> [parameters]''.\n");
		return -1;
	}

	printf("%s [1]\n", __func__);
	char *name = argv[1];
	char path[128];
	strcpy(path, "./loader/");
	strcat(path, name);
	printf("%s [2]: path = %s\n", __func__, path);

	copy_file_from_boot_partition(name, path);

	load(path, argc - 1, argv + 1);

	return 0;
}
