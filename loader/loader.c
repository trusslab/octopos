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


void load(const char *path, int _argc, char *_argv[])
{
	void *handle;
	int (*fptr)(int, char **);

	handle = dlopen(path, RTLD_LAZY);
	if (!handle) {
		printf("Error: couldn't open process.\n");
		return;
	}

	fptr = (int(*)(int, char **))dlsym(handle, "main");
	if (!fptr) {
		printf("Error: couldn't find main symbol.\n");
		return;
	}

	(*fptr)(_argc, _argv);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: ``loader <executable_path> [parameters]''.\n");
		return -1;
	}

	char *path = argv[1];
	
	load(path, argc - 1, argv + 1);

	return 0;
}
