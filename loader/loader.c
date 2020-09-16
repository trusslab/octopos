#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
// #include <arch/mailbox_tpm.h>

void load(char *path, int _argc, char *_argv[]);

void load(char *path, int _argc, char *_argv[])
{
    void *handle;
    int (*fptr)(int, char **);

    // send_measurement_to_queue((uint8_t *)path);

    handle = dlopen(path, RTLD_LAZY);

    fptr = (int(*)(int, char **))dlsym(handle, "main");
    (*fptr)(_argc, _argv);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stdout, "Usage: ``loader <executable_path> [parameters]''.\n");
        return -1;
    }

    char *path = argv[1];
    
    load(path, argc - 1, argv + 1);

    return 0;
}
