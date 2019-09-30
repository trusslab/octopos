/* octopos serial output code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

struct runtime_api {
	int (*request_keyboard_access)(int);
	int (*request_serial_out_access)(int);
};

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	printf("This is secure login speaking.\n");	
	api->request_keyboard_access(0);
}
