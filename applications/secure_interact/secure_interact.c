/* secure_interact app */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>

/* FIXME: how does the app know the size of the buf? */
char output_buf[64];
int num_chars = 0;
#define secure_printf(fmt, args...) {memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args);	\
				     api->write_to_secure_serial_out(output_buf);}			\

#define insecure_printf(fmt, args...) {memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args);\
				     api->write_to_shell(output_buf, num_chars);}				 \

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	char line[1024];
	int i, size;
	int ret;

	insecure_printf("This is secure_interact speaking.\n");
	insecure_printf("Provide an insecure phrase: ");

	api->read_from_shell(line, &size);
	insecure_printf("Your insecure phrase: %s\n", line);	

	insecure_printf("Switching to secure interaction mode now.\n");

	ret = api->request_secure_keyboard(100);
	if (ret) {
		printf("Error: could not get secure access to keyboard\n");
		insecure_printf("Failed to switch.\n");
		return;
	}
	ret = api->request_secure_serial_out(200);
	if (ret) {
		api->yield_secure_keyboard();
		printf("Error: could not get secure access to serial_out\n");
		insecure_printf("Failed to switch.\n");
		return;
	}
	
	secure_printf("Please enter your secure phrase: ");	

	memset(line, 0x0, 1024);
	for (i = 0; i < 1024; i++) {
		api->read_char_from_secure_keyboard(&line[i]);
		if (line[i] == '\n')
			break;
	}

	secure_printf("\nYour secure phrase is: %s\n", line);	

	api->yield_secure_keyboard();
	api->yield_secure_serial_out();
}
