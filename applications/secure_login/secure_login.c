/* octopos serial output code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/runtime.h>

/* FIXME: how does the app know the size of the buf? */
char output_buf[64];
int num_chars = 0;
#define secure_printf(fmt, args...); memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args); api->write_to_serial_out(output_buf);
#define insecure_printf(fmt, args...); memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args); api->write_to_shell(output_buf, num_chars);

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	char line[1024];
	int i, size;
	uint32_t secret = 0;

	insecure_printf("\nThis is secure login speaking.\n");
	insecure_printf("Provide an insecure phrase:\n");

	api->read_from_shell(line, &size);
	insecure_printf("Your phrase: %s (size = %d)\n", line, size);	

	insecure_printf("Switching to secure mode now.\n");

	api->request_access_keyboard(0, 10);
	api->request_access_serial_out(0, 100);
	
	secret = api->read_from_file((char *) "secret");
	secure_printf("Your secret = %d\n", secret);	

	secure_printf("Please enter your password: ");	

	for (i = 0; i < 1024; i++) {
		api->read_char_from_keyboard(&line[i]);
		if (line[i] == '\n')
			break;
	}

	secure_printf("\nYour password is: %s\n", line);	

	secret = 105;
	secure_printf("Updating your secret to %d\n", secret);	
	api->write_to_file((char *) "secret", secret);

	secure_printf("Secure login terminating.\n");	
	api->yield_access_keyboard();
	api->yield_access_serial_out();
}
