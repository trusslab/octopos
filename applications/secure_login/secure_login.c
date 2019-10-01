/* octopos serial output code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

struct runtime_api {
	int (*request_keyboard_access)(int);
	int (*yield_keyboard_access)(void);
	int (*request_serial_out_access)(int);
	int (*yield_serial_out_access)(void);
	void (*write_to_serial_out)(char *buf);
	void (*read_char_from_keyboard)(char *buf);
};

/* FIXME: how does the app know the size of the buf? */
char output_buf[64];
#define channel_printf(fmt, args...); sprintf(output_buf, fmt, ##args); api->write_to_serial_out(output_buf);

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	char line[1024];
	int i;

	api->request_keyboard_access(0);
	api->request_serial_out_access(0);
	channel_printf("\nThis is secure login speaking.\n");	
	channel_printf("Please enter your password: ");	

	for (i = 0; i < 1024; i++) {
		api->read_char_from_keyboard(&line[i]);
		if (line[i] == '\n')
			break;
	}

	channel_printf("\nYour password is: %s\n", line);	
	channel_printf("Secure login terminating.\n");	
	api->yield_keyboard_access();
	api->yield_serial_out_access();
}
