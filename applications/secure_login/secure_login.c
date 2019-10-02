/* octopos serial output code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

struct runtime_api {
	int (*request_access_keyboard)(int, int);
	int (*yield_access_keyboard)(void);
	int (*request_access_serial_out)(int, int);
	int (*yield_access_serial_out)(void);
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

	api->request_access_keyboard(1, 10);
	api->request_access_serial_out(1, 100);
	channel_printf("\nThis is secure login speaking.\n");	
	channel_printf("Please enter your password: ");	

	for (i = 0; i < 1024; i++) {
		api->read_char_from_keyboard(&line[i]);
		if (line[i] == '\n')
			break;
	}

	channel_printf("\nYour password is: %s\n", line);	
	channel_printf("Secure login terminating.\n");	
	api->yield_access_keyboard();
	api->yield_access_serial_out();
}
