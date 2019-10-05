/* octopos serial output code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>

struct runtime_api {
	int (*request_access_keyboard)(int, int);
	int (*yield_access_keyboard)(void);
	int (*request_access_serial_out)(int, int);
	int (*yield_access_serial_out)(void);
	void (*write_to_serial_out)(char *buf);
	void (*read_char_from_keyboard)(char *buf);
	int (*write_to_file)(char *filename, uint32_t data);
	uint32_t (*read_from_file)(char *filename);
};


/* FIXME: how does the app know the size of the buf? */
char output_buf[64];
#define channel_printf(fmt, args...); sprintf(output_buf, fmt, ##args); api->write_to_serial_out(output_buf);

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	char line[1024];
	int i;
	uint32_t secret = 0;

	api->request_access_keyboard(0, 10);
	api->request_access_serial_out(0, 100);
	
	channel_printf("\nThis is secure login speaking.\n");	
	secret = api->read_from_file((char *) "secret");
	channel_printf("Your secret = %d\n", secret);	

	channel_printf("Please enter your password: ");	

	for (i = 0; i < 1024; i++) {
		api->read_char_from_keyboard(&line[i]);
		if (line[i] == '\n')
			break;
	}

	channel_printf("\nYour password is: %s\n", line);	

	secret = 105;
	channel_printf("Updating your secret to %d\n", secret);	
	api->write_to_file((char *) "secret", secret);

	channel_printf("Secure login terminating.\n");	
	api->yield_access_keyboard();
	api->yield_access_serial_out();
}
