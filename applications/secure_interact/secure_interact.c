/* secure_interact app */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>

#include "arch/defines.h"
#ifdef ARCH_SEC_HW
#include "arch/sec_hw.h"
#endif

#include <octopos/runtime.h>
#include <octopos/storage.h>

/* FIXME: how does the app know the size of the buf? */
char output_buf[64];
int num_chars = 0;
#define secure_printf(fmt, args...) {memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args);	\
				     api->write_to_secure_serial_out(output_buf);}			\

#ifdef ARCH_SEC_HW

#define insecure_printf(fmt, ...)                                      		\
	do {memset(output_buf, 0x0, 64);  						 			 	\
	num_chars = snprintf(output_buf, 61, fmt "\r\n", ##__VA_ARGS__);		\
	if (num_chars > 61) num_chars = 61;										\
	api->write_to_shell(output_buf, num_chars);} while(0)

#else

#define insecure_printf(fmt, args...) {memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args);\
				     api->write_to_shell(output_buf, num_chars);}				 \

#endif

#ifdef ARCH_UMODE
extern "C" __attribute__ ((visibility ("default")))
#endif
void app_main(struct runtime_api *api)
{
	char line[1024];
	int i, size;
	int ret;

	insecure_printf("This is secure_interact speaking.\n");
	insecure_printf("Provide an insecure phrase: \n");

	api->read_from_shell(line, &size);
	line[size - 1] = '\0';
	insecure_printf("Your insecure phrase: %s\n", line);

	insecure_printf("Switching to secure interaction mode now.\n");

	ret = api->request_secure_keyboard(4093);
	if (ret) {
		printf("Error: could not get secure access to keyboard\n");
		insecure_printf("Failed to switch.\n");
		return;
	}

	insecure_printf("keyboard switched");

	ret = api->request_secure_serial_out(4094);
	if (ret) {
		api->yield_secure_keyboard();
		printf("Error: could not get secure access to serial_out\n");
		insecure_printf("Failed to switch.\n");
		return;
	}
	
	secure_printf("Please enter your secure phrase: \r\n");

	memset(line, 0x0, 1024);
	for (i = 0; i < 1024; i++) {
		api->read_char_from_secure_keyboard(&line[i]);
#ifdef ARCH_SEC_HW
		if (line[i] == '\r') {
#else
		if (line[i] == '\n') {
#endif
			break;
		}
#ifdef ARCH_SEC_HW
		if (line[i] == '\0') {
			i -= 1; // This is to compensate the empty read
		}
#endif
	}

	secure_printf("\nYour secure phrase is: %s\n", line);

	api->yield_secure_keyboard();
	api->yield_secure_serial_out();
}
