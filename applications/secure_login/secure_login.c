/* secure_login app */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>

#ifdef ARCH_SEC_HW_RUNTIME
#include "arch/sec_hw.h"
#include "arch/app_utilities.h"
#endif

#define APPLICATION
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/mailbox.h>

/* FIXME: how does the app know the size of the buf? */
#ifndef ARCH_SEC_HW
char output_buf[64];
int num_chars = 0;
#define secure_printf(fmt, args...) {memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args);	\
				     api->write_to_secure_serial_out(output_buf);}			\

#define insecure_printf(fmt, args...) {memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args);\
				     api->write_to_shell(output_buf, num_chars);}				 \

#endif

#ifndef ARCH_SEC_HW
extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
#else
void secure_login(struct runtime_api *api)
#endif
{
	char line[1024];
	int i, size;
	uint32_t secret = 0;
	int ret;

	insecure_printf("This is secure login speaking.\n");
	insecure_printf("Provide an insecure phrase:\n");

	api->read_from_shell(line, &size);
	insecure_printf("Your phrase: %s (size = %d)\n", line, size);

	insecure_printf("Switching to secure mode now.\n");

	ret = api->request_secure_keyboard(100, 100, NULL, NULL);
	if (ret) {
		printf("Error: could not get secure access to keyboard\n");
		insecure_printf("Failed to switch.\n");
		return;
	}
	ret = api->request_secure_serial_out(200, 100, NULL, NULL);
	if (ret) {
		api->yield_secure_keyboard();
		printf("Error: could not get secure access to serial_out\n");
		insecure_printf("Failed to switch.\n");
		return;
	}
	
	uint32_t fd = api->open_file((char *) "test_file_1.txt",
				     FILE_OPEN_CREATE_MODE);
	if (fd == 0)
		secure_printf("Couldn't open file (fd = %d)\n", fd);
	api->read_from_file(fd, (uint8_t *) &secret, 4, 0);
	secure_printf("Your secret code = %d\r\n", secret);
	api->write_to_file(fd, (uint8_t *) line, size, 50);

	secure_printf("Please enter your password: ");	

	memset(line, 0x0, 1024);
	for (i = 0; i < 1024; i++) {
		api->read_char_from_secure_keyboard(&line[i]);
#ifdef ARCH_SEC_HW
		if (line[i] == '\r')
#else
		if (line[i] == '\n')
#endif
			break;
	}

	secure_printf("\r\nYour password is: %s\r\n", line);

	secret = 109;
	secure_printf("Updating your secret to %d\r\n", secret);
	api->write_to_file(fd, (uint8_t *) &secret, 4, 0);

	secure_printf("Secure login terminating.\r\n");
	api->yield_secure_keyboard();
	api->yield_secure_serial_out();

	memset(line, 0x0, 1024);
	api->read_from_file(fd, (uint8_t *) line, size, 50);
	insecure_printf("Your secret phrase: %s (size = %d)\n", line, size);
	api->close_file(fd);
	
	insecure_printf("Now testing secure storage\n");
	ret = api->request_secure_storage_access(100, 200,
						 MAILBOX_DEFAULT_TIMEOUT_VAL,
						 NULL, NULL, NULL);
	if (ret) {
		printf("Error: could not get secure access to storage.\n");
		insecure_printf("Error: could not get secure access to "
				"storage.\n");
		return;
	}

	api->write_to_secure_storage_block((uint8_t *) line, 0, 0, size);
	memset(line, 0x0, 1024);
	api->read_from_secure_storage_block((uint8_t *) line, 0, 0, size);
	insecure_printf("secret (from secure storage): %s (size = %d)\n", line,
			size);
	api->delete_and_yield_secure_storage();
}
