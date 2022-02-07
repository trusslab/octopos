#ifndef ARCH_SEC_HW
/* fs_loop app */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#define APPLICATION
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
	uint32_t data;

	insecure_printf("fs_loop starting.\n");
	printf("fs_loop starting.\n");

	insecure_printf("Test 1\n");

	while (1) {
		printf("Test\n");
		data = 0;

		uint32_t fd1 = api->open_file((char *) "test_file_loop_1.txt", FILE_OPEN_CREATE_MODE);
		if (fd1 == 0) {
			insecure_printf("Couldn't open first file (fd1 = %d)\n", fd1);
			printf("Couldn't open first file (fd1 = %d)\n", fd1);
			return;
		}
		uint32_t fd2 = api->open_file((char *) "test_file_loop_2.txt", FILE_OPEN_CREATE_MODE);
		if (fd1 == 0) {
			api->close_file(fd1);
			insecure_printf("Couldn't open second file (fd2 = %d)\n", fd2);
			printf("Couldn't open second file (fd2 = %d)\n", fd2);
			return;
		}

		data = 13;
		api->write_to_file(fd1, (uint8_t *) &data, 4, 10);
		data = 15;
		api->write_to_file(fd2, (uint8_t *) &data, 4, 10);

		api->read_from_file(fd1, (uint8_t *) &data, 4, 10);
		insecure_printf("data (first file) = %d\n", data);
		printf("data (first file) = %d\n", data);
		if (data != 13) {
			insecure_printf("Test 1 (1) failed\n");
			printf("Test 1 (1) failed\n");
			goto out;
		}
		api->read_from_file(fd2, (uint8_t *) &data, 4, 10);
		insecure_printf("data (first file) = %d\n", data);
		printf("data (first file) = %d\n", data);
		if (data != 15) {
			insecure_printf("Test 1 (2) failed\n");
			printf("Test 1 (2) failed\n");
			goto out;
		}

		insecure_printf("Test 1 passed.\n");
		printf("Test 1 passed.\n");
out:
		api->close_file(fd1);
		api->remove_file((char *) "test_file_loop_1.txt");
		api->close_file(fd2);
		api->remove_file((char *) "test_file_loop_2.txt");
	}
}
#endif
