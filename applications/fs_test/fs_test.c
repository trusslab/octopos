/* fs_test app */
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
	uint32_t data = 0;

	insecure_printf("fs_test starting.\n");

	uint32_t fd = api->open_file((char *) "test_file_1.txt", FILE_OPEN_CREATE_MODE);
	if (fd == 0) {
		insecure_printf("Couldn't open file (fd = %d)\n", fd);
		return;
	}
	api->read_from_file(fd, (uint8_t *) &data, 4, 0);
	insecure_printf("data = %d\n", data);
	data++;
	if (data > 10)
		data = 0;
	api->write_to_file(fd, (uint8_t *) &data, 4, 0);
	api->close_file(fd);
	api->remove_file((char *) "test_file_1.txt");
}
