/* simple_loop app */
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

uint32_t gcounter = 0;

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	/* For context switch */
	uint8_t secure_storage_key[STORAGE_KEY_SIZE];
	
	if (api->get_runtime_proc_id() == 7) {
		/* generate a key */
		for (int i = 0; i < STORAGE_KEY_SIZE; i++)
			secure_storage_key[i] = i + 1;
	} else {
		/* generate a key */
		for (int i = 0; i < STORAGE_KEY_SIZE; i++)
			secure_storage_key[i] = i;
	}
	printf("%s [2]\n", __func__);

	api->set_up_secure_storage_key(secure_storage_key);
	api->set_up_context((void *) &gcounter, 4);	

	while (1) {
		insecure_printf("gcounter = %d\n", gcounter);
		printf("gcounter = %d\n", gcounter);
		sleep(1);	
		gcounter++;
	}
}
