/* ipc_sender app */
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
#define secure_printf(fmt, args...) {memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args);	\
				     api->write_to_secure_serial_out(output_buf);}			\

#define insecure_printf(fmt, args...) {memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args);\
				     api->write_to_shell(output_buf, num_chars);}				 \

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	char line[1024];
	int size;
	uint8_t target_qid = 0;
	uint8_t own_qid = api->get_runtime_queue_id();

	/* receive message */
	int ret = api->read_from_shell(line, &size);
	if (ret || size == 0) {
		printf("Didn't receive a valid response\n");
		return;
	}

	target_qid = line[0];
	printf("Received response: target_qid = %d (size = %d)\n", target_qid, size);

	/* send response */
	insecure_printf("%c", own_qid);

	/* secure IPC */
	ret = api->request_secure_ipc(target_qid, 200);
	if (ret) {
		printf("Couldn't establish secure IPC (ret = %d)\n", ret);
		return;
	}

	char secure_msg[64];
	int secure_msg_size;

	api->recv_msg_on_secure_ipc(secure_msg, &secure_msg_size);
	printf("Received secure msg: %s (size = %d)\n", secure_msg, secure_msg_size);

	strcpy(secure_msg, "secure msg 2");
	secure_msg_size = sizeof("secure msg 2");
	api->send_msg_on_secure_ipc(secure_msg, secure_msg_size);

	api->yield_secure_ipc();
}
