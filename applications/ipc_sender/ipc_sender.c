/* ipc_sender app */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/runtime.h>

#include "arch/defines.h"
#ifdef ARCH_SEC_HW
#include "arch/sec_hw.h"
#include "arch/app_utilities.h"
#endif

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
void ipc_sender(struct runtime_api *api)
#endif
{
	char line[1024];
	int size;
	uint8_t target_qid = 0;
	uint8_t own_qid = api->get_runtime_queue_id();

#ifdef ARCH_SEC_HW
	_SEC_HW_ERROR("own_qid = %d", own_qid);
#endif

	/* send message */
	insecure_printf("%c", own_qid);

	/* receive response */
	int ret = api->read_from_shell(line, &size);
	if (ret || size == 0) {
#ifndef ARCH_SEC_HW
		printf("Didn't receive a valid response\n");
#else
		_SEC_HW_ERROR("Didn't receive a valid response\n");
#endif
		return;
	}

	target_qid = line[0];
#ifndef ARCH_SEC_HW
	printf("Received response: target_qid = %d (size = %d)\n", target_qid, size);
#else
	_SEC_HW_ERROR("target_qid = %d (size = %d)\n", target_qid, size);
#endif

	/* secure IPC */
	ret = api->request_secure_ipc(target_qid, 200);
	if (ret) {
		printf("Couldn't establish secure IPC (ret = %d)\n", ret);
		return;
	}

	char secure_msg[64] = "secure msg 1";
	int secure_msg_size = sizeof("secure msg 1");
	api->send_msg_on_secure_ipc(secure_msg, secure_msg_size);

	api->recv_msg_on_secure_ipc(secure_msg, &secure_msg_size);
#ifndef ARCH_SEC_HW
	printf("Received secure msg: %s (size = %d)\n", secure_msg, secure_msg_size);
#else
	_SEC_HW_ERROR("msg: %s (size = %d)\n", secure_msg, secure_msg_size);
#endif

	api->yield_secure_ipc();
}
