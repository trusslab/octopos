#include "emu_sys.h"

int matrix[N * N];
int result[N * N];

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	int ret;
	uint8_t own_qid = api->get_runtime_queue_id();
	ret = establish_ipc((struct runtime_api *) api, 17 - (own_qid - 18));
	if (ret)
		return;

	generate_square_matrix(matrix);
	printf("square matrix B with N = %d: \n", N);
	print_square_matrix(matrix);

	while (true) {
		ret = recv_msg_on_secure_ipc(api);
		if (ret == -1)
			break;
		send_msg_on_secure_ipc(api, read_memory(api, matrix, ret - N * N));
	}

	disconnect_ipc(api);
}
