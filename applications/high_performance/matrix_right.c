#include "emu_sys.h"

int matrix_a[N * M];
int matrix_b[M * N];
int cache;

int read_memory(struct runtime_api *api, int *matrix, int loc)
{
	if (loc < N * M) {
		send_thread_msg(api, loc, OP_THREAD_READ);
		return recv_thread_msg(api);
	} else {
		return matrix[loc - N * M];
	}
}

void *ipc_handler(void *arg)
{
	int ret;
	struct runtime_api *api = ((struct arg *) arg)->api;
	uint8_t own_qid = api->get_runtime_queue_id();
	ret = establish_ipc(api, 17 - (own_qid - 18));
	if (ret)
		return NULL;

	while (true) {
		ret = recv_thread_msg(api);
		if (ret == -INT_MAX)
			break;
		send_thread_msg(api, read_memory(api, matrix_b, ret - N * M),  OP_THREAD_RESP);
	}

	disconnect_ipc(api);
}

void *matrix_multiplication(void *arg)
{
	struct runtime_api *api = ((struct arg *) arg)->api;
	for (int i = 0; i < N; i++) {
		for (int j = 0; j < M; j++) {
			for (int k = 0; k < M; k++) {
				cache[i * M + j] += read_memory(api, matrix_a, i * M + k) * read_memory(api, matrix_b, k * M + j);
			}
		}
	}
	return NULL;
}

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	pthread_t handler_thread, multiplication_thread;
	struct arg arguments;

	generate_matrix(matrix_a, N * M);
	printf("matrix A bottom part with %d rows and %d cols: \n", N, M);
	print_matrix(matrix_a, N, M);
	generate_matrix(matrix_b, N * M);
	printf("matrix B bottom part with %d rows and %d cols: \n", N, M);
	print_matrix(matrix_b, N, M);

	arguments.api = api;
	pthread_create(&handler_thread, NULL, ipc_handler, &arguments);
	pthread_create(&multiplication_thread, NULL, matrix_multiplication, &arguments);

	pthread_join(handler_thread, NULL);
	pthread_join(multiplication_thread, NULL);

	pthread_exit(NULL);
}
