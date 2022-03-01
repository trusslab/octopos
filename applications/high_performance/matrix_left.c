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
	printf("square matrix A with N = %d: \n", N);
	print_square_matrix(matrix);

	for (int i = 0; i < N; i++) {
		for (int j = 0; j < N; j++) {
			for (int k = 0; k < N; k++) {
				result[i * N + j] += read_memory(api, matrix, i * N + k) * read_memory(api, matrix, k * N + j + N * N);
			}
		}
	}

	printf("multiplication result: \n");
	print_square_matrix(result);

	disconnect_ipc(api);
}
