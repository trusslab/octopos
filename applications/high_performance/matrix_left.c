#include "emu_sys.h"

pthread_mutex_t mem_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t mem_accessible = PTHREAD_COND_INITIALIZER;
pthread_mutex_t ipc_lock = PTHREAD_MUTEX_INITIALIZER;

struct cache_entry cache[CACHE_SIZE];

int matrix_a[N * M];
int matrix_b[N * M];
int result[M * M];
int ipc_val;

int read_memory(struct runtime_api *api, int *matrix, int loc)
{
	if (loc >= N * M) {
		pthread_mutex_lock(&mem_lock);
		send_thread_msg(api, OP_THREAD_READ, loc, 0);
		pthread_cond_wait(&mem_accessible, &mem_lock);
		pthread_mutex_unlock(&mem_lock);
		return ipc_val;
	} else {
		return matrix[loc];
	}
}

void *ipc_handler(void *arg)
{
	int loc, val;
	char msg[MAX_MSG_SIZE];
	char *loc_ptr = msg + 1;
	char *val_ptr = msg + 11;
	struct runtime_api *api = ((struct arg *) arg)->api;

	pthread_mutex_lock(&ipc_lock);
	while (true) {
		recv_thread_msg(api, msg);
		if (msg[0] == OP_THREAD_READ) {
			loc = (int) strtol(loc_ptr, &val_ptr, 10);
			send_thread_msg(api, OP_THREAD_RESP, loc, read_memory(api, matrix_b, loc));
		} else if (msg[0] == OP_THREAD_WRITE) {
			loc = (int) strtol(loc_ptr, &val_ptr, 10);
			val = (int) strtol(val_ptr, NULL, 10);
			result[loc] = val;
		} else if (msg[0] == OP_THREAD_RESP) {
			loc = (int) strtol(loc_ptr, &val_ptr, 10);
			val = (int) strtol(val_ptr, NULL, 10);
			ipc_val = val;
			cache[loc % CACHE_SIZE].loc = loc;
			cache[loc % CACHE_SIZE].val = val;
			pthread_cond_signal(&mem_accessible);
		} else {
			pthread_mutex_unlock(&ipc_lock);
		}
	}
}

void *matrix_multiplication(void *arg)
{
	struct runtime_api *api = ((struct arg *) arg)->api;
	for (int i = 0; i < N; i++) {
		for (int j = 0; j < M; j++) {
			for (int k = 0; k < M; k++) {
				result[i * M + j] += read_memory(api,matrix_a,i * M + k) * read_memory(api,matrix_b,k * M + j);
			}
		}
	}

	/* Waiting for the IPC thread received finish signal */
	send_thread_msg(api, OP_THREAD_EXIT, 0, 0);
	pthread_mutex_lock(&ipc_lock);
	pthread_mutex_unlock(&ipc_lock);

	return NULL;
}

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	uint8_t own_qid = api->get_runtime_queue_id();
	pthread_t handler_thread, multiplication_thread;
	struct arg arguments;
	arguments.api = api;

	if (establish_ipc(api, 17 - (own_qid - 18)))
		return;

	generate_matrix(matrix_a, N * M);
	printf("matrix A top part with %d rows and %d cols: \n", N, M);
	print_matrix(matrix_a, N, M);
	generate_matrix(matrix_b, N * M);
	printf("matrix B top part with %d rows and %d cols: \n", N, M);
	print_matrix(matrix_b, N, M);

	pthread_create(&handler_thread, NULL, ipc_handler, &arguments);
	pthread_create(&multiplication_thread, NULL, matrix_multiplication, &arguments);

	/* Waiting for the calculation thread finished */
	pthread_join(multiplication_thread, NULL);
	pthread_mutex_destroy(&mem_lock);
	pthread_cond_destroy(&mem_accessible);
	pthread_mutex_destroy(&ipc_lock);

	printf("multiplication result: \n");
	print_matrix(result, M, M);
}
