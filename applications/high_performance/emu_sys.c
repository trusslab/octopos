#include "emu_sys.h"

int establish_ipc(struct runtime_api *api, uint8_t target_qid)
{
	int ret = api->request_secure_ipc(target_qid, 200, 100, NULL);
	if (ret) {
		printf("%s: Couldn't establish secure IPC (ret = %d)\n",
		       __func__, ret);
		return -1;
	}
	return 0;
}

void disconnect_ipc(struct runtime_api *api)
{
	api->yield_secure_ipc();
}

void send_msg_on_secure_ipc(struct runtime_api *api, int loc)
{
	char request_msg[MAX_MSG_SIZE];
	sprintf(request_msg, "%d", loc);
	api->send_msg_on_secure_ipc(request_msg, MAX_MSG_SIZE);
}

int recv_msg_on_secure_ipc(struct runtime_api *api)
{
	int dummy_size;
	char response_msg[MAX_MSG_SIZE];
	api->recv_msg_on_secure_ipc(response_msg, &dummy_size);
	return (int) strtol(response_msg, NULL, 10);
}

void generate_square_matrix(int *matrix)
{
	unsigned int randval;
	FILE *f = fopen("/dev/random", "r");
	fread(&randval, sizeof(randval), 1, f);
	fclose(f);

	srand(randval);
	for (int i = 0; i < N * N; i++) {
		matrix[i] = rand() % MAX_ELEM_VALUE;
	}
}

void print_square_matrix(int *matrix)
{
	for (int i = 0; i < N; i++) {
		for (int j = 0; j < N; j++) {
			printf("%5d ", matrix[i * N + j]);
		}
		printf("\n");
	}
}

int read_memory(struct runtime_api *api, int *matrix, int loc)
{
	if (loc >= N * N) {
		send_msg_on_secure_ipc(api, loc);
		return recv_msg_on_secure_ipc(api);
	} else {
		return matrix[loc];
	}
}