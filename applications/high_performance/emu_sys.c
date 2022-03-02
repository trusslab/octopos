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

void send_thread_msg(struct runtime_api *api, int loc, char op)
{
	char request_msg[MAX_MSG_SIZE];
	request_msg[0] = op;
	sprintf(request_msg + 1, "%d", loc);
	api->send_msg_on_secure_ipc(request_msg, MAX_MSG_SIZE);
}

int recv_thread_msg(struct runtime_api *api)
{
	int dummy_size;
	char response_msg[MAX_MSG_SIZE];
	api->recv_msg_on_secure_ipc(response_msg, &dummy_size);
	if (response_msg[0] == OP_THREAD_RESP) {
		return (int) strtol(response_msg + 1, NULL, 10);
	} else if (response_msg[0] == OP_THREAD_EXIT) {
		return -INT_MAX;
	} else {
		printf("%s: Unexpected response message\n", __func__);
		return -INT_MAX;
	}
}

void generate_matrix(int *matrix, int size)
{
	unsigned int randval;
	FILE *f = fopen("/dev/random", "r");
	fread(&randval, sizeof(randval), 1, f);
	fclose(f);

	srand(randval);
	for (int i = 0; i < size; i++) {
		matrix[i] = rand() % MAX_ELEM_VALUE;
	}
}

void print_matrix(int *matrix, int rows, int cols)
{
	for (int i = 0; i < rows; i++) {
		for (int j = 0; j < cols; j++) {
			printf("%5d ", matrix[i * cols + j]);
		}
		printf("\n");
	}
}
