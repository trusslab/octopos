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

void send_thread_msg(struct runtime_api *api, char op, int loc, int val)
{
	char request_msg[MAX_MSG_SIZE];
	request_msg[0] = op;
	sprintf(request_msg + 1, "%10d", loc);
	sprintf(request_msg + 11, "%10d", val);
	api->send_msg_on_secure_ipc(request_msg, MAX_MSG_SIZE);
}

void recv_thread_msg(struct runtime_api *api, char *msg)
{
	int dummy_size;
	char response_msg[MAX_MSG_SIZE];
	api->recv_msg_on_secure_ipc(response_msg, &dummy_size);
	memcpy(msg, response_msg, MAX_MSG_SIZE);
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
