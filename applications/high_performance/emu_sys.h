#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <pthread.h>
#include <octopos/runtime.h>

#define MAX_MSG_SIZE	12 	// INT_MAX has 10 digits, 1 for \0 and 1 for op
#define N		4
#define M		2 * N	// Matrix size: M x M
#define MAX_ELEM_VALUE	64

#define OP_THREAD_READ	0
#define OP_THREAD_WRITE	1
#define OP_THREAD_RESP	2
#define OP_THREAD_EXIT	3

struct arg {
	struct runtime_api *api;
};

int establish_ipc(struct runtime_api *api, uint8_t target_qid);
void disconnect_ipc(struct runtime_api *api);
void send_thread_msg(struct runtime_api *api, int loc, char op);
int recv_thread_msg(struct runtime_api *api);
void generate_matrix(int *matrix, int size);
void print_matrix(int *matrix, int rows, int cols);
