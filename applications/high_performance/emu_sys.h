#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <pthread.h>
#include <octopos/runtime.h>

/* 1 for op, 10 for location, 10 for value and ending with \0
 * location and value maximum contains 10 characters since INT_MAX has 10 digits
 */
#define MAX_MSG_SIZE	22
#define N		2
#define M		(2 * N)	// Matrix size: M x M
#define MAX_ELEM_VALUE	64

#define CACHE_SIZE	64

#define OP_THREAD_READ	0x01
#define OP_THREAD_WRITE	0x02
#define OP_THREAD_RESP	0x03
#define OP_THREAD_EXIT	0xFF

struct arg {
	struct runtime_api *api;
};

struct cache_entry {
	int loc;
	int val;
	int invalid;
};

int establish_ipc(struct runtime_api *api, uint8_t target_qid);
void disconnect_ipc(struct runtime_api *api);
void send_thread_msg(struct runtime_api *api, char op, int loc, int val);
void recv_thread_msg(struct runtime_api *api, char *msg);
void generate_matrix(int *matrix, int size);
void print_matrix(int *matrix, int rows, int cols);
