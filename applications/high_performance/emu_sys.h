#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/runtime.h>

#define MAX_MSG_SIZE	11 	// INT_MAX has 10 digits and 1 for \0
#define N		4 	// Matrix size: N x N
#define MAX_ELEM_VALUE	128

int establish_ipc(struct runtime_api *api, uint8_t target_qid);
void disconnect_ipc(struct runtime_api *api);
void send_msg_on_secure_ipc(struct runtime_api *api, int loc);
int recv_msg_on_secure_ipc(struct runtime_api *api);
void generate_square_matrix(int *matrix);
void print_square_matrix(int *matrix);
int read_memory(struct runtime_api *api, int *matrix, int loc);