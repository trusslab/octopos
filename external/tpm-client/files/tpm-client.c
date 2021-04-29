#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "tpm.h"
#include "hash.h"

#define MAILBOX_QUEUE_MSG_SIZE	64
#define BUFFER_LENGTH		(MAILBOX_QUEUE_MSG_SIZE + 1)
#define SHORT_BUFFER		0
#define LARGE_BUFFER		1

int main(int argc, char const *argv[])
{
	uint8_t current_proc, op;
	int ret, fd;
	char send[BUFFER_LENGTH] = {0};
	char receive[BUFFER_LENGTH] = {0};
	char *large_send;
	size_t large_send_size = 0;

	// Open the device with read/write access
	fd = open("/dev/octopos_tpm", O_RDWR);
	if (fd < 0){
		perror("Failed to open the device...");
		return errno;
	}

	while (true) {
		ret = read(fd, receive, BUFFER_LENGTH);
		if (ret < 0) {
			perror("Failed to read the message from the device.");
			continue;
		}

		current_proc = receive[0];
		op = receive[1];

		enforce_running_process(current_proc);
		if (op == OP_MEASURE) {
			uint8_t hash[BUFFER_LENGTH - 2];
			memcpy(&receive[2], hash, BUFFER_LENGTH - 2);
			ret = tpm_measure_service(hash);
			send[0] = SHORT_BUFFER;
		} else if (op == OP_READ) {
			uint32_t pcr_index = (uint32_t) receive[1];
			uint8_t pcr_value[TPM_EXTEND_HASH_SIZE];
			ret = tpm_processor_read_pcr(pcr_index, pcr_value);
			send[0] = SHORT_BUFFER;
			memcpy(send + 1, pcr_value, TPM_EXTEND_HASH_SIZE);
		} else if (op == OP_ATTEST) {
			uint8_t nonce[TPM_AT_NONCE_LENGTH];
			size_t pcr_list_size;
			uint32_t *pcr_list;
			uint8_t *signature;
			size_t sig_size;
			char *quote_info;
			size_t quote_size;
			memcpy(receive + 2, nonce, TPM_AT_NONCE_LENGTH);
			pcr_list_size = (size_t) receive[2 + TPM_AT_NONCE_LENGTH];
			pcr_list = (uint32_t *) malloc(pcr_list_size * sizeof(uint32_t));
			for (size_t i = 0; i < pcr_list_size; i++) {
				pcr_list[i] = receive[3 + TPM_AT_NONCE_LENGTH + i];
			}
			ret = tpm_attest(nonce, pcr_list, pcr_list_size, 
					 &signature, &sig_size, &quote_info);
			free(pcr_list);
			quote_size = strlen((char *) *quote_info);
			large_send_size = sig_size + quote_size;
			large_send = malloc(large_send_size * sizeof(char));
			memcpy(large_send, signature, sig_size);
			memcpy(large_send + sig_size, quote_info, quote_size);
		} else if (op == OP_RESET) {
			size_t pcr_list_size;
			uint32_t *pcr_list;
			pcr_list_size = (size_t) receive[2];
			pcr_list = (uint32_t *) malloc(pcr_list_size * sizeof(uint32_t));
			for (size_t i = 0; i < pcr_list_size; i++) {
				pcr_list[i] = receive[3 + i];
			}
			ret = tpm_reset_pcrs(pcr_list, pcr_list_size);
			send[0] = SHORT_BUFFER;
		} else {
			perror("Unrecognizable operator.");
			cancel_running_process();
			memset(receive, 0, BUFFER_LENGTH);
			continue;
		}

		if (op == OP_ATTEST) {
			size_t times = (large_send_size - 1) / MAILBOX_QUEUE_MSG_SIZE + 1;
			for (size_t i = 0; i < times; i++) {
				if (i != times - 1) {
					send[0] = LARGE_BUFFER;
					memcpy(send + 1, large_send + MAILBOX_QUEUE_MSG_SIZE * i, MAILBOX_QUEUE_MSG_SIZE);
				} else {
					send[0] = SHORT_BUFFER;
					memcpy(send + 1, large_send + MAILBOX_QUEUE_MSG_SIZE * i, large_send_size - MAILBOX_QUEUE_MSG_SIZE * i);
				}
				ret = write(fd, send, BUFFER_LENGTH);
				if (ret < 0) {
					perror("Failed to write the message to the device.");
					break;
				}
				memset(send, 0, BUFFER_LENGTH);
			}
			free(large_send);
			large_send_size = 0;
		} else {
			ret = write(fd, send, BUFFER_LENGTH);
			if (ret < 0) {
				perror("Failed to write the message to the device.");
			}
		}

		cancel_running_process();
		memset(send, 0, BUFFER_LENGTH);
		memset(receive, 0, BUFFER_LENGTH);
	}

	ret = close(fd);
	if (ret != 0) {
		perror("Failed to close the device...");
		return errno;
	}

	return 0;
}
