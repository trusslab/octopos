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

#define BUFFER_LENGTH (MAILBOX_QUEUE_MSG_SIZE + 1)

int main(int argc, char const *argv[])
{
	uint8_t current_proc, op;
	int ret, fd;
	char send[BUFFER_LENGTH] = {0};
	char receive[BUFFER_LENGTH] = {0};

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
			return errno;
		}

		current_proc = receive[0];
		op = receive[1];

		enforce_running_process(current_proc);
		if (op == OP_MEASURE) {
			uint8_t hash[BUFFER_LENGTH - 2];
			memcpy(&receive[2], hash, BUFFER_LENGTH - 2);
			ret = tpm_measure_service(hash);
		} else if (op == OP_READ) {
			uint32_t pcr_index = (uint32_t) receive[1];
			uint8_t pcr_value[TPM_EXTEND_HASH_SIZE];
			ret = tpm_processor_read_pcr(pcr_index, pcr_value);

			memcpy(send + 1, pcr_value, TPM_EXTEND_HASH_SIZE);
		} else if (op == OP_ATTEST) {
			uint8_t nonce[TPM_AT_NONCE_LENGTH];
			size_t pcr_list_size;
			uint32_t *pcr_list;
			uint8_t *signature;
			size_t sig_size;
			char *quote_info;
			memcpy(receive + 2, nonce, TPM_AT_NONCE_LENGTH);
			pcr_list_size = (size_t) receive[2 + TPM_AT_NONCE_LENGTH];
			pcr_list = (uint32_t *) malloc(pcr_list_size * sizeof(uint32_t));
			for (size_t i = 0; i < pcr_list_size; i++) {
				pcr_list[i] = receive[3 + TPM_AT_NONCE_LENGTH + i];
			}
			ret = tpm_attest(nonce, pcr_list, pcr_list_size, 
					 &signature, &sig_size, &quote_info);
			free(pcr_list);

			// memcpy(send + 1, signature, sig_size);
			// memcpy(send + sig_size + 1, quote_info, strlen((char *) *quote_info));
		} else if (op == OP_RESET) {
			size_t pcr_list_size;
			uint32_t *pcr_list;
			pcr_list_size = (size_t) receive[2];
			pcr_list = (uint32_t *) malloc(pcr_list_size * sizeof(uint32_t));
			for (size_t i = 0; i < pcr_list_size; i++) {
				pcr_list[i] = receive[3 + i];
			}
			ret = tpm_reset_pcrs(pcr_list, pcr_list_size);
		} else {
			perror("Unrecognizable operator.");
		}

		send[0] = (char) ret;
		ret = write(fd, send, BUFFER_LENGTH);
		if (ret < 0) {
			perror("Failed to write the message to the device.");
			return errno;
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
