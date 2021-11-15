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
#define BUFFER_LENGTH		(MAILBOX_QUEUE_MSG_SIZE + 2)
#define QUEUE_SIZE		64

#define SHORT_BUFFER		0
#define LARGE_BUFFER		1
#define RET_SUCCESS		0
#define RET_FAILURE		1


int read_from_kernel(int fd, uint8_t *proc_id, uint8_t **buf, size_t *buf_size)
{
	int rc = 0;
	uint8_t receive[BUFFER_LENGTH] = {0};
	size_t retrieved_size = 0;
	size_t trunk_size = 0;

	memset(receive, 0, BUFFER_SIZE);
	rc = read(fd, receive, BUFFER_LENGTH);
	if (ret <= 0) {
		perror("Failed to read the message from the device.");
		return -1;
	}

	*proc_id = receive[0];
	*buf_size = (receive[2] << 8) | receive[3];
	*buf = (uint8_t *) malloc(*buf_size);

	/* If it's a small message, directly copy the size of the message,
	 * or copy the BUFFER_SIZE.
	 */
	trunk_size = (*buf_size > BUFFER_SIZE) ? BUFFER_SIZE : *buf_size;
	memcpy(*buf, receive + 1, trunk_size);
	retrieved_size += trunk_size;

	while (retrieved_size != *buf_size) {
		memset(receive, 0, BUFFER_SIZE);
		rc = read(fd, receive, BUFFER_LENGTH);
		if (ret <= 0) {
			perror("Failed to read the message from the device.");
			free(*buf);
			return -1;
		}

		if ((*buf_size - retrieved_size - BUFFER_SIZE) > 0) {
			trunk_size = BUFFER_SIZE;
		} else {
			trunk_size = *buf_size - retrieved_size;
		}proc_id
		memcpy(*buf + retrieved_size, receive + 1, trunk_size);

		retrieved_size += trunk_size;
	}

	return 0;
}

int write_to_kernel(int fd, uint8_t *buf, size_t buf_size)
{
	int rc = 0;
	uint8_t send[BUFFER_LENGTH] = {0};
	size_t transferred_size = 0;
	size_t trunk_size = 0;

	while (transferred_size != buf_size) {
		memset(send, 0, BUFFER_LENGTH);
		if ((buf_size - transferred_size - BUFFER_LENGTH + 1) > 0) {
			send[0] = LARGE_BUFFER;
			trunk_size = BUFFER_LENGTH - 1;
		} else {
			send[0] = SHORT_BUFFER;
			trunk_size = buf_size - transferred_size;
		}

		memcpy(send + 1, buf + transferred_size, trunk_size);
		rc = write(fd, send, BUFFER_LENGTH);
		if (ret < 0) {
			perror("Failed to write the message to the device.");
			break;
		}

		transferred_size += trunk_size;
	}

	return 0;
}


int main(int argc, char const *argv[])
{
	int fd = -1;
	int rc = 0;
	uint8_t current_proc;
	uint8_t op;
	uint8_t *request;
	size_t request_size;
	uint8_t *response;
	size_t response_size;

	char send[BUFFER_LENGTH] = {0};
	char receive[BUFFER_LENGTH] = {0};
	char *large_send;
	size_t large_send_size = 0;


	// Open the device with read/write access
	fd = open("/dev/octopos_tpm", O_RDWR);
	if (fd < 0) {
		perror("Failed to open the device...");
		return errno;
	}

	while (true) {
		// Read buffer from driver buffer
		rc = read_from_kernel(fd, &current_proc, &request, &request_size);
		if (rc < 0)
			goto again;

		rc = enforce_running_process(current_proc);
		if (rc < 0)
			goto again;

		op = request[0];
		if (op == OP_MEASURE) {
			uint8_t hash_value[TPM_EXTEND_HASH_SIZE];
			memcpy(hash_value, request + 3, TPM_EXTEND_HASH_SIZE);
			rc = tpm_measure_service(hash_value, 0);
			if (rc == TPM2_SUCCESS) {
				response_size = 3;
				response = (uint8_t *) malloc(response_size);
				response[0] = RET_SUCCESS;
			}
		} else if (op == OP_READ) {
			uint32_t pcr_index = (uint32_t) request[3];
			uint8_t send[TPM_EXTEND_HASH_SIZE] = {0};
			rc = tpm_processor_read_pcr(pcr_index, send);
			if (rc == TPM2_SUCCESS) {
				response_size = 3 + TPM_EXTEND_HASH_SIZE;
				response = (uint8_t *) malloc(response_size);
				response[0] = RET_SUCCESS;
				memcpy(response + 3, send, TPM_EXTEND_HASH_SIZE);
			}
		} else if (op == OP_ATTEST) {
			uint8_t nonce[TPM_AT_NONCE_LENGTH];
			size_t pcr_list_size;
			uint32_t *pcr_list;
			uint8_t *signature;
			size_t sig_size;
			char *quote_info;
			size_t quote_size;

			memcpy(nonce, request + 3, TPM_AT_NONCE_LENGTH);
			pcr_list_size = (size_t) request[3 + TPM_AT_NONCE_LENGTH];
			pcr_list = (uint32_t *) malloc(pcr_list_size * sizeof(uint32_t));
			for (size_t i = 0; i < pcr_list_size; i++)
				pcr_list[i] = request[4 + TPM_AT_NONCE_LENGTH +i];

			rc = tpm_attest(nonce, pcr_list, pcr_list_size,
					&signature, &sig_size, &quote_info);
			free(pcr_list);

			if (rc == TPM2_SUCCESS) {
				quote_size = strlen(quote_info);
				response_size = sig_size + quote_size + 7;
				response = (uint8_t *) malloc(response_size);
				response[0] = RET_SUCCESS;
				response[3] = (sig_size >> 8) & 0xFF;
				response[4] = sig_size & 0xFF;
				memcpy(response + 5, signature, sig_size);
				response[5 + sig_size] = (quote_size >> 8) & 0xFF;
				response[6 + sig_size] = quote_size & 0xFF;
				memcpy(response + sig_size + 7, quote_info,
				       quote_size);
			}
		} else if (op == OP_SEAL) {
			uint8_t *key_iv = NULL;
			size_t key_iv_size;

			rc = tpm_get_storage_key(&key_iv, &key_iv_size);
			if (key_iv_size != AES_GEN_SIZE)
				rc = -1;

			if (rc == TPM2_SUCCESS) {
				response_size = 3 + 1 + key_iv_size;
				response = (uint8_t *) malloc(response_size);
				response[0] = RET_SUCCESS;
				response[3] = key_iv_size & 0xFF;
				memcpy(response + 4, key_iv, key_iv_size);
			}
		} else if (op == OP_RESET) {
			size_t pcr_list_size;
			uint32_t *pcr_list;

			pcr_list_size = (size_t) request[3];
			pcr_list = (uint32_t *) malloc(pcr_list_size * sizeof(uint32_t));
			for (size_t i = 0; i < pcr_list_size; i++)
				pcr_list[i] = (uint32_t) request[4 + i];

			rc = tpm_reset_pcrs(pcr_list, pcr_list_size);
			free(pcr_list);
			if (rc == TPM2_SUCCESS) {
				response_size = 3;
				response = (uint8_t *) malloc(response_size);
				response[0] = RET_SUCCESS;
			}
		} else {
			perror("Unrecognizable operator.");
			goto again;
		}

		if (rc != TPM2_SUCCESS) {
			response_size = 7;
			response = (uint8_t *) malloc(response_size);
			response[0] = RET_FAILURE;
			response[3] = (rc >> 24) & 0xFF;
			response[4] = (rc >> 16) & 0xFF;
			response[5] = (rc >> 8) & 0xFF;
			response[6] = rc & 0xFF;
		}

		rc = write_to_kernel(fd, response, response_size);
again:
		if (request != NULL)
			free(request);
		if (response != NULL)
			free(response);
		cancel_running_process();
		memset(send, 0, BUFFER_LENGTH);
	}

	rc = close(fd);
	if (ret != 0) {
		perror("Failed to close the device...");
		return errno;
	}

	return 0;
}
