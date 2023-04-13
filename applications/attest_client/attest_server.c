/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef ARCH_SEC_HW

/* Based on https://courses.cs.washington.edu/courses/cse461/05au/lectures/server.c */
/* A simple server in the internet domain using TCP */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define ID_LENGTH 16
#define NONCE_LENGTH 16
#define MSG_LENGTH (1 + ID_LENGTH + 2 + NONCE_LENGTH)
#define TPM2_ATTEST_KEY_HANDLE \
	0x81000202 /* Attestation Key Handle for common use */

void error(const char *msg)
{
	perror(msg);
	exit(1);
}

int check_slot(char *slot)
{
	int slot_len = strlen(slot);
	if (slot_len == 1) {
		slot[1] = slot[0];
		slot[0] = '0';
		slot[2] = '\0';
	} else if (slot_len > 2 || slot_len <= 0) {
		fprintf(stderr, "Error: Invalid input %s.\n", slot);
		return -1;
	}

	int i;
	for (i = 0; i < strlen(slot); i++) {
		if (!isdigit(slot[i])) {
			fprintf(stderr, "Error: Invalid charcter %c.\n",
				slot[i]);
			return -1;
		}
	}

	int tmp = atoi(slot);
	if (tmp < 0 || tmp > 40) {
		fprintf(stderr, "Error: Slot %d out of range.\n", tmp);
		return -1;
	}

	return 0;
}

void gen_random(char *buf, int size)
{
	/* arc4random_buf works on bsd, but need lib to run on linux */
	// arc4random_buf(nonce, NONCE_LENGTH);

	FILE *rand_handler = fopen("/dev/urandom", "r");
	if (rand_handler) {
		size_t ret = fread(buf, 1, size, rand_handler);
		if (ret < 0) {
			fprintf(stderr, "Error: Generate Random Error.\n");
		}
	} else {
		fprintf(stderr, "Error: Open uRandom Error.\n");
	}
	fclose(rand_handler);

	for (int i = 0; i < size; i++) {
		if (buf[i] < 0)
			buf[i] += 128;
	}
}

/* Message structure sent to tpm attestor
 * ----------------------------------------
 * |A|B               |C |D               |
 * |1|16              |2 |16              |
 * ----------------------------------------
 * 
 * A: 1 byte length preserve command byte
 * B: 16 bytes length request uuid
 * C: 2 bytes length pcr number
 * D: 16 bytes length nonce
 */
void gen_attest_payload(char *msg, char *slot, uint8_t *nonce_buf)
{
	char uuid[ID_LENGTH];
	char nonce[NONCE_LENGTH];

	gen_random(uuid, ID_LENGTH);
	gen_random(nonce, NONCE_LENGTH);

	msg[0] = '0';
	memcpy(msg + 1, uuid, ID_LENGTH);
	memcpy(msg + 1 + ID_LENGTH, slot, 2);
	memcpy(msg + 1 + ID_LENGTH + 2, nonce, NONCE_LENGTH);

	memcpy(nonce_buf, nonce, NONCE_LENGTH);
}

int hash_buffer(uint8_t *buffer, uint32_t buffer_size, uint8_t *hash_buf)
{
	unsigned int hashLen = 0;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_sha256();

	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, buffer, buffer_size);
	EVP_DigestFinal_ex(mdctx, hash_buf, &hashLen);

	EVP_MD_CTX_free(mdctx);

	return 0;
}

void verify_quote(uint8_t *nonce, uint8_t *quote_info, int quote_size,
		  uint8_t *signature, int sig_size)
{
	int rc;
	uint8_t hashed[SHA256_DIGEST_LENGTH];
	TPMT_SIGNATURE sig;
	WOLFTPM2_DEV dev;
	WOLFTPM2_KEY aik;

	rc = wolfTPM2_Init(&dev, NULL, NULL);
	if (rc != TPM_RC_SUCCESS) {
		fprintf(stderr, "Error: TPM initialization failed.\n");
		return;
	}

	rc = wolfTPM2_ReadPublicKey(&dev, &aik, TPM2_ATTEST_KEY_HANDLE);
	if (rc) {
		fprintf(stderr, "Error: Failed to read public key from TPM.\n");
		return;
	}
	wolfTPM2_SetAuthHandle(&dev, 0, &aik.handle);

	XMEMCPY(&sig, signature, sig_size);
	hash_buffer(quote_info, quote_size, hashed);

	rc = wolfTPM2_VerifyHash(&dev, &aik, sig.signature.rsassa.sig.buffer,
				 sig.signature.rsassa.sig.size, hashed,
				 SHA256_DIGEST_LENGTH);
	if (rc != TPM_RC_SUCCESS) {
		printf("Failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
		return;
	}

	wolfTPM2_Shutdown(&dev, 0);
	wolfTPM2_Cleanup(&dev);
}

int main(int argc, char *argv[])
{
	int sockfd, newsockfd, portno;
	socklen_t clilen;
	char buffer[256];
	struct sockaddr_in serv_addr, cli_addr;
	int n;

	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: attest_server init\n", __func__);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	int enable = 1;
	/* This will allow us to reuse the port:
	 * https://stackoverflow.com/questions/24194961/how-do-i-use-setsockoptso-reuseaddr
	 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) <
	    0)
		error("setsockopt(SO_REUSEADDR) failed");

	bzero((char *)&serv_addr, sizeof(serv_addr));
	portno = 10001;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	listen(sockfd, 5);

	clilen = sizeof(cli_addr);
	printf("Waiting for a connection\n");
	newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
	printf("Received a connection\n");
	if (newsockfd < 0)
		error("ERROR on accept");

	printf("IP address: %s\n", inet_ntoa(cli_addr.sin_addr));
	printf("Port: %d\n", (int)ntohs(cli_addr.sin_port));

	char msg[MSG_LENGTH];
	char pcr_slot[3] = "31";
	uint8_t nonce[NONCE_LENGTH];
	while (1) {
		int ret = check_slot(pcr_slot);
		if (!ret) {
			gen_attest_payload(msg, pcr_slot, nonce);
			n = write(newsockfd, msg, MSG_LENGTH);
			if (n < 0) {
				error("ERROR writing to socket");
				break;
			}

			uint8_t quote_buf[4096];
			bzero(quote_buf, 4096);

			int count = 0;
			uint8_t packet[256];
			int package_size = 0;
			do {
				bzero(packet, 256);
				n = read(newsockfd, packet, 256);
				if (n < 0) {
					error("ERROR reading from socket");
				}
				memcpy(quote_buf + count * 256, packet, 256);
				count += 1;
				package_size += n;
			} while (n > 0 && count < 16);

			int sig_size = (quote_buf[0] << 24) |
				       (quote_buf[1] << 16) |
				       (quote_buf[2] << 8) | quote_buf[3];
			uint8_t *signature = (uint8_t *)malloc(sig_size);
			bzero(signature, sig_size);
			memcpy(signature, quote_buf + 4, sig_size);

			int quote_size = package_size - sig_size - 4;
			uint8_t *quote_info = (uint8_t *)malloc(quote_size);
			bzero(quote_info, quote_size);
			memcpy(quote_info, quote_buf + 4 + sig_size,
			       quote_size);

			verify_quote(nonce, quote_info, quote_size, signature,
				     sig_size);

			free(signature);
			free(quote_info);
			break;
		} else {
			printf("Reprint PCR Bank.\n");
		}
	}

	close(newsockfd);
	close(sockfd);

	return 0;
}
#endif
