/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef ARCH_SEC_HW

/* The server for the health app
 *
 * Based on:
 * bank_server.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
/* octopos header files */
#define APPLICATION
#include <tpm/hash.h>
#include <tpm/rsa.h>

#define MSG_LENGTH (1 + TPM_AT_ID_LENGTH + TPM_AT_NONCE_LENGTH)
#define TPM2_ATTEST_KEY_HANDLE     0x81000202  /* Attestation Key Handle for common use */


char glucose_monitor_password[32] = "glucose_monitor_password";
char insulin_pump_password[32] = "insulin_pump_password";

uint8_t bluetooth_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t network_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t storage_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t expected_pcr_digest[TPM_EXTEND_HASH_SIZE];
uint8_t expected_pcr_digest_str[(2 * TPM_EXTEND_HASH_SIZE) + 1];
uint8_t app_signature[RSA_SIGNATURE_SIZE];

static void error(const char *msg)
{
	/* FIXME: prints :Success on errors */
	perror(msg);
	exit(1);
}

static void gen_random(char* buf, int size)
{
	FILE* rand_handler = fopen("/dev/urandom", "r");
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
		if (buf[i] < 0)  buf[i] += 128;
	}
}

/* FIXME: update comment below */
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
static void gen_attest_payload(char* msg, uint8_t* nonce_buf)
{
	char uuid[TPM_AT_ID_LENGTH];
	char nonce[TPM_AT_NONCE_LENGTH];

	gen_random(uuid, TPM_AT_ID_LENGTH);
	gen_random(nonce, TPM_AT_NONCE_LENGTH);

	msg[0] = '0';
	memcpy(msg + 1, uuid, TPM_AT_ID_LENGTH);
	memcpy(msg + 1 + TPM_AT_ID_LENGTH, nonce, TPM_AT_NONCE_LENGTH);

	memcpy(nonce_buf, nonce, TPM_AT_NONCE_LENGTH);
}

static int verify_quote(uint8_t* nonce, uint8_t* quote_info, int quote_size, uint8_t* signature, int sig_size)
{
	int rc;
	uint8_t hashed[SHA256_DIGEST_LENGTH];
	TPMT_SIGNATURE sig;
	WOLFTPM2_DEV dev;
	WOLFTPM2_KEY aik;

	rc = wolfTPM2_Init(&dev, NULL, NULL);
	if (rc != TPM_RC_SUCCESS) {
		fprintf(stderr, "Error: TPM initialization failed.\n");
		return rc;
	}

	rc = wolfTPM2_ReadPublicKey(&dev, &aik, TPM2_ATTEST_KEY_HANDLE);
	if (rc) {
		fprintf(stderr, "Error: Failed to read public key from TPM.\n");
		return rc;
	}
	wolfTPM2_SetAuthHandle(&dev, 0, &aik.handle);

	XMEMCPY(&sig, signature, sig_size);
	hash_buffer(quote_info, quote_size, hashed);

	rc = wolfTPM2_VerifyHash(&dev, &aik, sig.signature.rsassa.sig.buffer,
				 sig.signature.rsassa.sig.size, hashed,
				 SHA256_DIGEST_LENGTH);
	if (rc != TPM_RC_SUCCESS) {
		printf("Failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
		return rc;
	}

	wolfTPM2_Shutdown(&dev, 0);
	wolfTPM2_Cleanup(&dev);

	printf("%s: pcr_digest is successfully verified\n", __func__);
	return 0;
}

static void generate_PCR_digests(void)
{
	uint8_t app_pcr[TPM_EXTEND_HASH_SIZE];
	uint8_t file_hash[TPM_EXTEND_HASH_SIZE];
	uint8_t temp_hash[TPM_EXTEND_HASH_SIZE];
	uint8_t *buffers[2];
	uint32_t buffer_sizes[2];
	uint8_t zero_pcr[TPM_EXTEND_HASH_SIZE];
	memset(zero_pcr, 0x0, TPM_EXTEND_HASH_SIZE);

	buffer_sizes[0] = TPM_EXTEND_HASH_SIZE;
	buffer_sizes[1] = TPM_EXTEND_HASH_SIZE;
	
	/* Bluetooth PCR */
	hash_file((char *) "./installer/aligned_bluetooth", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, bluetooth_pcr);

	/* Network PCR */
	hash_file((char *) "./installer/aligned_network", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, network_pcr);

	/* Storage PCR */
	/* We don't use the aligned file for storage since the storage service
	 * measures the actual executable.
	 */
	hash_file((char *) "./storage/storage", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, storage_pcr);

	/* App PCR: two hashes are extended to PCR in this case. */
	hash_file((char *) "./installer/aligned_runtime", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, temp_hash);
	hash_file((char *) "applications/health_client/health_client.so",
		  file_hash);
	buffers[0] = temp_hash;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, app_pcr);

	/* Attestation quote pcr digest: PCR 0 (boot) and 14 (app) */
	/* FIXME: for now, PCR 0 is just a zero buf since we don't extend it. */
	buffers[0] = zero_pcr;
	buffers[1] = app_pcr;
	hash_multiple_buffers(buffers, buffer_sizes, 2, expected_pcr_digest);
	convert_hash_to_str(expected_pcr_digest, expected_pcr_digest_str);
}

static int read_app_signature(void)
{
	FILE *filep;
	uint32_t size;

	filep = fopen((char *) "./installer/health_client_signature", "r");
	if (!filep) {
		printf("Error: %s: Couldn't open ./installer/health_client_"
		       "signature (r).\n", __func__);
		return -1;
	}

	fseek(filep, 0, SEEK_SET);
	size = (uint32_t) fread(app_signature, sizeof(uint8_t),
				 RSA_SIGNATURE_SIZE, filep);
	if (size != RSA_SIGNATURE_SIZE) {
		printf("Error: %s: couldn't read the signature.\n", __func__);
		fclose(filep);
		return -1;
	}

	fclose(filep);

	return 0;
}

int main(int argc, char *argv[])
{
	int sockfd, newsockfd, portno;
	socklen_t clilen;
	char buffer[32];
	struct sockaddr_in serv_addr, cli_addr;
	int n, ret;
	
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: health_server init\n", __func__);

	generate_PCR_digests();	

	ret = read_app_signature();
	if (ret) {
		printf("Error: %s: couldn't read the app signature.\n",
		       __func__);
		return -1;
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
		error("ERROR opening socket");
	int enable = 1;
	/* This will allow us to reuse the port:
	 * https://stackoverflow.com/questions/24194961/how-do-i-use-setsockoptso-reuseaddr
	 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
		error("setsockopt(SO_REUSEADDR) failed");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	portno = 12347;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	if (bind(sockfd, (struct sockaddr *) &serv_addr, 
		 sizeof(serv_addr)) < 0) 
		error("ERROR on binding");
	listen(sockfd,5);
	clilen = sizeof(cli_addr);
	printf("Waiting for a connection\n");
	newsockfd = accept(sockfd,
			   (struct sockaddr *) &cli_addr, 
	                   &clilen);
	printf("Received a connection\n");
	if (newsockfd < 0) 
		error("ERROR on accept");

	/* remote attestation */
	char msg[MSG_LENGTH];
	uint8_t nonce[TPM_AT_NONCE_LENGTH];

	bzero(buffer, 1);
	n = read(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR reading from socket -- 1");

	if (buffer[0] != 1)
		error("ERROR unexpected initial cmd");

	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 1");

	gen_attest_payload(msg, nonce);
	n = write(newsockfd, msg, MSG_LENGTH);
	if (n < 0)
		error("ERROR writing to socket -- 2");
	
	uint8_t quote_buf[4096];
	bzero(quote_buf, 4096);

	int count = 0;
	uint8_t packet[256];
	int package_size = 0;
	do {
		bzero(packet, 256);
		n = read(newsockfd, packet, 256);
		if (n < 0)
			error("ERROR reading from socket -- 2");

		memcpy(quote_buf + count * 256, packet, 256);
		count += 1;
		package_size += n;
	} while (n > 0 && count < 4);

	int sig_size = (quote_buf[0] << 24) | (quote_buf[1] << 16) |
		       (quote_buf[2] << 8) | quote_buf[3];
	uint8_t *signature = (uint8_t *)malloc(sig_size);
	bzero(signature, sig_size);
	memcpy(signature, quote_buf + 4, sig_size);

	int quote_size = package_size - sig_size - 4;
	uint8_t *quote_info = (uint8_t *)malloc(quote_size);
	bzero(quote_info, quote_size);
	memcpy(quote_info, quote_buf + 4 + sig_size, quote_size);

	ret = verify_quote(nonce, quote_info, quote_size, signature, sig_size);
	if (ret) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		free(signature);
		free(quote_info);
		error("ERROR quote verification failed");
	}
	free(signature);
	free(quote_info);

	/* Verification of the quote tells us that our app is running in one
	 * of the runtimes. We can be sure that we're talking to that runtime
	 * since other runtimes won't have the ability to read the PCR for this
	 * runtime.
	 */

	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 3");

	/* Send I/O service PCRs and app signature */
	n = write(newsockfd, bluetooth_pcr, TPM_EXTEND_HASH_SIZE);
	if (n < 0)
		error("ERROR writing to socket -- bluetooth_pcr");

	n = write(newsockfd, storage_pcr, TPM_EXTEND_HASH_SIZE);
	if (n < 0)
		error("ERROR writing to socket -- storage_pcr");

	n = write(newsockfd, network_pcr, TPM_EXTEND_HASH_SIZE);
	if (n < 0)
		error("ERROR writing to socket -- network_pcr");

	n = write(newsockfd, app_signature, RSA_SIGNATURE_SIZE);
	if (n < 0)
		error("ERROR writing to socket -- app_signature");

	/* This is needed for attestation of the network service.
	 * Right after we receive the PCR, we compare it with what we have
	 * from TPM measurements. If they match, we tell the server so that
	 * it can send us secrets or receive confidential information.
	 * Note that the client and server communication is secured end-to-end,
	 * therefore we can trust our message to be delivered correctly and not
	 * delivered at all. Yet, we don't assume that the communications
	 * between the client are secure against side-channels on the client
	 * device. The attestation of the network service tries to defeat that.
	 */
	bzero(buffer, 1);
	n = read(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR reading from socket -- 3");

	if (buffer[0] != 1)
		error("ERROR network service attestation failed on the device");

	/* Send bluetooth device passwords */
	n = write(newsockfd, glucose_monitor_password, 32);
	if (n < 0)
		error("ERROR writing to socket -- glucose_monitor_password");

	n = write(newsockfd, insulin_pump_password, 32);
	if (n < 0)
		error("ERROR writing to socket -- insulin_pump_password");

	printf("Terminating\n");
	close(newsockfd);
	close(sockfd);

	return 0; 
}
#endif
