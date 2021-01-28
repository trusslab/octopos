#ifndef ARCH_SEC_HW

/* The server for the banking app
 *
 * Based on:
 * socket_server.c
 * attest_server.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_rc.h>
#include <openssl/sha.h>
#include <json-c/json.h>
/* octopos header files */
#define APPLICATION
#include <tpm/hash.h>

#define MSG_LENGTH (1 + TPM_AT_ID_LENGTH + TPM_AT_NONCE_LENGTH)

char username[32] = "BANK";
char secret[32] = "SECRET";
char password[32] = "pass";
uint32_t balance = 1000;

uint8_t keyboard_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t serial_out_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t network_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t expected_pcr_digest[TPM_EXTEND_HASH_SIZE];
char expected_pcr_digest_str[(2 * TPM_EXTEND_HASH_SIZE) + 1];

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

static const char *extract_pcr_digest(json_object *jobj)
{
	enum json_type type;
	int found = 0;

	json_object_object_foreach(jobj, key, val) {
		type = json_object_get_type(val);
		if (!strcmp(key, "pcrDigest"))
		    found = 1;

		switch (type) {
		case json_type_string:
			if (found) {
				return json_object_get_string(val);
			}
			break;

		case json_type_object: {
			const char *ret = extract_pcr_digest(val);
			if (ret)
				return ret;
			break;
		}

		default:
			break;
		}

		found = 0;
	}

	return NULL;
}

static int verify_quote(uint8_t *nonce, char *quote_info, uint8_t *signature,
			int size)
{
	FAPI_CONTEXT *context;
	TSS2_RC rc = Fapi_Initialize(&context, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Fapi_Initialize: %s\n", Tss2_RC_Decode(rc));
		return -1;
	}

	rc = Fapi_Provision(context, NULL, NULL, NULL);
	if (rc == TSS2_FAPI_RC_ALREADY_PROVISIONED) {
		fprintf(stdout, "INFO: Profile was provisioned.\n");
	} else if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "ERROR: Fapi_Provision: %s.\n", Tss2_RC_Decode(rc));
		Fapi_Finalize(&context);
		return -1;
	}

	rc = Fapi_VerifyQuote(context, "HS/SRK/AK", nonce, TPM_AT_NONCE_LENGTH,
			      quote_info,
			signature, size, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Fapi_VerifyQuote: %s\n", Tss2_RC_Decode(rc));
		Fapi_Finalize(&context);
		return -1;
	}
		
	fprintf(stdout, "Quote is successfully verified.\n");

	/* FIXME: verify the quote digest. */
	json_object *quote_jobj = json_tokener_parse(quote_info);
	const char *pcr_digest = extract_pcr_digest(quote_jobj); 
	if (!pcr_digest) {
		printf("Error: %s: couldn't find the PCR digest in quote\n",
		       __func__);
		Fapi_Finalize(&context);
		return -1;
	}

	if (strcmp(pcr_digest, expected_pcr_digest_str)) {
		printf("Error: %s: pcr_digest in the quote not verified\n",
		       __func__);
		Fapi_Finalize(&context);
		return -1;
	}

	printf("%s: pcr_digest is successfully verified\n", __func__);
	Fapi_Finalize(&context);

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
	
	/* Keyboard PCR */
	hash_file((char *) "./installer/aligned_keyboard", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, keyboard_pcr);

	/* Serial Out PCR */
	hash_file((char *) "./installer/aligned_serial_out", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, serial_out_pcr);

	/* Network PCR */
	hash_file((char *) "./installer/aligned_network", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, network_pcr);

	/* App PCR: two hashes are extended to PCR in this case. */
	hash_file((char *) "./installer/aligned_runtime", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, temp_hash);
	hash_file((char *) "applications/bank_client/bank_client.so", file_hash);
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

int main(int argc, char *argv[])
{
	int sockfd, newsockfd, portno;
	socklen_t clilen;
	char buffer[32];
	struct sockaddr_in serv_addr, cli_addr;
	int n, ret;
	
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: bank_server init\n", __func__);

	generate_PCR_digests();	

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
	portno = 12346;
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

	int sig_size = quote_buf[0];
	uint8_t signature[256];
	bzero(signature, 256);
	memcpy(signature, quote_buf + 1, sig_size);

	int quote_size = package_size - 1 - sig_size;
	char *quote_info = (char *) malloc(quote_size + 1);
	bzero(quote_info, quote_size + 1);
	memcpy(quote_info, quote_buf + 1 + sig_size, quote_size);

	ret = verify_quote(nonce, quote_info, signature, sig_size);
	if (ret) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		error("ERROR quote verification failed");
	}

	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 3");

	/* Send I/O service PCRs */
	n = write(newsockfd, keyboard_pcr, TPM_EXTEND_HASH_SIZE);
	if (n < 0)
		error("ERROR writing to socket -- keyboard_pcr");

	n = write(newsockfd, serial_out_pcr, TPM_EXTEND_HASH_SIZE);
	if (n < 0)
		error("ERROR writing to socket -- serial_out_pcr");

	n = write(newsockfd, network_pcr, TPM_EXTEND_HASH_SIZE);
	if (n < 0)
		error("ERROR writing to socket -- network_pcr");

	/* Receive username and compare */
	bzero(buffer, 32);
	n = read(newsockfd, buffer, 32);
	if (n < 0)
		error("ERROR reading from socket -- 3");

	printf("Received username (n = %d): %s\n", n, buffer);

	if (strcmp(buffer, username)) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		error("ERROR invalid username");
	}
		
	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 4");

	/* Send the secret */
	n = write(newsockfd, secret, 32);
	if (n < 0)
		error("ERROR writing to socket -- 5");

	/* Receive password and compare */
	bzero(buffer, 32);
	n = read(newsockfd, buffer, 32);
	if (n < 0)
		error("ERROR reading from socket -- 4");

	printf("Received password (n = %d): %s\n", n, buffer);

	if (strcmp(buffer, password)) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		error("ERROR invalid password");
	}
		
	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 6");

	/* Accept and execute command to retrieve balance */
	bzero(buffer, 32);
	n = read(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR reading from socket -- 5");
	
	if (buffer[0] != 1) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		error("ERROR invalid password");
	}
		
	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 7");

	printf("Sending balance: $%d\n", balance);
	n = write(newsockfd, &balance, 4);
	if (n < 0)
		error("ERROR writing to socket -- 8");

	printf("Terminating\n");
	close(newsockfd);
	close(sockfd);

	return 0; 
}
#endif
