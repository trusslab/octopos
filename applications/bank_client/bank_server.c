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
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_rc.h>

#define ID_LENGTH 16
#define NONCE_LENGTH 16
#define MSG_LENGTH (1 + ID_LENGTH + 2 + NONCE_LENGTH)

char username[32] = "BANK";
char secret[32] = "SECRET";
char password[32] = "pass";
uint32_t balance = 1000;

static void error(const char *msg)
{
	perror(msg);
	exit(1);
}

static int check_slot(char* slot)
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
			fprintf(stderr, "Error: Invalid charcter %c.\n", slot[i]);
			return -1;
		}
	}
	
	int tmp = atoi(slot);
	if (tmp <0 || tmp > 23) {
		fprintf(stderr, "Error: Slot %d out of range.\n", tmp);
		return -1;
	}

	return 0;
}

static void gen_random(char* buf, int size)
{
	/* arc4random_buf works on bsd, but need lib to run on linux */
	// arc4random_buf(nonce, NONCE_LENGTH);
	
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
static void gen_attest_payload(char* msg, char* slot, uint8_t* nonce_buf)
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

static int verify_quote(uint8_t* nonce, char* quote_info, uint8_t* signature,
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
		return -1;
	}

	rc = Fapi_VerifyQuote(context, "HS/SRK/AK", nonce, NONCE_LENGTH, quote_info,
			signature, size, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Fapi_VerifyQuote: %s\n", Tss2_RC_Decode(rc));
		return -1;
	}
		
	fprintf(stdout, "Quote is successfully verified.\n");

	Fapi_Finalize(&context);

	return 0;
}

int main(int argc, char *argv[])
{
	int sockfd, newsockfd, portno;
	socklen_t clilen;
	char buffer[32];
	struct sockaddr_in serv_addr, cli_addr;
	int n;
	
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: bank_server init\n", __func__);
	
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
	char pcr_slot[3];
	uint8_t nonce[NONCE_LENGTH];

	bzero(pcr_slot, 3);
	n = read(newsockfd, pcr_slot, 3);
	if (n < 0)
		error("ERROR reading from socket -- 1");

	printf("%s [1]\n", __func__);
	int ret = check_slot(pcr_slot);
	if (ret) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		error("ERROR invalid PCR slot");
	}
	printf("%s [2]\n", __func__);

	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 1");
	printf("%s [3]\n", __func__);

	gen_attest_payload(msg, pcr_slot, nonce);
	n = write(newsockfd, msg, MSG_LENGTH);
	if (n < 0)
		error("ERROR writing to socket -- 2");
	printf("%s [4]\n", __func__);
	
	uint8_t quote_buf[4096];
	bzero(quote_buf, 4096);

	int count = 0;
	uint8_t packet[256];
	int package_size = 0;
	do {
		printf("%s [4.1]\n", __func__);
		bzero(packet, 256);
		n = read(newsockfd, packet, 256);
		printf("%s [4.2]: n = %d\n", __func__, n);
		if (n < 0)
			error("ERROR reading from socket -- 2");

		memcpy(quote_buf + count * 256, packet, 256);
		count += 1;
		package_size += n;
	} while (n > 0 && count < 4);
	printf("%s [5]\n", __func__);

	int sig_size = quote_buf[0];
	uint8_t signature[256];
	bzero(signature, 256);
	memcpy(signature, quote_buf + 1, sig_size);

	int quote_size = package_size - 1 - sig_size;
	char *quote_info = (char *) malloc(quote_size + 1);
	bzero(quote_info, quote_size + 1);
	memcpy(quote_info, quote_buf + 1 + sig_size, quote_size);
	printf("%s [6]\n", __func__);

	ret = verify_quote(nonce, quote_info, signature, sig_size);
	if (ret) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		error("ERROR quote verification failed");
	}
	printf("%s [6.1]\n", __func__);

	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 3");
	printf("%s [7]\n", __func__);

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
