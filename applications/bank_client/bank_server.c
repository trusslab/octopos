#ifndef ARCH_SEC_HW

/* Based on https://courses.cs.washington.edu/courses/cse461/05au/lectures/server.c */
/* A simple server in the internet domain using TCP */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

char username[32] = "BANK";
char secret[32] = "SECRET";
char password[32] = "pass";
uint32_t balance = 1000;

void error(const char *msg)
{
	perror(msg);
	exit(1);
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

	/* Receive username and compare */
	bzero(buffer, 32);
	n = read(newsockfd, buffer, 32);
	if (n < 0)
		error("ERROR reading from socket -- 1");

	printf("Received username (n = %d): %s\n", n, buffer);

	if (strcmp(buffer, username)) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		error("ERROR invalid username");
	}
		
	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 1");

	/* Send the secret */
	n = write(newsockfd, secret, 32);
	if (n < 0)
		error("ERROR writing to socket -- 2");

	/* Receive password and compare */
	bzero(buffer, 32);
	n = read(newsockfd, buffer, 32);
	if (n < 0)
		error("ERROR reading from socket -- 2");

	printf("Received password (n = %d): %s\n", n, buffer);

	if (strcmp(buffer, password)) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		error("ERROR invalid password");
	}
		
	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 3");

	/* Accept and execute command to retrieve balance */
	bzero(buffer, 32);
	n = read(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR reading from socket -- 3");
	
	if (buffer[0] != 1) {
		buffer[0] = 0;
		write(newsockfd, buffer, 1);
		error("ERROR invalid password");
	}
		
	buffer[0] = 1;
	n = write(newsockfd, buffer, 1);
	if (n < 0)
		error("ERROR writing to socket -- 4");

	printf("Sending balance: $%d\n", balance);
	n = write(newsockfd, &balance, 4);
	if (n < 0)
		error("ERROR writing to socket -- 5");

	printf("Terminating\n");
	close(newsockfd);
	close(sockfd);

	return 0; 
}
#endif
