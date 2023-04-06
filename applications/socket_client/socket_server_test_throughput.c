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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <time.h>
#include <sys/time.h>

struct timeval begin, end;

void error(const char *msg)
{
	perror(msg);
	exit(1);
}

int main(int argc, char *argv[])
{
	int sockfd, newsockfd, portno;
	socklen_t clilen;
	char buffer[2048];
	struct sockaddr_in serv_addr, cli_addr;
	int n;

	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: socket_server init\n", __func__);

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
	portno = 12345;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		printf("ERROR on binding");
	listen(sockfd, 5);
	clilen = sizeof(cli_addr);
	printf("Waiting for a connection\n");
	newsockfd = accept(sockfd,
			   (struct sockaddr *) &cli_addr,
			   &clilen);
	printf("Received a connection\n");
	if (newsockfd < 0)
		error("ERROR on accept");
	bzero(buffer, 256);
	n = read(newsockfd, buffer, 255);
	if (n < 0)
		error("ERROR reading from socket");
	printf("Here is the first message (n = %d): %s\n", n, buffer);
	gettimeofday(&begin, 0);
	
	/* A customized handshake with the application server */
	n = write(newsockfd, "IIIIIIIIIIIIIIIII", 18);
	if (n < 0)
		printf("ERROR writing to socket");
	int rounds = 2000;
	long seconds, microseconds;
	double diffs, tp;
	for (int i = 0; i < rounds; i++) {
		printf("%d\n\r", i);
		n = read(newsockfd, buffer, 1024);
		if (n < 0)
			printf("ERROR reading from socket");
	}
	gettimeofday(&end, 0);
	seconds = end.tv_sec - begin.tv_sec;
	microseconds = end.tv_usec - begin.tv_usec;
	diffs = (seconds * 1000000 + microseconds) / 1000000.0;
	tp = (256 * rounds) / 1024.0 / 1024.0 / diffs;
	printf("rounds=%d, t_diff=%lf(%ld.%ld), tp=%lfMB/s\n", rounds, diffs, seconds, microseconds, tp);
	close(newsockfd);
	close(sockfd);

	return 0;
}
#endif
