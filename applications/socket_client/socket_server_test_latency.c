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

//int times,timed;
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
	char buffer[256];
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
	bzero(buffer,256);
	n = read(newsockfd,buffer,255);
	if (n < 0)
		error("ERROR reading from socket");
	printf("Here is the first message (n = %d): %s\n", n, buffer);
//	times=clock();
	gettimeofday(&begin, 0);
	n = write(newsockfd,"I",18);
	if (n < 0)
		error("ERROR writing to socket");

	n = read(newsockfd,buffer,255);
	if (n < 0)
		error("ERROR reading from socket");
//	timed=clock();
    	gettimeofday(&end, 0);
//	double diffticks=timed-times;
//	double diffms=(diffticks)/(CLOCKS_PER_SEC/1000);
    	long microseconds = end.tv_usec - begin.tv_usec;
//	printf("Here is the second message (n = %d): %s  time passed= %f \n", n, buffer, diffms);
	printf("Here is the second message (n = %d): %s  time passed= %ld \n", n, buffer, microseconds);
	close(newsockfd);
	close(sockfd);

	return 0; 
}
#endif
