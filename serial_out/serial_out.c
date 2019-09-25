/* octopos serial output code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

char fifo[64] = "/tmp/octopos_serial_out";
#define CHANNEL_MSG_SIZE	256

int main(int argc, char **argv)
{
	int fd;
	char buf[CHANNEL_MSG_SIZE];

	mkfifo(fifo, 0666);

	fd = open(fifo, O_RDWR);
	
	while(1) {
		memset(buf, 0x0, CHANNEL_MSG_SIZE);
		read(fd, buf, CHANNEL_MSG_SIZE);
		printf("%s", buf);
		fflush(NULL);
	}
	
	close(fd);
	remove(fifo);
}
