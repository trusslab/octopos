/* octopos serial output code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

enum processors {
	OS = 1,
	KEYBOARD = 2,
	SERIAL_OUT = 3
};

char fifo_out[64] = "/tmp/octopos_mailbox_serial_out_out";
char fifo_in[64] = "/tmp/octopos_mailbox_serial_out_in";
char fifo_intr[64] = "/tmp/octopos_mailbox_serial_out_intr";
#define CHANNEL_MSG_SIZE	64

int main(int argc, char **argv)
{
	int fd_out, fd_in, fd_intr;
	char buf[CHANNEL_MSG_SIZE];
	char interrupt, opcode;

	mkfifo(fifo_out, 0666);
	mkfifo(fifo_in, 0666);
	mkfifo(fifo_intr, 0666);

	fd_out = open(fifo_out, O_WRONLY);
	fd_in = open(fifo_in, O_RDONLY);
	fd_intr = open(fifo_intr, O_RDONLY);
		
	opcode = 0; /* read queue */
	
	while(1) {
		memset(buf, 0x0, CHANNEL_MSG_SIZE);
		read(fd_intr, &interrupt, 1);
		write(fd_out, &opcode, 1), 
		read(fd_in, buf, CHANNEL_MSG_SIZE);
		printf("%s", buf);
		fflush(NULL);
	}
	
	close(fd_out);
	close(fd_in);

	remove(fifo_out);
	remove(fifo_in);
}
