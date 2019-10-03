/* octopos serial output code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>

int main(int argc, char **argv)
{
	int fd_out, fd_in, fd_intr;
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t interrupt, opcode[2];

	mkfifo(FIFO_SERIAL_OUT_OUT, 0666);
	mkfifo(FIFO_SERIAL_OUT_IN, 0666);
	mkfifo(FIFO_SERIAL_OUT_INTR, 0666);

	fd_out = open(FIFO_SERIAL_OUT_OUT, O_WRONLY);
	fd_in = open(FIFO_SERIAL_OUT_IN, O_RDONLY);
	fd_intr = open(FIFO_SERIAL_OUT_INTR, O_RDONLY);
		
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_SERIAL_OUT;
	
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		read(fd_intr, &interrupt, 1);
		write(fd_out, opcode, 2), 
		read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
		printf("%s", buf);
		fflush(NULL);
	}
	
	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_SERIAL_OUT_OUT);
	remove(FIFO_SERIAL_OUT_IN);
	remove(FIFO_SERIAL_OUT_INTR);
}
