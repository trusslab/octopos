/* octopos keyboard code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <termios.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>

int main(int argc, char **argv)
{
	int fd, fd_intr;
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE * 4], opcode[2];
	uint8_t interrupt;

	mkfifo(FIFO_SENSOR, 0666);
	mkfifo(FIFO_SENSOR_INTR, 0666);

	fd = open(FIFO_SENSOR, O_WRONLY);
	fd_intr = open(FIFO_SENSOR_INTR, O_WRONLY);

        setvbuf(stdout, NULL, _IONBF ,0);

	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		read(fd_intr, &interrupt, 1);

		opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
		opcode[1] = Q_SENSOR;
		write(fd, opcode, 2);
		write(fd, buf , MAILBOX_QUEUE_MSG_SIZE * 4);
		//printf("%c", buf[0]);
	}

	close(fd);
	remove(FIFO_SENSOR);
}
