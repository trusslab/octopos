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
	int fd;
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE], opcode[2];

	mkfifo(FIFO_KEYBOARD, 0666);

	fd = open(FIFO_KEYBOARD, O_WRONLY);

	/*
	 * put tty in raw mode.
	 * see here:
	 * https://www.unix.com/programming/3690-how-programm-tty-devices-under-unix-platform.html#post12226
	 */
        struct termios orig,now;
        setvbuf(stdout, NULL, _IONBF ,0);

	tcgetattr(0, &orig);
        now=orig;
        now.c_lflag &= ~(ISIG|ICANON|ECHO);
        now.c_cc[VMIN]=1;
        now.c_cc[VTIME]=2;
        tcsetattr(0, TCSANOW, &now);

	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		buf[0] = (uint8_t) getchar();
		opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
		opcode[1] = KEYBOARD;
		write(fd, opcode, 2);
		write(fd, buf, MAILBOX_QUEUE_MSG_SIZE);
		if (buf[0] == 3) { /* ETX */
			printf("^C");
			break;
		}
		//printf("%c", buf[0]);
	}


	tcsetattr(0, TCSANOW, &orig);
	close(fd);
	remove(FIFO_KEYBOARD);
}
