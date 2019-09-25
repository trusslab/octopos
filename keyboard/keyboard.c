/* octopos keyboard code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>

char fifo[64] = "/tmp/octopos_keyboard";
#define CHANNEL_MSG_SIZE	1

int main(int argc, char **argv)
{
	int fd;
	char buf[CHANNEL_MSG_SIZE];

	mkfifo(fifo, 0666);

	fd = open(fifo, O_RDWR);

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
		memset(buf, 0x0, CHANNEL_MSG_SIZE);
		buf[0] = getchar();
		write(fd, buf, sizeof(buf));
		if (buf[0] == 3) { /* ETX */
			printf("^C");
			break;
		}
		//printf("%c", buf[0]);
	}


	tcsetattr(0, TCSANOW, &orig);
	close(fd);
	remove(fifo);
}
