/* octopos keyboard code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <termios.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>

int fd_intr;
sem_t interrupt_keyboard;

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt != Q_KEYBOARD) {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
		sem_post(&interrupt_keyboard);
	}
}

int main(int argc, char **argv)
{
	int fd_out;
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE], opcode[2];
	pthread_t mailbox_thread;

	mkfifo(FIFO_KEYBOARD_OUT, 0666);
	mkfifo(FIFO_KEYBOARD_INTR, 0666);

	fd_out = open(FIFO_KEYBOARD_OUT, O_WRONLY);
	fd_intr = open(FIFO_KEYBOARD_INTR, O_RDONLY);

	sem_init(&interrupt_keyboard, 0, MAILBOX_QUEUE_SIZE);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

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

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_KEYBOARD;

	while (1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		buf[0] = (uint8_t) getchar();
		sem_wait(&interrupt_keyboard);
		write(fd_out, opcode, 2);
		write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
		if (buf[0] == 3) { /* ETX */
			printf("^C");
			break;
		}
	}

	tcsetattr(0, TCSANOW, &orig);

	pthread_join(mailbox_thread, NULL);

	close(fd_intr);
	close(fd_out);
	remove(FIFO_KEYBOARD_INTR);
	remove(FIFO_KEYBOARD_OUT);
}
