/* OctopOS keyboard mailbox interface */
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

int fd_out, fd_intr;
sem_t interrupt_keyboard;
pthread_t mailbox_thread;
struct termios orig;

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

uint8_t read_char_from_keyboard(void)
{
	return (uint8_t) getchar();
}

void put_char_on_keyboard_queue(uint8_t kchar)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE], opcode[2];

	sem_wait(&interrupt_keyboard);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_KEYBOARD;
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	buf[0] = kchar;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

/* Initializes the keyboard and its mailbox */
int init_keyboard(void)
{
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
        struct termios now;
        setvbuf(stdout, NULL, _IONBF ,0);

	tcgetattr(0, &orig);
        now=orig;
        now.c_lflag &= ~(ISIG|ICANON|ECHO);
        now.c_cc[VMIN]=1;
        now.c_cc[VTIME]=2;
        tcsetattr(0, TCSANOW, &now);

	return 0;
}

void close_keyboard(void)
{
	tcsetattr(0, TCSANOW, &orig);

	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);

	close(fd_intr);
	close(fd_out);
	remove(FIFO_KEYBOARD_INTR);
	remove(FIFO_KEYBOARD_OUT);
}
