/* octopos mailbox */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/select.h>

char fifo_shell_out[64] = "/tmp/octopos_mailbox_shell_out";
char fifo_shell_in[64] = "/tmp/octopos_mailbox_shell_in";
char fifo_keyboard[64] = "/tmp/octopos_mailbox_keyboard";
char fifo_serial_out[64] = "/tmp/octopos_mailbox_serial_out";

#define OUTPUT_CHANNEL_MSG_SIZE	256
#define INPUT_CHANNEL_MSG_SIZE	1

int main(int argc, char **argv)
{
	int fd_shell_out, fd_shell_in, fd_keyboard, fd_serial_out, nfds;
	fd_set listen_fds;
	char output_buf[OUTPUT_CHANNEL_MSG_SIZE];
	char input_buf[INPUT_CHANNEL_MSG_SIZE];

	mkfifo(fifo_shell_out, 0666);
	mkfifo(fifo_shell_in, 0666);
	mkfifo(fifo_keyboard, 0666);
	mkfifo(fifo_serial_out, 0666);

	fd_shell_out = open(fifo_shell_out, O_RDWR);
	fd_shell_in = open(fifo_shell_in, O_RDWR);
	fd_keyboard = open(fifo_keyboard, O_RDWR);
	fd_serial_out = open(fifo_serial_out, O_RDWR);
	
	FD_ZERO(&listen_fds);

	nfds = fd_keyboard;
	if (fd_shell_out > nfds)
		nfds = fd_shell_out;

	while(1) {
		FD_SET(fd_shell_out, &listen_fds);
		FD_SET(fd_keyboard, &listen_fds);
		if (select(nfds + 1, &listen_fds, NULL, NULL, NULL) < 0) {
			printf("Error: select\n");
			break;
		}
		//printf("[1]\n");

		if (FD_ISSET(fd_shell_out, &listen_fds)) {
			//printf("[2]\n");
			memset(output_buf, 0x0, OUTPUT_CHANNEL_MSG_SIZE);
			read(fd_shell_out, output_buf, OUTPUT_CHANNEL_MSG_SIZE);
			//printf("%s", output_buf);
			write(fd_serial_out, output_buf, OUTPUT_CHANNEL_MSG_SIZE);
		}

		if (FD_ISSET(fd_keyboard, &listen_fds)) {
			//printf("[3]\n");
			memset(input_buf, 0x0, INPUT_CHANNEL_MSG_SIZE);
			read(fd_keyboard, input_buf, INPUT_CHANNEL_MSG_SIZE);
			write(fd_shell_in, input_buf, INPUT_CHANNEL_MSG_SIZE);
		}		
	}
	
	close(fd_shell_out);
	close(fd_shell_in);
	close(fd_keyboard);
	close(fd_serial_out);

	remove(fifo_shell_out);
	remove(fifo_shell_in);
	remove(fifo_keyboard);
	remove(fifo_serial_out);
}
