/* octopos application runtime */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>

int fd_out, fd_in, fd_intr;

struct runtime_api {
	int (*request_keyboard_access)(int);
	int (*yield_keyboard_access)(void);
	int (*request_serial_out_access)(int);
	int (*yield_serial_out_access)(void);
	void (*write_to_serial_out)(char *buf);
	void (*read_char_from_keyboard)(char *buf);
};

static char issue_syscall(char syscall_nr)
{
	char opcode[2], interrupt;
	char buf[MAILBOX_QUEUE_MSG_SIZE];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = OS;
	write(fd_out, opcode, 2);
	buf[0] = RUNTIME; /* dummy. format not specified yet. */
	buf[1] = syscall_nr; /* dummy. format not specified yet. */
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	/* wait for response */
	read(fd_intr, &interrupt, 1);
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = RUNTIME;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return buf[0]; /* dummy. format not specified yet. */
}

static int request_keyboard_access(int access_type)
{
	return (int) issue_syscall(2);
}

static int yield_keyboard_access(void)
{
	return (int) issue_syscall(3);
}

static int request_serial_out_access(int access_type)
{
	return (int) issue_syscall(0);
}

static int yield_serial_out_access(void)
{
	return (int) issue_syscall(1);
}

static void write_to_serial_out(char *buf)
{
	char opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = SERIAL_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void read_char_from_keyboard(char *buf)
{
	char input_buf[MAILBOX_QUEUE_MSG_SIZE];
	char opcode[2], interrupt;

	read(fd_intr, &interrupt, 1);
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = KEYBOARD;
	write(fd_out, opcode, 2);
	read(fd_in, input_buf, MAILBOX_QUEUE_MSG_SIZE);
	*buf = input_buf[0];
}

typedef void (*app_main_proc)(struct runtime_api *);

static void load_application(char *msg)
{
	void *app;
	char path[2 * MAILBOX_QUEUE_MSG_SIZE] = "../applications/bin/";
	app_main_proc app_main;
	struct runtime_api api = {
		.request_keyboard_access = request_keyboard_access,
		.yield_keyboard_access = yield_keyboard_access,
		.request_serial_out_access = request_serial_out_access,
		.yield_serial_out_access = yield_serial_out_access,
		.write_to_serial_out = write_to_serial_out,
		.read_char_from_keyboard = read_char_from_keyboard,
	};

	strcat(path, msg);
	strcat(path, ".so");
	printf("opening %s\n", path);

	app = dlopen(path, RTLD_LAZY);
	if (!app) {
		printf("Error: couldn't open app.\n");
		return;
	}
	
	app_main = (app_main_proc) dlsym(app, "app_main");
	if (!app_main) {
		printf("Error: couldn't find app_main symbol\n");
		return;
	}

	(*app_main)(&api);
	return;
}

int main(int argc, char **argv)
{
	char buf[MAILBOX_QUEUE_MSG_SIZE];
	char interrupt, opcode[2];

	mkfifo(FIFO_RUNTIME_OUT, 0666);
	mkfifo(FIFO_RUNTIME_IN, 0666);
	mkfifo(FIFO_RUNTIME_INTR, 0666);

	fd_out = open(FIFO_RUNTIME_OUT, O_WRONLY);
	fd_in = open(FIFO_RUNTIME_IN, O_RDONLY);
	fd_intr = open(FIFO_RUNTIME_INTR, O_RDONLY);
		
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = RUNTIME;
	
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		read(fd_intr, &interrupt, 1);
		write(fd_out, opcode, 2), 
		read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
		load_application(buf);
	}
	
	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_RUNTIME_OUT);
	remove(FIFO_RUNTIME_IN);
	remove(FIFO_RUNTIME_INTR);
}
