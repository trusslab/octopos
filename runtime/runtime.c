/* octopos application runtime */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/error.h>

int fd_out, fd_in, fd_intr;

struct runtime_api {
	int (*request_access_keyboard)(int);
	int (*yield_access_keyboard)(void);
	int (*request_access_serial_out)(int);
	int (*yield_access_serial_out)(void);
	void (*write_to_serial_out)(char *buf);
	void (*read_char_from_keyboard)(char *buf);
};

static uint32_t issue_syscall(uint16_t syscall_nr, uint32_t arg0, uint32_t arg1)
{
	uint8_t opcode[2], interrupt;
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = OS;
	write(fd_out, opcode, 2);
	buf[0] = RUNTIME;
	*((uint16_t *) &buf[1]) = syscall_nr;
	*((uint16_t *) &buf[3]) = arg0;
	*((uint16_t *) &buf[7]) = arg1;
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	/* wait for response */
	read(fd_intr, &interrupt, 1);
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = RUNTIME;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return *((uint32_t *) &buf[0]);
}

static int request_access_keyboard(int access_type)
{
	return (int) issue_syscall(REQUEST_ACCESS_KEYBOARD, (uint32_t) access_type, 0);
}

static int yield_access_keyboard(void)
{
	return (int) issue_syscall(YIELD_ACCESS_KEYBOARD, 0, 0);
}

static int request_access_serial_out(int access_type)
{
	return (int) issue_syscall(REQUEST_ACCESS_SERIAL_OUT, (uint32_t) access_type, 0);
}

static int yield_access_serial_out(void)
{
	return (int) issue_syscall(YIELD_ACCESS_SERIAL_OUT, 0, 0);
}

static void write_to_serial_out(char *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = SERIAL_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, (uint8_t *) buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void read_char_from_keyboard(char *buf)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t opcode[2], interrupt;

	read(fd_intr, &interrupt, 1);
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = KEYBOARD;
	write(fd_out, opcode, 2);
	read(fd_in, input_buf, MAILBOX_QUEUE_MSG_SIZE);
	*buf = (char) input_buf[0];
}

typedef void (*app_main_proc)(struct runtime_api *);

static void load_application(char *msg)
{
	void *app;
	char path[2 * MAILBOX_QUEUE_MSG_SIZE] = "../applications/bin/";
	app_main_proc app_main;
	struct runtime_api api = {
		.request_access_keyboard = request_access_keyboard,
		.yield_access_keyboard = yield_access_keyboard,
		.request_access_serial_out = request_access_serial_out,
		.yield_access_serial_out = yield_access_serial_out,
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
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t interrupt, opcode[2];

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
		load_application((char *) buf);
	}
	
	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_RUNTIME_OUT);
	remove(FIFO_RUNTIME_IN);
	remove(FIFO_RUNTIME_INTR);
}
