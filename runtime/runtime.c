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
#include <octopos/runtime.h>

#define SYSCALL_SET_ZERO_ARGS(syscall_nr)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	*((uint16_t *) &buf[1]) = syscall_nr;		\

#define SYSCALL_SET_ONE_ARG(syscall_nr, arg0)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	*((uint16_t *) &buf[1]) = syscall_nr;		\
	*((uint32_t *) &buf[3]) = arg0;			\

#define SYSCALL_SET_TWO_ARGS(syscall_nr, arg0, arg1)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	*((uint16_t *) &buf[1]) = syscall_nr;		\
	*((uint32_t *) &buf[3]) = arg0;			\
	*((uint32_t *) &buf[7]) = arg1;			\

#define SYSCALL_GET_ONE_RET				\
	uint32_t ret0;					\
	ret0 = *((uint32_t *) &buf[0]);			\

int fd_out, fd_in, fd_intr;

static void issue_syscall(uint8_t *buf)
{
	uint8_t opcode[2], interrupt;

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_OS;
	write(fd_out, opcode, 2);
	buf[0] = P_RUNTIME; /* FIXME: can't be set by RUNTIME itself */
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	/* wait for response */
	read(fd_intr, &interrupt, 1);
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_RUNTIME;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id)
{
	uint8_t opcode[4];

	opcode[0] = MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	opcode[3] = proc_id;
	write(fd_out, opcode, 4);
}

static int request_access_keyboard(int access_mode, int count)
{
	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_ACCESS_KEYBOARD, access_mode, count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0; 
}

static int yield_access_keyboard(void)
{
	mailbox_change_queue_access(Q_KEYBOARD, READ_ACCESS, P_OS);
	return 0;
}

static int request_access_serial_out(int access_mode, int count)
{
	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_ACCESS_SERIAL_OUT, access_mode, count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0; 
}

static int yield_access_serial_out(void)
{
	mailbox_change_queue_access(Q_SERIAL_OUT, WRITE_ACCESS, P_OS);
	return 0;
}

static void write_to_serial_out(char *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_SERIAL_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, (uint8_t *) buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void read_char_from_keyboard(char *buf)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t opcode[2], interrupt;

	read(fd_intr, &interrupt, 1);
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_KEYBOARD;
	write(fd_out, opcode, 2);
	read(fd_in, input_buf, MAILBOX_QUEUE_MSG_SIZE);
	*buf = (char) input_buf[0];
}

static int write_to_file(char *filename, uint32_t data)
{
	SYSCALL_SET_ONE_ARG(SYSCALL_WRITE_TO_FILE, data)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0; 

}
static uint32_t read_from_file(char *filename)
{
	SYSCALL_SET_ZERO_ARGS(SYSCALL_READ_FROM_FILE)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return ret0; 
}

//static void write_to_shell(char *buf)
//{
//	//issue_syscall(SYSCALL_WRITE_TO_SHELL, 0, 0);
//
//}
//void (*read_from_shell)(char *buf);

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
		.write_to_file = write_to_file,
		.read_from_file = read_from_file,
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
	opcode[1] = Q_RUNTIME;
	
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
