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
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	*((uint16_t *) &buf[1]) = syscall_nr;		\

#define SYSCALL_SET_ONE_ARG(syscall_nr, arg0)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	*((uint16_t *) &buf[1]) = syscall_nr;		\
	*((uint32_t *) &buf[3]) = arg0;			\

#define SYSCALL_SET_TWO_ARGS(syscall_nr, arg0, arg1)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	*((uint16_t *) &buf[1]) = syscall_nr;		\
	*((uint32_t *) &buf[3]) = arg0;			\
	*((uint32_t *) &buf[7]) = arg1;			\

#define SYSCALL_SET_THREE_ARGS(syscall_nr, arg0, arg1, arg2)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	*((uint16_t *) &buf[1]) = syscall_nr;			\
	*((uint32_t *) &buf[3]) = arg0;				\
	*((uint32_t *) &buf[7]) = arg1;				\
	*((uint32_t *) &buf[11]) = arg2;			\

#define SYSCALL_SET_ZERO_ARGS_DATA(syscall_nr, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 4;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	*((uint16_t *) &buf[1]) = syscall_nr;					\
	buf[3] = size;								\
	memcpy(&buf[4], (uint8_t *) data, size);				\

#define SYSCALL_SET_TWO_ARGS_DATA(syscall_nr, arg0, arg1, data, size)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 12;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	*((uint16_t *) &buf[1]) = syscall_nr;					\
	*((uint32_t *) &buf[3]) = arg0;						\
	*((uint32_t *) &buf[7]) = arg1;						\
	buf[11] = size;								\
	memcpy(&buf[12], (uint8_t *) data, size);				\

#define SYSCALL_GET_ONE_RET				\
	uint32_t ret0;					\
	ret0 = *((uint32_t *) &buf[0]);			\

#define SYSCALL_GET_ONE_RET_DATA(data)						\
	uint32_t ret0;								\
	uint8_t _size, max_size = MAILBOX_QUEUE_MSG_SIZE - 5;			\
	ret0 = *((uint32_t *) &buf[0]);						\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	_size = buf[4];								\
	if (_size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	memcpy(data, &buf[5], _size);						\

/* FIXME: there are a lot of repetition in these macros (also see file_system.c) */
#define STORAGE_SET_THREE_ARGS(arg0, arg1, arg2)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	*((uint32_t *) &buf[1]) = arg0;				\
	*((uint32_t *) &buf[5]) = arg1;				\
	*((uint32_t *) &buf[9]) = arg2;				\


#define STORAGE_SET_TWO_ARGS_DATA(arg0, arg1, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 10;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	*((uint32_t *) &buf[1]) = arg0;						\
	*((uint32_t *) &buf[5]) = arg1;						\
	buf[9] = size;								\
	memcpy(&buf[10], (uint8_t *) data, size);				\

#define STORAGE_GET_ONE_RET				\
	uint32_t ret0;					\
	ret0 = *((uint32_t *) &buf[0]);			\

#define STORAGE_GET_ONE_RET_DATA(data)						\
	uint32_t ret0;								\
	uint8_t _size, max_size = MAILBOX_QUEUE_MSG_SIZE - 5;			\
	ret0 = *((uint32_t *) &buf[0]);						\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	_size = buf[4];								\
	if (_size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	memcpy(data, &buf[5], _size);						\

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

static int mailbox_attest_queue_access(uint8_t queue_id, uint8_t access, uint8_t access_mode, uint8_t count)
{
	uint8_t opcode[5], ret;

	opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	opcode[3] = access_mode;
	opcode[4] = count;
	write(fd_out, opcode, 5);
	read(fd_in, &ret, 1);

	return (int) ret; 
}

static int request_secure_keyboard(int access_mode, int count)
{
	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_SECURE_KEYBOARD, (uint32_t) access_mode, (uint32_t) count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (access_mode == ACCESS_LIMITED_IRREVOCABLE) {
		int attest_ret = mailbox_attest_queue_access(Q_KEYBOARD,
						READ_ACCESS, access_mode, count);
		if (!attest_ret) {
			printf("%s: Error: failed to attest secure keyboard access\n", __func__);
			return ERR_FAULT;
		}
	}

	return (int) ret0; 
}

static int yield_secure_keyboard(void)
{
	mailbox_change_queue_access(Q_KEYBOARD, READ_ACCESS, P_OS);
	return 0;
}

static int request_secure_serial_out(int access_mode, int count)
{
	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_SECURE_SERIAL_OUT, (uint32_t) access_mode, (uint32_t) count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (access_mode == ACCESS_LIMITED_IRREVOCABLE) {
		int attest_ret = mailbox_attest_queue_access(Q_SERIAL_OUT,
						WRITE_ACCESS, access_mode, count);
		if (!attest_ret) {
			printf("%s: Error: failed to attest secure serial_out access\n", __func__);
			return ERR_FAULT;
		}
	}

	return (int) ret0; 
}

static int yield_secure_serial_out(void)
{
	mailbox_change_queue_access(Q_SERIAL_OUT, WRITE_ACCESS, P_OS);
	return 0;
}

static void write_to_secure_serial_out(char *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_SERIAL_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, (uint8_t *) buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void read_char_from_secure_keyboard(char *buf)
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

static int inform_os_of_termination(void)
{
	SYSCALL_SET_ZERO_ARGS(SYSCALL_INFORM_OS_OF_TERMINATION)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0; 
}

static int write_to_shell(char *data, int size)
{
	SYSCALL_SET_ZERO_ARGS_DATA(SYSCALL_WRITE_TO_SHELL, data, size)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0;
}

static int read_from_shell(char *data, int *data_size)
{
	/* FIXME: check the data buf to make sure it is allocated. */
	SYSCALL_SET_ZERO_ARGS(SYSCALL_READ_FROM_SHELL)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET_DATA(data)
	*data_size = (int) _size;
	return (int) ret0;
}

static uint32_t open_file(char *filename)
{
	SYSCALL_SET_ZERO_ARGS_DATA(SYSCALL_OPEN_FILE, filename, strlen(filename))
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return ret0; 
}

static int write_to_file(uint32_t fd, uint8_t *data, int size, int offset)
{
	SYSCALL_SET_TWO_ARGS_DATA(SYSCALL_WRITE_TO_FILE, fd, offset, data, size)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0; 

}

static int read_from_file(uint32_t fd, uint8_t *data, int size, int offset)
{
	SYSCALL_SET_THREE_ARGS(SYSCALL_READ_FROM_FILE, fd, size, offset)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET_DATA(data)
	return (int) ret0; 
}

static int close_file(uint32_t fd)
{
	SYSCALL_SET_ONE_ARG(SYSCALL_CLOSE_FILE, fd)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0;
}

static int request_secure_storage(int access_mode, int count)
{
	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_SECURE_STORAGE, access_mode, count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (access_mode == ACCESS_LIMITED_IRREVOCABLE) {
		int attest_ret = mailbox_attest_queue_access(Q_STORAGE_IN_2,
						WRITE_ACCESS, access_mode, count);
		if (!attest_ret) {
			printf("%s: Error: failed to attest secure storage write access\n", __func__);
			return ERR_FAULT;
		}

		attest_ret = mailbox_attest_queue_access(Q_STORAGE_OUT_2,
						READ_ACCESS, access_mode, count);
		if (!attest_ret) {
			printf("%s: Error: failed to attest secure storage read access\n", __func__);
			return ERR_FAULT;
		}
	}

	return (int) ret0; 
}

int yield_secure_storage(void)
{
	mailbox_change_queue_access(Q_STORAGE_IN_2, WRITE_ACCESS, P_OS);
	mailbox_change_queue_access(Q_STORAGE_OUT_2, READ_ACCESS, P_OS);
	return 0;
}

/* FIXME: (mostly) copied from os/mailbox.c */
int send_msg_to_storage(uint8_t *buf)
{
	uint8_t opcode[2], interrupt;

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_STORAGE_IN_2;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	/* wait for response */
	read(fd_intr, &interrupt, 1);
	if (!(interrupt == Q_STORAGE_OUT_2)) {
		printf("Interrupt from an unexpected queue\n");
		_exit(-1);
		return ERR_UNEXPECTED;
	}

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_OUT_2;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

int write_to_secure_storage(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t write_size)
{
	STORAGE_SET_TWO_ARGS_DATA(block_num, block_offset, data, write_size)
	buf[0] = 0; /* write */
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

int read_from_secure_storage(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t read_size)
{
	STORAGE_SET_THREE_ARGS(block_num, block_offset, read_size)
	buf[0] = 1; /* read */
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET_DATA(data)
	return (int) ret0;
}

typedef void (*app_main_proc)(struct runtime_api *);

static void load_application(char *msg)
{
	void *app;
	char path[2 * MAILBOX_QUEUE_MSG_SIZE] = "../applications/bin/";
	app_main_proc app_main;
	struct runtime_api api = {
		.request_secure_keyboard = request_secure_keyboard,
		.yield_secure_keyboard = yield_secure_keyboard,
		.request_secure_serial_out = request_secure_serial_out,
		.yield_secure_serial_out = yield_secure_serial_out,
		.write_to_secure_serial_out = write_to_secure_serial_out,
		.read_char_from_secure_keyboard = read_char_from_secure_keyboard,
		.write_to_shell = write_to_shell,
		.read_from_shell = read_from_shell,
		.open_file = open_file,
		.write_to_file = write_to_file,
		.read_from_file = read_from_file,
		.close_file = close_file,
		.request_secure_storage = request_secure_storage,
		.yield_secure_storage = yield_secure_storage,
		.write_to_secure_storage = write_to_secure_storage,
		.read_from_secure_storage = read_from_secure_storage,
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
		inform_os_of_termination();
	}
	
	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_RUNTIME_OUT);
	remove(FIFO_RUNTIME_IN);
	remove(FIFO_RUNTIME_INTR);
}
