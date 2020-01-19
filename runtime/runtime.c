/* octopos application runtime */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/error.h>


int p_runtime = 0;
int q_runtime = 0;
int q_os = 0;
char fifo_runtime_out[64];
char fifo_runtime_in[64];
char fifo_runtime_intr[64];

#define SYSCALL_SET_ZERO_ARGS(syscall_nr)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	*((uint16_t *) &buf[0]) = syscall_nr;		\

#define SYSCALL_SET_ONE_ARG(syscall_nr, arg0)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	*((uint16_t *) &buf[0]) = syscall_nr;		\
	*((uint32_t *) &buf[2]) = arg0;			\

#define SYSCALL_SET_TWO_ARGS(syscall_nr, arg0, arg1)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	*((uint16_t *) &buf[0]) = syscall_nr;		\
	*((uint32_t *) &buf[2]) = arg0;			\
	*((uint32_t *) &buf[6]) = arg1;			\

#define SYSCALL_SET_THREE_ARGS(syscall_nr, arg0, arg1, arg2)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	*((uint16_t *) &buf[0]) = syscall_nr;			\
	*((uint32_t *) &buf[2]) = arg0;				\
	*((uint32_t *) &buf[6]) = arg1;				\
	*((uint32_t *) &buf[10]) = arg2;			\

#define SYSCALL_SET_ZERO_ARGS_DATA(syscall_nr, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 3;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	*((uint16_t *) &buf[0]) = syscall_nr;					\
	buf[2] = size;								\
	memcpy(&buf[3], (uint8_t *) data, size);				\

#define SYSCALL_SET_ONE_ARG_DATA(syscall_nr, arg0, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 7;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	*((uint16_t *) &buf[0]) = syscall_nr;					\
	*((uint32_t *) &buf[2]) = arg0;						\
	buf[6] = size;								\
	memcpy(&buf[7], (uint8_t *) data, size);				\

#define SYSCALL_SET_TWO_ARGS_DATA(syscall_nr, arg0, arg1, data, size)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 11;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	*((uint16_t *) &buf[0]) = syscall_nr;					\
	*((uint32_t *) &buf[2]) = arg0;						\
	*((uint32_t *) &buf[6]) = arg1;						\
	buf[10] = size;								\
	memcpy(&buf[11], (uint8_t *) data, size);				\

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

#define STORAGE_SET_ZERO_ARGS_DATA(data, size)					\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 2;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	buf[1] = size;								\
	memcpy(&buf[2], (uint8_t *) data, size);				\

#define STORAGE_SET_TWO_ARGS_DATA(arg0, arg1, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
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

/* FIXME: there are a lot of repetition in these macros */
#define IPC_SET_ZERO_ARGS_DATA(data, size)					\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 2;				\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	buf[1] = size;								\
	memcpy(&buf[2], (uint8_t *) data, size);				\

#define IPC_GET_ZERO_ARGS_DATA					\
	uint8_t data_size, *data;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 2;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		return ERR_INVALID;				\
	}							\
	data_size = buf[1];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		return ERR_INVALID;				\
	}							\
	data = &buf[2];

int fd_out, fd_in, fd_intr;

/* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];
sem_t interrupt_change;
int change_queue = 0;

static void issue_syscall(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = q_os;
	sem_wait(&interrupts[q_os]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	/* wait for response */
	sem_wait(&interrupts[q_runtime]);
	/* FIXME: check that it's the right interrupt */
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = q_runtime;
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void issue_syscall_noresponse(uint8_t *buf, bool *no_response)
{
	uint8_t opcode[2];
	*no_response = false;
	int is_change = 0;

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = q_os;
	sem_wait(&interrupts[q_os]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	/* FIXME: the name of this funciton has noresponse in it! */
	/* wait for response */
	sem_wait(&interrupts[q_runtime]);
	sem_getvalue(&interrupt_change, &is_change);
	if (!is_change) {
		opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
		opcode[1] = q_runtime;
		write(fd_out, opcode, 2), 
		read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
	} else { 
		sem_wait(&interrupt_change);
		*no_response = true;
	}
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

static int mailbox_attest_queue_access(uint8_t queue_id, uint8_t access, uint8_t count)
{
	uint8_t opcode[4], ret;

	opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	opcode[3] = count;
	write(fd_out, opcode, 4);
	read(fd_in, &ret, 1);

	return (int) ret; 
}

/* Only to be used for queues that runtime writes to */
/* FIXME: busy-waiting */
static void wait_until_empty(uint8_t queue_id, int queue_size)
{
	int left;
	
	while (1) {
		sem_getvalue(&interrupts[queue_id], &left);
		if (left == queue_size)
			break;
	}
}

static int request_secure_keyboard(int count)
{
	sem_init(&interrupts[Q_KEYBOARD], 0, 0);

	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_SECURE_KEYBOARD, (uint32_t) count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0; 

	int attest_ret = mailbox_attest_queue_access(Q_KEYBOARD,
					READ_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest secure keyboard access\n", __func__);
		return ERR_FAULT;
	}

	return 0; 
}

static int yield_secure_keyboard(void)
{
	mailbox_change_queue_access(Q_KEYBOARD, READ_ACCESS, P_OS);
	return 0;
}

static int request_secure_serial_out(int count)
{
	sem_init(&interrupts[Q_SERIAL_OUT], 0, MAILBOX_QUEUE_SIZE);

	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_SECURE_SERIAL_OUT, (uint32_t) count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0; 

	int attest_ret = mailbox_attest_queue_access(Q_SERIAL_OUT,
					WRITE_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest secure serial_out access\n", __func__);
		return ERR_FAULT;
	}

	return 0; 
}

static int yield_secure_serial_out(void)
{
	wait_until_empty(Q_SERIAL_OUT, MAILBOX_QUEUE_SIZE);

	mailbox_change_queue_access(Q_SERIAL_OUT, WRITE_ACCESS, P_OS);
	return 0;
}

static void write_to_secure_serial_out(char *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_SERIAL_OUT;
	sem_wait(&interrupts[Q_SERIAL_OUT]);
	write(fd_out, opcode, 2);
	write(fd_out, (uint8_t *) buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void read_char_from_secure_keyboard(char *buf)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_KEYBOARD;
	sem_wait(&interrupts[Q_KEYBOARD]);
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

static uint32_t open_file(char *filename, uint32_t mode)
{
	SYSCALL_SET_ONE_ARG_DATA(SYSCALL_OPEN_FILE, mode, filename, strlen(filename))
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

static int write_file_blocks(uint32_t fd, uint8_t *data, int start_block, int num_blocks)
{
	uint8_t opcode[2];

	sem_init(&interrupts[Q_STORAGE_DATA_IN], 0, MAILBOX_QUEUE_SIZE_LARGE);
	SYSCALL_SET_THREE_ARGS(SYSCALL_WRITE_FILE_BLOCKS, fd,
			       (uint32_t) start_block, (uint32_t) num_blocks)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0 == 0)
		return 0;

	uint8_t queue_id = (uint8_t) ret0;
	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;

	for (int i = 0; i < num_blocks; i++) {
		sem_wait(&interrupts[Q_STORAGE_DATA_IN]);
		write(fd_out, opcode, 2);
		write(fd_out, data + (i * STORAGE_BLOCK_SIZE), MAILBOX_QUEUE_MSG_SIZE_LARGE);
	}
	
	return num_blocks;
}

static int read_file_blocks(uint32_t fd, uint8_t *data, int start_block, int num_blocks)
{
	uint8_t opcode[2];

	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
	SYSCALL_SET_THREE_ARGS(SYSCALL_READ_FILE_BLOCKS, fd,
			       (uint32_t) start_block, (uint32_t) num_blocks)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0 == 0)
		return 0;

	uint8_t queue_id = (uint8_t) ret0;
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;

	for (int i = 0; i < num_blocks; i++) {
		sem_wait(&interrupts[Q_STORAGE_DATA_OUT]);
		write(fd_out, opcode, 2);
		read(fd_in, data + (i * STORAGE_BLOCK_SIZE), MAILBOX_QUEUE_MSG_SIZE_LARGE);
	}

	return num_blocks;
}

static int close_file(uint32_t fd)
{
	SYSCALL_SET_ONE_ARG(SYSCALL_CLOSE_FILE, fd)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0;
}

static int remove_file(char *filename)
{
	SYSCALL_SET_ZERO_ARGS_DATA(SYSCALL_REMOVE_FILE, filename, strlen(filename))
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0; 
}

/* FIXME: (mostly) copied from os/mailbox.c */
static int send_msg_to_storage(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_STORAGE_IN_2;
	sem_wait(&interrupts[Q_STORAGE_IN_2]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_OUT_2;
	/* wait for response */
	sem_wait(&interrupts[Q_STORAGE_OUT_2]);
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

static int unlock_secure_storage(uint8_t *key)
{
	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
	buf[0] = STORAGE_OP_UNLOCK;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int set_secure_storage_key(uint8_t *key)
{
	STORAGE_SET_ZERO_ARGS_DATA(key, STORAGE_KEY_SIZE)
	buf[0] = STORAGE_OP_SET_KEY;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int wipe_secure_storage(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	buf[0] = STORAGE_OP_WIPE;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int remove_secure_storage_key(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	buf[0] = STORAGE_OP_REMOVE_KEY;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int request_secure_storage(int count, uint8_t *key)
{
	sem_init(&interrupts[Q_STORAGE_IN_2], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_OUT_2], 0, 0);

	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_SECURE_STORAGE, count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0; 

	/* FIXME: if any of the attetations fail, we should yield the other one */
	int attest_ret = mailbox_attest_queue_access(Q_STORAGE_IN_2,
					WRITE_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest secure storage write access\n", __func__);
		return ERR_FAULT;
	}

	attest_ret = mailbox_attest_queue_access(Q_STORAGE_OUT_2,
					READ_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest secure storage read access\n", __func__);
		return ERR_FAULT;
	}

	/* unlock the storage (mainly needed to deal with reset-related interruptions.
	 * won't do anything if it's the first time accessing the secure storage) */
	int unlock_ret = unlock_secure_storage(key);
	if (!unlock_ret)
		return 0;

	/* if new storage, set the key */
	int set_key_ret = set_secure_storage_key(key);
	return set_key_ret;
}

static int yield_secure_storage(void)
{
	/* wipe storage content */
	int ret = wipe_secure_storage();

	/* if wipe successful, remove the key */
	if (!ret)
		remove_secure_storage_key();

	wait_until_empty(Q_STORAGE_IN_2, MAILBOX_QUEUE_SIZE);

	mailbox_change_queue_access(Q_STORAGE_IN_2, WRITE_ACCESS, P_OS);
	mailbox_change_queue_access(Q_STORAGE_OUT_2, READ_ACCESS, P_OS);
	return 0;
}

static int write_to_secure_storage(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t write_size)
{
	STORAGE_SET_TWO_ARGS_DATA(block_num, block_offset, data, write_size)
	buf[0] = STORAGE_OP_WRITE;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static int read_from_secure_storage(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t read_size)
{
	STORAGE_SET_THREE_ARGS(block_num, block_offset, read_size)
	buf[0] = STORAGE_OP_READ;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET_DATA(data)
	return (int) ret0;
}

static bool secure_ipc_mode = false;
static uint8_t secure_ipc_target_queue = 0;

static int request_secure_ipc(uint8_t target_runtime_queue_id, int count)
{
	bool no_response;
	sem_init(&interrupts[target_runtime_queue_id], 0, MAILBOX_QUEUE_SIZE);
	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_SECURE_IPC, target_runtime_queue_id, count)
	change_queue = target_runtime_queue_id;
	issue_syscall_noresponse(buf, &no_response);
	if (!no_response) {
		/* error */
		SYSCALL_GET_ONE_RET
		return (int) ret0;
	}

	/* FIXME: if any of the attetations fail, we should yield the other one */
	int attest_ret = mailbox_attest_queue_access(target_runtime_queue_id,
					WRITE_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest secure ipc send queue access\n", __func__);
		return ERR_FAULT;
	}

	/* FIXME
	attest_ret = mailbox_attest_queue_access(q_runtime,
					WRITE_ACCESS, count, other runtime);
	if (!attest_ret) {
		printf("%s: Error: failed to attest secure ipc recv queue access\n", __func__);
		return ERR_FAULT;
	}*/

	secure_ipc_mode = true;
	secure_ipc_target_queue = target_runtime_queue_id;

	return 0;
}

static int yield_secure_ipc(void)
{
	uint8_t qid = secure_ipc_target_queue;
	secure_ipc_target_queue = 0;
	secure_ipc_mode = false;

	wait_until_empty(qid, MAILBOX_QUEUE_SIZE);

	mailbox_change_queue_access(qid, WRITE_ACCESS, P_OS);
	mailbox_change_queue_access(q_runtime, WRITE_ACCESS, P_OS);
	return 0;
}

static int send_msg_on_secure_ipc(char *msg, int size)
{
	uint8_t opcode[2];
	if (!secure_ipc_mode)
		return ERR_UNEXPECTED;

	IPC_SET_ZERO_ARGS_DATA(msg, size)
	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = secure_ipc_target_queue;
	sem_wait(&interrupts[secure_ipc_target_queue]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	return 0;
}

static int recv_msg_on_secure_ipc(char *msg, int *size)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = q_runtime;
	/* wait for message */
	sem_wait(&interrupts[q_runtime]);
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
	IPC_GET_ZERO_ARGS_DATA

	memcpy(msg, data, data_size);
	*size = data_size;

	return 0;
}

static uint8_t get_runtime_proc_id(void)
{
	return (uint8_t) p_runtime;	
}

static uint8_t get_runtime_queue_id(void)
{
	return (uint8_t) q_runtime;
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
		.write_file_blocks = write_file_blocks,
		.read_file_blocks = read_file_blocks,
		.close_file = close_file,
		.remove_file = remove_file,
		.request_secure_storage = request_secure_storage,
		.yield_secure_storage = yield_secure_storage,
		.write_to_secure_storage = write_to_secure_storage,
		.read_from_secure_storage = read_from_secure_storage,
		.request_secure_ipc = request_secure_ipc,
		.yield_secure_ipc = yield_secure_ipc,
		.send_msg_on_secure_ipc = send_msg_on_secure_ipc,
		.recv_msg_on_secure_ipc = recv_msg_on_secure_ipc,
		.get_runtime_proc_id = get_runtime_proc_id,
		.get_runtime_queue_id = get_runtime_queue_id,
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
		printf("Error: couldn't find app_main symbol.\n");
		return;
	}

	(*app_main)(&api);
	return;
}

static void *handle_mailbox_interrupts(void *data)
{

	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt < 1 || interrupt > (2 * NUM_QUEUES)) {
			printf("Error: invalid interrupt (%d)\n", interrupt);
			exit(-1);
		}
		if (interrupt > NUM_QUEUES) {
			if ((interrupt - NUM_QUEUES) == change_queue) {
				sem_post(&interrupt_change);
				sem_post(&interrupts[q_runtime]);
			}

			/* ignore the rest */
			continue;
		}
		sem_post(&interrupts[interrupt]);
	}
}

int main(int argc, char **argv)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t opcode[2];
	int runtime_id = -1; 
	pthread_t mailbox_thread;

	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error (runtime): storage data queue msg size must be equal to storage block size\n");
		exit(-1);
	}

	if (argc != 2) {
		printf("Error: incorrect command. Use ``runtime <runtime_ID>''.\n");
		return -1;
	}

	runtime_id = atoi(argv[1]);

	if (runtime_id < 1 || runtime_id > 2) {
		printf("Error: invalid runtime ID.\n");
		return -1;
	}

	switch(runtime_id) {
	case 1:
		p_runtime = P_RUNTIME1;
		q_runtime = Q_RUNTIME1;
		q_os = Q_OS1;
		strcpy(fifo_runtime_out, FIFO_RUNTIME1_OUT);
		strcpy(fifo_runtime_in, FIFO_RUNTIME1_IN);
		strcpy(fifo_runtime_intr, FIFO_RUNTIME1_INTR);
		break;
	case 2:
		p_runtime = P_RUNTIME2;
		q_runtime = Q_RUNTIME2;
		q_os = Q_OS2;
		strcpy(fifo_runtime_out, FIFO_RUNTIME2_OUT);
		strcpy(fifo_runtime_in, FIFO_RUNTIME2_IN);
		strcpy(fifo_runtime_intr, FIFO_RUNTIME2_INTR);
		break;
	default:
		printf("Error: unexpected runtime ID.\n");
		return -1;
	}

	mkfifo(fifo_runtime_out, 0666);
	mkfifo(fifo_runtime_in, 0666);
	mkfifo(fifo_runtime_intr, 0666);

	fd_out = open(fifo_runtime_out, O_WRONLY);
	fd_in = open(fifo_runtime_in, O_RDONLY);
	fd_intr = open(fifo_runtime_intr, O_RDONLY);

	sem_init(&interrupts[q_os], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[q_runtime], 0, 0);

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = q_runtime;
	
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		sem_wait(&interrupts[q_runtime]);
		write(fd_out, opcode, 2), 
		read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
		load_application((char *) buf);
		inform_os_of_termination();
	}
	
	pthread_join(mailbox_thread, NULL);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(fifo_runtime_out);
	remove(fifo_runtime_in);
	remove(fifo_runtime_intr);
}
