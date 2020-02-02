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
#include <network/sock.h>
#include <network/socket.h>
#include <network/netif.h>
#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/error.h>

typedef int bool;
#define true	(int) 1
#define false	(int) 0

int p_runtime = 0;
int q_runtime = 0;
int q_os = 0;
char fifo_runtime_out[64];
char fifo_runtime_in[64];
char fifo_runtime_intr[64];

uint8_t **syscall_resp_queue;
int srq_size;
int srq_msg_size;
int srq_head;
int srq_tail;
int srq_counter;
sem_t srq_sem;

sem_t load_app_sem;

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
	ret0 = *((uint32_t *) &buf[1]);			\

#define SYSCALL_GET_TWO_RETS				\
	uint32_t ret0, ret1;				\
	ret0 = *((uint32_t *) &buf[1]);			\
	ret1 = *((uint32_t *) &buf[5]);			\

/* FIXME: are we sure data is big enough for the memcpy here? */
#define SYSCALL_GET_ONE_RET_DATA(data)						\
	uint32_t ret0;								\
	uint8_t _size, max_size = MAILBOX_QUEUE_MSG_SIZE - 6;			\
	ret0 = *((uint32_t *) &buf[1]);						\
	if (max_size >= 256) {							\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return ERR_INVALID;						\
	}									\
	_size = buf[5];								\
	if (_size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return ERR_INVALID;						\
	}									\
	memcpy(data, &buf[6], _size);						\

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

unsigned int net_debug = 0;

/* network */
void ip_send_out(struct pkbuf *pkb)
{
	exit(-1);
}

int local_address(unsigned int addr)
{
	exit(-1);
	return 0;
}

struct rtentry *rt_lookup(unsigned int ipaddr)
{
	exit(-1);
	return NULL;
}

void icmp_send(unsigned char type, unsigned char code,
                unsigned int data, struct pkbuf *pkb_in)
{
	exit(-1);
}

int rt_output(struct pkbuf *pkb)
{
	exit(-1);
	return 0;
}

/* FIXME: very similar to write_queue() in mailbox.c */
static int write_syscall_response(uint8_t *buf)
{
	sem_wait(&srq_sem);

	if (srq_counter >= srq_size) {
		printf("Error: syscall response queue is full\n");
		_exit(-1);
		return -1;
	}

	srq_counter++;
	memcpy(syscall_resp_queue[srq_tail], buf, srq_msg_size);
	srq_tail = (srq_tail + 1) % srq_size;

	return 0;
}

/* FIXME: very similar to read_queue() in mailbox.c */
static int read_syscall_response(uint8_t *buf)
{
	if (srq_counter <= 0) {
		printf("Error: syscall response  queue is empty\n");
		exit(-1);
		return -1;
	}

	srq_counter--;
	memcpy(buf, syscall_resp_queue[srq_head], srq_msg_size);
	srq_head = (srq_head + 1) % srq_size;

	sem_post(&srq_sem);

	return 0;
}

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
	read_syscall_response(buf);
}

static void issue_syscall_response_or_change(uint8_t *buf, bool *no_response)
{
	uint8_t opcode[2];
	*no_response = false;
	int is_change = 0;

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = q_os;
	sem_wait(&interrupts[q_os]);
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);

	/* wait for response or a change of queue ownership */
	sem_wait(&interrupts[q_runtime]);
	sem_getvalue(&interrupt_change, &is_change);
	if (!is_change) {
		read_syscall_response(buf);	
	} else { 
		sem_wait(&interrupt_change);
		*no_response = true;
	}
}

//static void issue_syscall_noresponse(uint8_t *buf)
//{
//	uint8_t opcode[2];
//
//	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
//	opcode[1] = q_os;
//	sem_wait(&interrupts[q_os]);
//	write(fd_out, opcode, 2);
//	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
//}

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

static int inform_os_of_pause(void)
{
	SYSCALL_SET_ZERO_ARGS(SYSCALL_INFORM_OS_OF_PAUSE)
	//issue_syscall_noresponse(buf);
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0; 

	return 0; 
}

static int inform_os_runtime_ready(void)
{
	SYSCALL_SET_ZERO_ARGS(SYSCALL_INFORM_OS_RUNTIME_READY)
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

static int lock_secure_storage(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	buf[0] = STORAGE_OP_LOCK;
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
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	buf[0] = STORAGE_OP_WIPE;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

uint8_t secure_storage_key[STORAGE_KEY_SIZE];
bool secure_storage_key_set = false;
bool secure_storage_available = false;
bool has_access_to_secure_storage = false;

bool context_set = false;
void *context_addr = NULL;
uint32_t context_size = 0;

/* FIXME: do we need an int return? */
static int set_up_secure_storage_key(uint8_t *key)
{
	memcpy(secure_storage_key, key, STORAGE_KEY_SIZE);
	secure_storage_key_set = true;

	return 0;
}

static int request_secure_storage_creation(uint8_t *returned_key)
{
	SYSCALL_SET_ZERO_ARGS(SYSCALL_REQUEST_SECURE_STORAGE_CREATION)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET_DATA(buf)
	if (ret0)
		return (int) ret0;

	if (_size != STORAGE_KEY_SIZE)
		return ERR_INVALID;

	memcpy(returned_key, buf, STORAGE_KEY_SIZE);

	return 0;
}

static int yield_secure_storage_access(void)
{
	if (!has_access_to_secure_storage) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return ERR_INVALID;
	}

	/* FIXME: what if lock fails? */
	lock_secure_storage();

	has_access_to_secure_storage = false;

	wait_until_empty(Q_STORAGE_IN_2, MAILBOX_QUEUE_SIZE);

	mailbox_change_queue_access(Q_STORAGE_IN_2, WRITE_ACCESS, P_OS);
	mailbox_change_queue_access(Q_STORAGE_OUT_2, READ_ACCESS, P_OS);

	return 0;
}

static int request_secure_storage_access(int count)
{
	if (!secure_storage_key_set) {
		printf("%s: Error: secure storage key not set.\n", __func__);
		return ERR_INVALID;
	}

	sem_init(&interrupts[Q_STORAGE_IN_2], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[Q_STORAGE_OUT_2], 0, 0);

	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_SECURE_STORAGE_ACCESS, count)
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
	has_access_to_secure_storage = true;

	/* unlock the storage (mainly needed to deal with reset-related interruptions.
	 * won't do anything if it's the first time accessing the secure storage) */
	int unlock_ret = unlock_secure_storage(secure_storage_key);
	if (unlock_ret == ERR_EXIST) {
		uint8_t temp_key[STORAGE_KEY_SIZE];
		int create_ret = request_secure_storage_creation(temp_key);
		if (create_ret) {
			yield_secure_storage_access();
			return create_ret;
		}
		int unlock_ret_2 = unlock_secure_storage(temp_key);
		if (unlock_ret_2) {
			yield_secure_storage_access();
			return create_ret;
		}
	} else if (unlock_ret) {
		yield_secure_storage_access();
		return unlock_ret;
	}

	/* if new storage, set the key */
	int set_key_ret = set_secure_storage_key(secure_storage_key);
	if (set_key_ret) {
		yield_secure_storage_access();
		return set_key_ret;
	}

	secure_storage_available = true;
	return 0;
}

static int delete_and_yield_secure_storage(void)
{
	if (!secure_storage_available || !has_access_to_secure_storage) {
		printf("%s: Error: secure storage has not been set up or there is no access\n", __func__);
		return ERR_INVALID;
	}

	secure_storage_available = false;

	/* wipe storage content */
	wipe_secure_storage();

	has_access_to_secure_storage = false;

	wait_until_empty(Q_STORAGE_IN_2, MAILBOX_QUEUE_SIZE);


	mailbox_change_queue_access(Q_STORAGE_IN_2, WRITE_ACCESS, P_OS);
	mailbox_change_queue_access(Q_STORAGE_OUT_2, READ_ACCESS, P_OS);

	SYSCALL_SET_ZERO_ARGS(SYSCALL_DELETE_SECURE_STORAGE)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	return 0;
}

static uint32_t write_to_secure_storage(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t write_size)
{
	if (!secure_storage_available) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return ERR_INVALID;
	}

	STORAGE_SET_TWO_ARGS_DATA(block_num, block_offset, data, write_size)
	buf[0] = STORAGE_OP_WRITE;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET
	return (int) ret0;
}

static uint32_t read_from_secure_storage(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t read_size)
{
	if (!secure_storage_available) {
		printf("%s: Error: secure storage has not been set up\n", __func__);
		return ERR_INVALID;
	}

	STORAGE_SET_THREE_ARGS(block_num, block_offset, read_size)
	buf[0] = STORAGE_OP_READ;
	send_msg_to_storage(buf);
	STORAGE_GET_ONE_RET_DATA(data)
	return (int) ret0;
}

static int set_up_context(void *addr, uint32_t size)
{
	context_addr = addr;
	context_size = size;
	context_set = true;

	/* Now, let's retrieve the context. */
	/* FIXME: we need to store the context in a way to allow us to know if there is none. */
	int ret = request_secure_storage_access(200);
	if (ret) {
		printf("Error (%s): Failed to get secure access to storage.\n", __func__);
		return ret;
	}

	uint32_t rret = read_from_secure_storage((uint8_t *) context_addr, 0, 0, context_size);
	if (rret != context_size)
		printf("%s: No context to use.\n", __func__);

	yield_secure_storage_access();

	return 0;
}

static bool secure_ipc_mode = false;
static uint8_t secure_ipc_target_queue = 0;

static int request_secure_ipc(uint8_t target_runtime_queue_id, int count)
{
	bool no_response;
	sem_init(&interrupts[target_runtime_queue_id], 0, MAILBOX_QUEUE_SIZE);
	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_SECURE_IPC, target_runtime_queue_id, count)
	change_queue = target_runtime_queue_id;
	issue_syscall_response_or_change(buf, &no_response);
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

static struct socket *create_socket(int family, int type, int protocol)
{
	return _socket(family, type, protocol);
}

static int listen_on_socket(struct socket *sock, int backlog)
{
	return _listen(sock, backlog);
}

static void close_socket(struct socket *sock)
{
	_close(sock);
}

static int bind_socket(struct socket *sock, struct sock_addr *skaddr)
{
	return bind_socket(sock, skaddr);
}

static struct socket *accept_connection(struct socket *sock, struct sock_addr *skaddr)
{
	return _accept(sock, skaddr);
}

static int connect_socket(struct socket *sock, struct sock_addr *skaddr)
{
	return _connect(sock, skaddr);
}

static int read_from_socket(struct socket *sock, void *buf, int len)
{
	return _read(sock, buf, len);
}

static int write_to_socket(struct socket *sock, void *buf, int len)
{
	return _write(sock, buf, len);
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
		.set_up_secure_storage_key = set_up_secure_storage_key,
		.request_secure_storage_access = request_secure_storage_access,
		.yield_secure_storage_access = yield_secure_storage_access,
		.delete_and_yield_secure_storage = delete_and_yield_secure_storage,
		.write_to_secure_storage = write_to_secure_storage,
		.read_from_secure_storage = read_from_secure_storage,
		.set_up_context = set_up_context,
		.request_secure_ipc = request_secure_ipc,
		.yield_secure_ipc = yield_secure_ipc,
		.send_msg_on_secure_ipc = send_msg_on_secure_ipc,
		.recv_msg_on_secure_ipc = recv_msg_on_secure_ipc,
		.get_runtime_proc_id = get_runtime_proc_id,
		.get_runtime_queue_id = get_runtime_queue_id,
		.create_socket = create_socket,
		.listen_on_socket = listen_on_socket,
		.close_socket = close_socket,
		.bind_socket = bind_socket,
		.accept_connection = accept_connection,
		.connect_socket = connect_socket,
		.read_from_socket = read_from_socket,
		.write_to_socket = write_to_socket,
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

uint8_t load_buf[MAILBOX_QUEUE_MSG_SIZE - 1];
bool still_running = true;

static void *run_app(void *data)
{
	int ret = inform_os_runtime_ready();
	if (ret) {
		printf("Error (%s): runtime ready notification rejected by the OS\n", __func__);
		still_running = false;
		return NULL;
	}
	sem_wait(&load_app_sem);
	load_application((char *) load_buf);
	still_running = false;
	inform_os_of_termination();

	return NULL;
}

/* FIXME: copied from mailbox.c */
static uint8_t **allocate_memory_for_queue(int queue_size, int msg_size)
{
	uint8_t **messages = (uint8_t **) malloc(queue_size * sizeof(uint8_t *));
	if (!messages) {
		printf("Error: couldn't allocate memory for a queue\n");
		exit(-1);
	}
	for (int i = 0; i < queue_size; i++) {
		messages[i] = (uint8_t *) malloc(msg_size);
		if (!messages[i]) {
			printf("Error: couldn't allocate memory for a queue\n");
			exit(-1);
		}
	}

	return messages;
}

static void *store_context(void *data)
{
	if (!secure_storage_key_set || !context_set) {
		printf("%s: Error: either the secure storage key or context not set\n", __func__);
		return NULL;
	}

	int ret = request_secure_storage_access(200);
	if (ret) {
		printf("Error (%s): Failed to get secure access to storage.\n", __func__);
		return NULL;
	}

	uint32_t wret = write_to_secure_storage((uint8_t *) context_addr, 0, 0, context_size);
	if (wret != context_size)
		printf("Error: couldn't write the context to secure storage.\n");

	yield_secure_storage_access();
	still_running = false;
	inform_os_of_pause();
		
	return NULL;
}

int main(int argc, char **argv)
{
	int runtime_id = -1; 
	pthread_t app_thread, ctx_thread;
	bool has_ctx_thread = false;
	uint8_t interrupt;

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

	/* initialize syscall response queue */
	syscall_resp_queue = allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);
	srq_size = MAILBOX_QUEUE_SIZE;
	srq_msg_size = MAILBOX_QUEUE_MSG_SIZE;
	srq_counter = 0;
	srq_head = 0;
	srq_tail = 0;
	
	sem_init(&srq_sem, 0, MAILBOX_QUEUE_SIZE);

	sem_init(&load_app_sem, 0, 0);

	int ret = pthread_create(&app_thread, NULL, run_app, NULL);
	if (ret) {
		printf("Error: couldn't launch the app thread\n");
		return -1;
	}

	bool keep_polling = true;

	/* interrupt handling loop */
	while (keep_polling) {
		read(fd_intr, &interrupt, 1);
		if (interrupt < 1 || interrupt > (2 * NUM_QUEUES)) {
			printf("Error: invalid interrupt (%d)\n", interrupt);
			exit(-1);
		} else if (interrupt > NUM_QUEUES) {
			if ((interrupt - NUM_QUEUES) == change_queue) {
				sem_post(&interrupt_change);
				sem_post(&interrupts[q_runtime]);
			}

			/* ignore the rest */
			continue;
		} else if (interrupt == q_runtime) {
			uint8_t opcode[2];
			uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

			opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
			opcode[1] = q_runtime;
			write(fd_out, opcode, 2);
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			if (buf[0] == RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG) {
				write_syscall_response(buf);
				sem_post(&interrupts[interrupt]);
				if (!still_running)
					keep_polling = false;
			} else if (buf[0] == RUNTIME_QUEUE_EXEC_APP_TAG) {
				memcpy(load_buf, &buf[1], MAILBOX_QUEUE_MSG_SIZE);
				sem_post(&load_app_sem);
			} else if (buf[0] == RUNTIME_QUEUE_CONTEXT_SWITCH_TAG) {
				//TODO
				pthread_cancel(app_thread);
				pthread_join(app_thread, NULL);
				int ret = pthread_create(&ctx_thread, NULL, store_context, NULL);
				if (ret)
					printf("Error: couldn't launch the app thread\n");
				has_ctx_thread = true;
			}
		} else {
			sem_post(&interrupts[interrupt]);
		}
	}

	if (has_ctx_thread)
		pthread_join(ctx_thread, NULL);

	pthread_join(app_thread, NULL);

	/* FIXME: free the memory allocated for srq */

	/* FIXME: resetting the mailbox needs to be done automatically. */
	uint8_t opcode[2];
	opcode[0] = MAILBOX_OPCODE_RESET;
	write(fd_out, opcode, 2);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(fifo_runtime_out);
	remove(fifo_runtime_in);
	remove(fifo_runtime_intr);
			
	return 0;
}
