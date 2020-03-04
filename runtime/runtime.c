/* octopos application runtime */
#include <stdio.h>
#include <string.h>
#ifdef ARCH_UMODE
#include <fcntl.h>
#endif
#include <unistd.h>
#include <stdint.h>

#ifdef ARCH_UMODE
#include <dlfcn.h>
#endif

#include <stdlib.h>
#ifdef ARCH_UMODE
#include <pthread.h>
#include <semaphore.h>
#else
#include <arch/semaphore.h>
#endif

#ifdef ARCH_UMODE
#include <sys/stat.h>
#include <network/sock.h>
#include <network/socket.h>
#include <network/netif.h>
#include <network/tcp_timer.h>
#endif

#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/error.h>
#include <arch/mailbox_runtime.h>

#ifdef ARCH_SEC_HW
#include "arch/sec_hw.h"
#include "xil_cache.h"
#endif
/* FIXME: remove */
#ifdef ARCH_UMODE
#include "tcp.h"
#include "ip.h"
#include "raw.h"
#endif

/* FIXME: also repeated in mailbox_runtime.c */
#ifdef ARCH_UMODE
typedef int bool;
#define true	(int) 1
#define false	(int) 0
#endif

int p_runtime = 0;
int q_runtime = 0;
int q_os = 0;

uint8_t **syscall_resp_queue;
int srq_size;
int srq_msg_size;
int srq_head;
int srq_tail;
int srq_counter;
sem_t srq_sem;

#define SYSCALL_SET_ZERO_ARGS(syscall_nr)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	*((uint16_t *) &buf[0]) = syscall_nr;		\

#define SYSCALL_SET_ONE_ARG(syscall_nr, arg0)		\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];		\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);	\
	u16 tmp_syscall_nr = (u16) syscall_nr; 		\
	u32 tmp_arg0 = (u32) arg0; 					\
	memcpy(&buf[0], (u16*) &tmp_syscall_nr, 2);		\
	memcpy(&buf[2], (u32*) &tmp_arg0, 4);		\

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

#define SYSCALL_SET_FOUR_ARGS(syscall_nr, arg0, arg1, arg2, arg3)	\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];				\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);			\
	*((uint16_t *) &buf[0]) = syscall_nr;				\
	*((uint32_t *) &buf[2]) = arg0;					\
	*((uint32_t *) &buf[6]) = arg1;					\
	*((uint32_t *) &buf[10]) = arg2;				\
	*((uint32_t *) &buf[14]) = arg3;				\

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

/* FIXME: the first check on max size is always false */
#define NETWORK_SET_ZERO_ARGS_DATA(data, size)					\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE_LARGE];				\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE);				\
	uint16_t max_size = MAILBOX_QUEUE_MSG_SIZE_LARGE - 2;			\
	if (max_size >= 65536) {						\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return;								\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return;								\
	}									\
	*((uint16_t *) &buf[0]) = size;						\
	memcpy(&buf[2], (uint8_t *) data, size);				\

#define NETWORK_GET_ZERO_ARGS_DATA							\
	uint8_t *data;									\
	uint16_t data_size;								\
	uint16_t max_size = MAILBOX_QUEUE_MSG_SIZE_LARGE - 2;				\
	if (max_size >= 65536) {							\
		printf("Error (%s): max_size not supported\n", __func__);		\
		continue;								\
	}										\
	data_size = *((uint16_t *) &buf[0]);						\
	if (data_size > max_size) {							\
		printf("Error (%s): size not supported (%d)\n", __func__, data_size);	\
		continue;								\
	}										\
	data = &buf[2];

int change_queue = 0;

unsigned int net_debug = 0;
pthread_t tcp_threads[2];
/* FIXME: move to header file. */
extern void tcp_timer(void);

/* FIXME: very similar to write_queue() in mailbox.c */
int write_syscall_response(uint8_t *buf)
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
		printf("Error: syscall response queue is empty\n");
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
	runtime_send_msg_on_queue(buf, q_os);

	/* wait for response */
#ifdef ARCH_SEC_HW
	wait_on_queue(q_runtime, buf);
	_SEC_HW_ASSERT_VOID(buf[0] == RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG);
#else
	wait_on_queue(q_runtime);
	read_syscall_response(buf);
#endif
}

static void issue_syscall_response_or_change(uint8_t *buf, bool *no_response)
{
	*no_response = false;
	int is_change = 0;

	runtime_send_msg_on_queue(buf, q_os);

	/* wait for response or a change of queue ownership */
#ifdef ARCH_SEC_HW
	wait_on_queue(q_runtime, buf);
#else
	wait_on_queue(q_runtime);
#endif
	is_ownership_change(&is_change);
	if (!is_change) {
#ifdef ARCH_UMODE
		read_syscall_response(buf);
#endif
	} else {
		*no_response = true;
	}
}

#ifdef ARCH_UMODE
/* network */
static int send_msg_to_network(uint8_t *buf)
{
	runtime_send_msg_on_queue_large(buf, Q_NETWORK_DATA_IN);

	return 0;
}

void ip_send_out(struct pkbuf *pkb)
{
	int size = pkb->pk_len + sizeof(*pkb);
	NETWORK_SET_ZERO_ARGS_DATA(pkb, size);
	send_msg_to_network(buf);
}

int local_address(unsigned int addr)
{
	printf("local_addr not implemented.\n");
	exit(-1);
	return 0;
}

void icmp_send(unsigned char type, unsigned char code,
                unsigned int data, struct pkbuf *pkb_in)
{
	printf("icmp_send not implemented.\n");
	exit(-1);
}

int rt_output(struct pkbuf *pkb)
{
	printf("rt_output not implemented.\n");
	exit(-1);
	return 0;
}

int syscall_allocate_tcp_socket(unsigned int *saddr, unsigned short *sport,
		unsigned int daddr, unsigned short dport)
{
	SYSCALL_SET_FOUR_ARGS(SYSCALL_ALLOCATE_SOCKET, (uint32_t) TCP_SOCKET,
			(uint32_t) *sport, (uint32_t) daddr, (uint32_t) dport)
	issue_syscall(buf);
	SYSCALL_GET_TWO_RETS

	if (!ret0 && !ret1)
		return ERR_FAULT;

	*saddr = ret0;
	*sport = ret1;

	return 0;
}

static void *tcp_receive(void *_data)
{
	while (1) {
		uint8_t *buf = (uint8_t *) malloc(MAILBOX_QUEUE_MSG_SIZE_LARGE);
		if (!buf) {
			printf("%s: Error: could not allocate memory for buf\n", __func__);
			exit(-1);
		}

		runtime_recv_msg_from_queue_large(buf, Q_NETWORK_DATA_OUT);
		NETWORK_GET_ZERO_ARGS_DATA
		struct pkbuf *pkb = (struct pkbuf *) data;
		pkb->pk_refcnt = 2; /* prevents the TCP code from freeing the pkb */
		list_init(&pkb->pk_list);
		/* FIXME: add */
		//pkb_safe();
		if (data_size != (pkb->pk_len + sizeof(*pkb))) {
			printf("%s: Error: packet size is not correct.\n", __func__);
			return NULL;
		}

		/* FIXME: is the call to raw_in() needed? */
		raw_in(pkb);
		tcp_in(pkb);
		free(buf);
	}
}

int net_stack_init(void)
{
	socket_init();

	/* tcp timer */
	/* FIXME: do we need this? */
	int ret = pthread_create(&tcp_threads[0], NULL, (pfunc_t) tcp_timer, NULL);
	if (ret) {
		printf("Error: couldn't launch tcp_threads[0]\n");
		return -1;
	}

	return 0;
}

void net_stack_exit(void)
{
	int ret = pthread_cancel(tcp_threads[0]);
	if (ret)
		printf("Error: couldn't kill tcp_threads[0]");
}
#endif

/* Only to be used for queues that runtime writes to */
/* FIXME: busy-waiting */
static void wait_until_empty(uint8_t queue_id, int queue_size)
{
	int left;

	while (1) {
		queue_sync_getval(queue_id, &left);
		if (left == queue_size)
			break;
	}
}

#ifdef ARCH_SEC_HW
static int request_secure_keyboard(u16 count)
#else
static int request_secure_keyboard(int count)
#endif
{
	reset_queue_sync(Q_KEYBOARD, 0);

	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_SECURE_KEYBOARD, (uint32_t) count)

	// FIXME: rm when the mailbox quota problem is fixed.
	_SEC_HW_ERROR("%d %02x%02x%02x%02x%02x%02x%02x%02x",
		count, buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]);

	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	int attest_ret = mailbox_attest_queue_access(Q_KEYBOARD,
					READ_ACCESS, count);
	if (!attest_ret) {
#ifdef ARCH_SEC_HW
		_SEC_HW_ERROR("%s: fail to attest\r\n", __func__);
#else
		printf("%s: Error: failed to attest secure keyboard access\n", __func__);
#endif
		return ERR_FAULT;
	}

	return 0;
}

static int yield_secure_keyboard(void)
{
	mailbox_change_queue_access(Q_KEYBOARD, READ_ACCESS, P_OS);
	return 0;
}

#ifdef ARCH_SEC_HW
static int request_secure_serial_out(u16 count)
#else
static int request_secure_serial_out(int count)
#endif
{
	reset_queue_sync(Q_SERIAL_OUT, MAILBOX_QUEUE_SIZE);

	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_SECURE_SERIAL_OUT, (uint32_t) count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	int attest_ret = mailbox_attest_queue_access(Q_SERIAL_OUT,
					WRITE_ACCESS, count);
	if (!attest_ret) {
#ifdef ARCH_SEC_HW
		_SEC_HW_ERROR("%s: fail to attest\r\n", __func__);
#else
		printf("%s: Error: failed to attest secure keyboard access\n", __func__);
#endif
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

// FIXME: rm when the mailbox quota problem is fixed.
u32 octopos_mailbox_get_quota_limit(UINTPTR base);
u32 octopos_mailbox_get_time_limit(UINTPTR base);
extern XMbox Mbox_keyboard;
extern XMbox Mbox_out;

static void write_to_secure_serial_out(char *buf)
{
	_SEC_HW_ERROR("serial out before: quota %d, time %d",
	 	octopos_mailbox_get_quota_limit(XPAR_OCTOPOS_MAILBOX_3WRI_0_BASEADDR),
	  	octopos_mailbox_get_time_limit(XPAR_OCTOPOS_MAILBOX_3WRI_0_BASEADDR));

	XMbox_IsEmpty(&Mbox_out);

	_SEC_HW_ERROR("serial out after: quota %d, time %d",
	 	octopos_mailbox_get_quota_limit(XPAR_OCTOPOS_MAILBOX_3WRI_0_BASEADDR),
	  	octopos_mailbox_get_time_limit(XPAR_OCTOPOS_MAILBOX_3WRI_0_BASEADDR));

	runtime_send_msg_on_queue((uint8_t *) buf, Q_SERIAL_OUT);
}



static void read_char_from_secure_keyboard(char *buf)
{
// FIXME: switch back to normal keyboard read when the 
// mailbox quota problem is fixed.

//	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
//	runtime_recv_msg_from_queue(input_buf, Q_KEYBOARD);
//	*buf = (char) input_buf[0];

    uint8_t          *message_buffer;
    u32		        bytes_read;

	message_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
	_SEC_HW_ERROR("keyboard before emty chk: quota %d", octopos_mailbox_get_quota_limit(XPAR_OCTOPOS_MAILBOX_1WRI_0_BASEADDR));

	if (!XMbox_IsEmpty(&Mbox_keyboard)) {
		_SEC_HW_ERROR("keyboard before read: quota %d", octopos_mailbox_get_quota_limit(XPAR_OCTOPOS_MAILBOX_1WRI_0_BASEADDR));
	    XMbox_Read(&Mbox_keyboard, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE, &bytes_read);
	}

	_SEC_HW_ERROR("keyboard done: quota %d", octopos_mailbox_get_quota_limit(XPAR_OCTOPOS_MAILBOX_1WRI_0_BASEADDR));

	*buf = (char) message_buffer[0];
	free((void*) message_buffer);
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

#ifdef ARCH_UMODE

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
	reset_queue_sync(Q_STORAGE_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
	SYSCALL_SET_THREE_ARGS(SYSCALL_WRITE_FILE_BLOCKS, fd,
			       (uint32_t) start_block, (uint32_t) num_blocks)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0 == 0)
		return 0;

	uint8_t queue_id = (uint8_t) ret0;

	for (int i = 0; i < num_blocks; i++)
		runtime_send_msg_on_queue_large(data + (i * STORAGE_BLOCK_SIZE), queue_id);

	return num_blocks;
}

static int read_file_blocks(uint32_t fd, uint8_t *data, int start_block, int num_blocks)
{
	reset_queue_sync(Q_STORAGE_DATA_OUT, 0);
	SYSCALL_SET_THREE_ARGS(SYSCALL_READ_FILE_BLOCKS, fd,
			       (uint32_t) start_block, (uint32_t) num_blocks)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0 == 0)
		return 0;

	uint8_t queue_id = (uint8_t) ret0;

	for (int i = 0; i < num_blocks; i++)
		runtime_recv_msg_from_queue_large(data + (i * STORAGE_BLOCK_SIZE), queue_id);

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

static int send_msg_to_storage(uint8_t *buf)
{
	runtime_send_msg_on_queue(buf, Q_STORAGE_IN_2);
	runtime_recv_msg_from_queue(buf, Q_STORAGE_OUT_2);

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

	reset_queue_sync(Q_STORAGE_IN_2, MAILBOX_QUEUE_SIZE);
	reset_queue_sync(Q_STORAGE_OUT_2, 0);

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
#endif

bool secure_ipc_mode = false;
static uint8_t secure_ipc_target_queue = 0;

#ifdef ARCH_SEC_HW
static int request_secure_ipc(uint8_t target_runtime_queue_id, u16 count)
#else
static int request_secure_ipc(uint8_t target_runtime_queue_id, int count)
#endif
{
	bool no_response;
	reset_queue_sync(target_runtime_queue_id, MAILBOX_QUEUE_SIZE);
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
	if (!secure_ipc_mode)
		return ERR_UNEXPECTED;

	IPC_SET_ZERO_ARGS_DATA(msg, size)
	runtime_send_msg_on_queue(buf, secure_ipc_target_queue);

	return 0;
}

static int recv_msg_on_secure_ipc(char *msg, int *size)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

	runtime_recv_msg_from_queue(buf, q_runtime);
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

bool has_network_access = false;
int network_access_count = 0;

#ifdef ARCH_UMODE
static struct socket *create_socket(int family, int type, int protocol,
				    struct sock_addr *skaddr)
{
	unsigned short sport = 0; /* do not support suggesting a port for now */
	unsigned int saddr;

	int ret = syscall_allocate_tcp_socket(&saddr, &sport,
			skaddr->dst_addr, skaddr->dst_port);
	if (ret)
		return NULL;

	skaddr->src_addr = saddr;
	skaddr->src_port = sport;

	return _socket(family, type, protocol);
}

//static int listen_on_socket(struct socket *sock, int backlog)
//{
//	return _listen(sock, backlog);
//}

static void close_socket(struct socket *sock)
{
	bool do_close = true;

	/* FIXME: 5 for close is an over-approximation (it only needs 1). */
	if (!has_network_access || (network_access_count < 5)) {
		printf("%s: Error: has no or insufficient network access.\n", __func__);
		do_close = false;
	}

	network_access_count -= 5;

	if (do_close)
		_close(sock);

	SYSCALL_SET_ZERO_ARGS(SYSCALL_CLOSE_SOCKET)
	issue_syscall(buf);
}

//static int bind_socket(struct socket *sock, struct sock_addr *skaddr)
//{
//	return bind_socket(sock, skaddr);
//}
//
//static struct socket *accept_connection(struct socket *sock, struct sock_addr *skaddr)
//{
//	return _accept(sock, skaddr);
//}

static int connect_socket(struct socket *sock, struct sock_addr *skaddr)
{
	/* FIXME: 20 packets for connect is an over-approximation. */
	if (!has_network_access || (network_access_count < 10)) {
		printf("%s: Error: has no or insufficient network access.\n", __func__);
		return ERR_INVALID;
	}

	network_access_count -= 10;

	return _connect(sock, skaddr);
}

static int read_from_socket(struct socket *sock, void *buf, int len)
{
	/* FIXME: calculate more precisely how many packets will be needed. */
	if (!has_network_access || (network_access_count < ((len / MAILBOX_QUEUE_MSG_SIZE_LARGE) + 1))) {
		printf("%s: Error: has no or insufficient network access.\n", __func__);
		return 0;
	}

	/* FIXME: what if _read returns error and doesn't use up these messages */
	network_access_count -= (len / MAILBOX_QUEUE_MSG_SIZE_LARGE) + 1;

	return _read(sock, buf, len);
}

static int write_to_socket(struct socket *sock, void *buf, int len)
{
	/* FIXME: calculate more precisely how many packets will be needed. */
	if (!has_network_access || (network_access_count < ((len / MAILBOX_QUEUE_MSG_SIZE_LARGE) + 1))) {
		printf("%s: Error: has no or insufficient network access.\n", __func__);
		return 0;
	}

	/* FIXME: what if _read returns error and doesn't use up these messages */
	network_access_count -= (len / MAILBOX_QUEUE_MSG_SIZE_LARGE) + 1;

	return _write(sock, buf, len);
}

static int yield_network_access(void)
{
	if (!has_network_access) {
		printf("%s: Error: no network access to yield\n", __func__);
		return ERR_INVALID;
	}

	has_network_access = false;
	network_access_count = 0;

	int ret = pthread_cancel(tcp_threads[1]);
	if (ret)
		printf("Error: couldn't kill tcp_threads[1]");

	wait_until_empty(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

	mailbox_change_queue_access(Q_NETWORK_DATA_IN, WRITE_ACCESS, P_OS);
	mailbox_change_queue_access(Q_NETWORK_DATA_OUT, READ_ACCESS, P_OS);

	return 0;
}

static int request_network_access(int count)
{
	if (has_network_access) {
		printf("%s: Error: already has network access\n", __func__);
		return ERR_INVALID;
	}

	reset_queue_sync(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
	reset_queue_sync(Q_NETWORK_DATA_OUT, 0);

	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_NETWORK_ACCESS, count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	/* FIXME: if any of the attetations fail, we should yield the other one */
	int attest_ret = mailbox_attest_queue_access(Q_NETWORK_DATA_IN,
					WRITE_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest network write access\n", __func__);
		return ERR_FAULT;
	}

	attest_ret = mailbox_attest_queue_access(Q_NETWORK_DATA_OUT,
					READ_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest network read access\n", __func__);
		return ERR_FAULT;
	}

	/* tcp receive */
	/* FIXME: process received message on the main thread */
	int ret = pthread_create(&tcp_threads[1], NULL, (pfunc_t) tcp_receive, NULL);
	if (ret) {
		printf("Error: couldn't launch tcp_threads[1]\n");
		wait_until_empty(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
		mailbox_change_queue_access(Q_NETWORK_DATA_IN, WRITE_ACCESS, P_OS);
		mailbox_change_queue_access(Q_NETWORK_DATA_OUT, READ_ACCESS, P_OS);
		return ERR_FAULT;
	}

	has_network_access = true;
	network_access_count = count;

	return 0;
}

#endif

static void load_application(char *msg)
{
	struct runtime_api api = {
		.request_secure_keyboard = request_secure_keyboard,
		.yield_secure_keyboard = yield_secure_keyboard,
		.request_secure_serial_out = request_secure_serial_out,
		.yield_secure_serial_out = yield_secure_serial_out,
		.write_to_secure_serial_out = write_to_secure_serial_out,
		.read_char_from_secure_keyboard = read_char_from_secure_keyboard,
		.write_to_shell = write_to_shell,
		.read_from_shell = read_from_shell,
#ifdef ARCH_UMODE
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
#endif
		.request_secure_ipc = request_secure_ipc,
		.yield_secure_ipc = yield_secure_ipc,
		.send_msg_on_secure_ipc = send_msg_on_secure_ipc,
		.recv_msg_on_secure_ipc = recv_msg_on_secure_ipc,
		.get_runtime_proc_id = get_runtime_proc_id,
		.get_runtime_queue_id = get_runtime_queue_id,
#ifdef ARCH_UMODE
		.create_socket = create_socket,
		//.listen_on_socket = listen_on_socket,
		.close_socket = close_socket,
		//.bind_socket = bind_socket,
		//.accept_connection = accept_connection,
		.connect_socket = connect_socket,
		.read_from_socket = read_from_socket,
		.write_to_socket = write_to_socket,
		.request_network_access = request_network_access,
		.yield_network_access = yield_network_access,
#endif
	};

	load_application_arch(msg, &api);

	return;
}

bool still_running = true;

void *run_app(void *load_buf)
{
	int ret = inform_os_runtime_ready();
	if (ret) {
		printf("Error (%s): runtime ready notification rejected by the OS\n", __func__);
		still_running = false;
		return NULL;
	}
	wait_for_app_load();
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

#ifdef ARCH_UMODE
void *store_context(void *data)
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
#endif


#ifdef ARCH_UMODE
int main(int argc, char **argv)
#else
int main()
{
    // FIXME: Zephyr: rm this when microblaze doesn't use ddr for cache
    Xil_ICacheEnable();
    Xil_DCacheEnable();
#endif

	int runtime_id = -1;

	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error (runtime): storage data queue msg size must be equal to storage block size\n");
		exit(-1);
	}
#ifdef ARCH_UMODE
	if (argc != 2) {
		printf("Error: incorrect command. Use ``runtime <runtime_ID>''.\n");
		return -1;
	}

	runtime_id = atoi(argv[1]);
#else
	runtime_id = RUNTIME_ID;
#endif

	if (runtime_id < 1 || runtime_id > 2) {
		printf("Error: invalid runtime ID.\n");
		return -1;
	}
	int ret = init_runtime(runtime_id);

	if (ret) {
		printf("%s: Error: couldn't initialize the runtime\n", __func__);
		return -1;
	}

	/* initialize syscall response queue */
	syscall_resp_queue = allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);
	srq_size = MAILBOX_QUEUE_SIZE;
	srq_msg_size = MAILBOX_QUEUE_MSG_SIZE;
	srq_counter = 0;
	srq_head = 0;
	srq_tail = 0;

	sem_init(&srq_sem, 0, MAILBOX_QUEUE_SIZE);

#ifdef ARCH_UMODE
	ret = net_stack_init();
	if (ret) {
		printf("%s: Error: couldn't initialize the runtime network stack\n", __func__);
		return -1;
	}
#endif

	runtime_core();
#ifdef ARCH_UMODE
	net_stack_exit();
#endif

	close_runtime();

	return 0;
}
