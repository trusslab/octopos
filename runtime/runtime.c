/* octopos application runtime */
#include <arch/defines.h>

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
#include <runtime/runtime.h>
#include <runtime/storage_client.h>
#include <network/sock.h>
#include <network/socket.h>
#include <network/netif.h>
#include <network/tcp_timer.h>
#include <runtime/network_client.h>
#endif

#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/error.h>
#include <arch/mailbox_runtime.h>

#ifdef ARCH_SEC_HW
#include "xparameters.h"
#include "arch/sec_hw.h"
#include "xil_cache.h"
#endif
/* FIXME: remove */
#ifdef ARCH_UMODE
#include "tcp.h"
#include "ip.h"
#include "raw.h"
#endif

volatile int i = 0xDEADBEEF;
extern unsigned char __datacopy;
extern unsigned char __data_start;
extern unsigned char __data_end;

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

#ifdef ARCH_SEC_HW
extern sem_t interrupt_change;
#endif

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
		/* FIXME: dead code */
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
		/* FIXME: dead code */
		return -1;
	}

	srq_counter--;
	memcpy(buf, syscall_resp_queue[srq_head], srq_msg_size);
	srq_head = (srq_head + 1) % srq_size;

	sem_post(&srq_sem);

	return 0;
}

void issue_syscall(uint8_t *buf)
{
	runtime_send_msg_on_queue(buf, q_os);

	/* wait for response */
	wait_on_queue(q_runtime);
	read_syscall_response(buf);
}

static void issue_syscall_response_or_change(uint8_t *buf, bool *no_response)
{
	*no_response = false;
	int is_change = 0;

	runtime_send_msg_on_queue(buf, q_os);

	/* wait for response or a change of queue ownership */
#ifdef ARCH_SEC_HW
	sem_wait(&interrupt_change);
	*no_response = true;
#else
	wait_on_queue(q_runtime);
	is_ownership_change(&is_change);
	if (!is_change) {
		read_syscall_response(buf);
	} else {
		*no_response = true;
	}
#endif
}

#ifdef ARCH_UMODE
/* network */
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

static void *tcp_receive(void *_data)
{
	while (1) {
		uint8_t *buf = (uint8_t *) malloc(MAILBOX_QUEUE_MSG_SIZE_LARGE);
		if (!buf) {
			printf("%s: Error: could not allocate memory for buf\n", __func__);
			exit(-1);
		}

		uint8_t *data;
		uint16_t data_size;

		data = ip_receive(buf, &data_size);
		if (!data_size) {
			printf("%s: Error: bad network data message\n", __func__);
			continue;
		}

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

int net_start_receive(void)
{
	/* tcp receive */
	/* FIXME: process received message on the main thread */
	int ret = pthread_create(&tcp_threads[1], NULL, (pfunc_t) tcp_receive, NULL);
	if (ret) {
		printf("Error: couldn't launch tcp_threads[1]\n");
		return ret;
	}

	return 0;
}

void net_stop_receive(void)
{
	int ret = pthread_cancel(tcp_threads[1]);
	if (ret)
		printf("Error: couldn't kill tcp_threads[1]");
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
void wait_until_empty(uint8_t queue_id, int queue_size)
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
#ifdef ARCH_SEC_HW
	mailbox_yield_to_previous_owner(Q_KEYBOARD);
#else
	mailbox_change_queue_access(Q_KEYBOARD, READ_ACCESS, P_OS);
#endif
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

#ifdef ARCH_SEC_HW
	mailbox_yield_to_previous_owner(Q_SERIAL_OUT);
#else
	mailbox_change_queue_access(Q_SERIAL_OUT, WRITE_ACCESS, P_OS);
#endif
	return 0;
}

static void write_to_secure_serial_out(char *buf)
{
	runtime_send_msg_on_queue((uint8_t *) buf, Q_SERIAL_OUT);
}

static void read_char_from_secure_keyboard(char *buf)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];
	runtime_recv_msg_from_queue(input_buf, Q_KEYBOARD);
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

#ifdef ARCH_SEC_HW
/* Runtime needs to print critical messages to shell */
int write_to_shell(char *data, int size)
#else
static int write_to_shell(char *data, int size)
#endif
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
#ifdef ARCH_SEC_HW
	data[*data_size - 1] = '\0';
#endif
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


bool context_set = false;
void *context_addr = NULL;
uint32_t context_size = 0;
uint32_t context_tag = 0xDEADBEEF;
#define CONTEXT_TAG_SIZE	4

static int set_up_context(void *addr, uint32_t size)
{
	uint8_t context_block[STORAGE_BLOCK_SIZE];

	if (size > (STORAGE_BLOCK_SIZE - CONTEXT_TAG_SIZE)) {
		printf("Error (%s): context size is too big.\n", __func__);
		return ERR_INVALID;
	}

	context_addr = addr;
	context_size = size;
	context_set = true;

	/* Now, let's retrieve the context. */
	int ret = request_secure_storage_access(200, 100);
	if (ret) {
		printf("Error (%s): Failed to get secure access to storage.\n", __func__);
		return ret;
	}

	uint32_t rret = read_from_secure_storage_block(context_block, 0, 0, context_size + CONTEXT_TAG_SIZE);
	if (rret != (context_size + CONTEXT_TAG_SIZE)) {
		printf("%s: Couldn't read from secure storage.\n", __func__);
		yield_secure_storage_access();
		return ERR_FAULT;
	}

	if ((*(uint32_t *) context_block) != context_tag) {
		printf("%s: No context to use.\n", __func__);
		yield_secure_storage_access();
		return ERR_INVALID;
	}

	memcpy(context_addr, &context_block[CONTEXT_TAG_SIZE], context_size);

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

/* ARCH_SEC_HW */
#ifndef ARCH_SEC_HW 
	/* FIXME: 
	attest_ret = mailbox_attest_queue_access(q_runtime,
					WRITE_ACCESS, count, other runtime);
	if (!attest_ret) {
		printf("%s: Error: failed to attest secure ipc recv queue access\n", __func__);
		return ERR_FAULT;
	}*/
#endif

	secure_ipc_mode = true;
	secure_ipc_target_queue = target_runtime_queue_id;

	return 0;
}

static int yield_secure_ipc(void)
{
	uint8_t qid = secure_ipc_target_queue;
	secure_ipc_target_queue = 0;
	secure_ipc_mode = false;

#ifdef ARCH_SEC_HW
	/* Before we change runtime queue access, we must
	 * make sure the other side has done with its reading
	 * or writing.
	 */
	char yield_msg[MAILBOX_QUEUE_MSG_SIZE] = "ADIOS";
	int yield_msg_size = strlen(yield_msg) + 1;

	IPC_SET_ZERO_ARGS_DATA(yield_msg, yield_msg_size)
	runtime_send_msg_on_queue(buf, qid);

	{
		uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
		runtime_recv_msg_from_queue(buf, q_runtime);
		IPC_GET_ZERO_ARGS_DATA

		int goodbye_received = memcmp(data, yield_msg, strlen(yield_msg));
		_SEC_HW_ASSERT_NON_VOID(0 == goodbye_received)
		_SEC_HW_DEBUG("ADIOS received from %d", qid);
	}
#endif

	wait_until_empty(qid, MAILBOX_QUEUE_SIZE);

#ifdef ARCH_SEC_HW
	mailbox_yield_to_previous_owner(qid);
#else
	mailbox_change_queue_access(qid, WRITE_ACCESS, P_OS);
#endif

/* ARCH_SEC_HW OctopOS mailbox only allows the current owner
 * to change/yield ownership. This is different from umode.
 * Thus, instead of explicitly yielding it, we attest it.
 * In case the other runtime refuses to yield, we forcefully
 * deplete the quota by repeatedly reading the mailbox.
 */
#ifdef ARCH_SEC_HW
	if (!mailbox_attest_queue_owner(q_runtime, P_OS)) {
		mailbox_force_ownership(q_runtime, P_OS);
	}
#else
	mailbox_change_queue_access(q_runtime, WRITE_ACCESS, P_OS);
#endif

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

extern bool has_network_access;
extern int network_access_count;

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
		.write_secure_storage_blocks = write_secure_storage_blocks,
		.read_secure_storage_blocks = read_secure_storage_blocks,
		.write_to_secure_storage_block = write_to_secure_storage_block,
		.read_from_secure_storage_block = read_from_secure_storage_block,
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
	uint8_t context_block[STORAGE_BLOCK_SIZE];

	if (!is_secure_storage_key_set() || !context_set) {
		printf("%s: Error: either the secure storage key or context not set\n", __func__);
		return NULL;
	}

	int ret = request_secure_storage_access(200, 100);
	if (ret) {
		printf("Error (%s): Failed to get secure access to storage.\n", __func__);
		return NULL;
	}

	memcpy(context_block, &context_tag, CONTEXT_TAG_SIZE);
	memcpy(&context_block[CONTEXT_TAG_SIZE], context_addr, context_size);

	uint32_t wret = write_to_secure_storage_block(context_block, 0, 0, context_size + CONTEXT_TAG_SIZE);
	if (wret != (context_size + CONTEXT_TAG_SIZE))
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
#endif
{
#ifdef ARCH_SEC_HW
	// FIXME: Zephyr: rm this when microblaze doesn't use ddr for cache
#if RUNTIME_ID == 1
	Xil_ICacheEnable();
	Xil_DCacheEnable();
#endif /* RUNTIME_ID == 1 */

#if RUNTIME_ID == 2
//    _SEC_HW_ERROR("ENTERING MAIN");

	unsigned char *dataCopyStart = &__datacopy;
	unsigned char *dataStart = &__data_start;
	unsigned char *dataEnd = &__data_end;
	if (i == 0xDEADBEEF) {
		while(dataStart < dataEnd)
			*dataCopyStart++ = *dataStart++;
	} else {
		while(dataStart < dataEnd)
			*dataStart++ = *dataCopyStart++;
		// _mb_restarted = TRUE;
	}

	i = 0;
#endif /* RUNTIME_ID == 2 */

#endif /* ARCH_SEC_HW */

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
	/* FIXME: release memory on exit */
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

#ifdef ARCH_SEC_HW
	close_runtime();
#endif

	return 0;
}
