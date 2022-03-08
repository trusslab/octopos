/* octopos application runtime */
#include <arch/defines.h>

#include <stdio.h>
#include <string.h>
#ifdef ARCH_UMODE
#include <fcntl.h>
#endif
#include <unistd.h>
#include <stdint.h>
#include <time.h>

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
#ifdef ARCH_SEC_HW
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
#include <octopos/io.h>
#include <octopos/storage.h>
#include <octopos/error.h>
#include <octopos/bluetooth.h>
/* FIXME: tpm/tpm.h should be moved to octopos/tpm.h */
#include <tpm/hash.h>
#include <tpm/tpm.h>
#include <tpm/rsa.h>
#include <arch/mailbox_runtime.h>

#ifdef ARCH_SEC_HW
#include <runtime/storage_client.h>
#include "xparameters.h"
#include "arch/sec_hw.h"
#include <network/ip.h>
#include <network/tcp.h>
#endif
/* FIXME: remove */
#ifdef ARCH_UMODE
#include "tcp.h"
#include "ip.h"
#include "raw.h"
#endif

#ifdef ARCH_SEC_HW
#define ARCH_SEC_HW_EVALUATION
#endif

int network_domain_bind_sport(unsigned short sport);

int p_runtime = 0;
int q_runtime = 0;
int q_os = 0;

bool still_running = true;

uint8_t **syscall_resp_queue;
int srq_size;
int srq_msg_size;
int srq_head;
int srq_tail;
int srq_counter;
sem_t srq_sem;

limit_t queue_limits[NUM_QUEUES + 1];
timeout_t queue_timeouts[NUM_QUEUES + 1];
queue_update_callback_t queue_update_callbacks[NUM_QUEUES + 1];

bool has_secure_keyboard_access = false;
bool has_secure_serial_out_access = false;
bool has_secure_bluetooth_access = false;

#ifdef ARCH_SEC_HW
extern sem_t interrupt_change;
/* FIXME: during context switch, we cannot receive any interrupt.
 * This is an ad hoc solution before a solution is found.
 */
_Bool async_syscall_mode = FALSE;
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

bool secure_ipc_mode = false;
static uint8_t secure_ipc_target_queue = 0;

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

#ifdef ARCH_SEC_HW
if (async_syscall_mode) {
	sleep(1);
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	return;
}
#endif
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

static void reset_keyboard_queue_trackers(void)
{
	/* FIXME: redundant when called from yield_secure_keyboard() */
	has_secure_keyboard_access = false;

	queue_limits[Q_KEYBOARD] = 0;
	queue_timeouts[Q_KEYBOARD] = 0;
	queue_update_callbacks[Q_KEYBOARD] = NULL;
}

static void reset_serial_out_queue_trackers(void)
{
	/* FIXME: redundant when called from yield_secure_serial_out() */
	has_secure_serial_out_access = false;

	queue_limits[Q_SERIAL_OUT] = 0;
	queue_timeouts[Q_SERIAL_OUT] = 0;
	queue_update_callbacks[Q_SERIAL_OUT] = NULL;
}

static void reset_ipc_queue_trackers(void)
{
	/* FIXME: redundant when called from yield_secure_ipc() */
	secure_ipc_mode = false;

	queue_limits[secure_ipc_target_queue] = 0;
	queue_timeouts[secure_ipc_target_queue] = 0;
	queue_update_callbacks[secure_ipc_target_queue] = NULL;
}

static void reset_bluetooth_queues_trackers(void)
{
	/* FIXME: redundant when called from yield_secure_bluetooth_access() */
	has_secure_bluetooth_access = false;

	queue_limits[Q_BLUETOOTH_CMD_IN] = 0;
	queue_timeouts[Q_BLUETOOTH_CMD_IN] = 0;
	queue_update_callbacks[Q_BLUETOOTH_CMD_IN] = NULL;

	queue_limits[Q_BLUETOOTH_CMD_OUT] = 0;
	queue_timeouts[Q_BLUETOOTH_CMD_OUT] = 0;
	queue_update_callbacks[Q_BLUETOOTH_CMD_OUT] = NULL;

	queue_limits[Q_BLUETOOTH_DATA_IN] = 0;
	queue_timeouts[Q_BLUETOOTH_DATA_IN] = 0;
	queue_update_callbacks[Q_BLUETOOTH_DATA_IN] = NULL;

	queue_limits[Q_BLUETOOTH_DATA_OUT] = 0;
	queue_timeouts[Q_BLUETOOTH_DATA_OUT] = 0;
	queue_update_callbacks[Q_BLUETOOTH_DATA_OUT] = NULL;
}

static void queue_expired(uint8_t queue_id)
{
	if (queue_id == Q_KEYBOARD)
		reset_keyboard_queue_trackers();
	else if (queue_id == Q_SERIAL_OUT)
		reset_serial_out_queue_trackers();
	else if (queue_id == secure_ipc_target_queue)
		reset_ipc_queue_trackers();
	else if (queue_id == Q_STORAGE_CMD_IN ||
		 queue_id == Q_STORAGE_CMD_OUT ||
		 queue_id == Q_STORAGE_DATA_IN ||
		 queue_id == Q_STORAGE_DATA_OUT)
		reset_storage_queues_trackers();
#ifndef ARCH_SEC_HW
	else if (queue_id == Q_NETWORK_DATA_IN ||
		 queue_id == Q_NETWORK_DATA_OUT)
		reset_network_queues_tracker();
#endif
	else if (queue_id == Q_BLUETOOTH_CMD_IN ||
		 queue_id == Q_BLUETOOTH_CMD_OUT ||
		 queue_id == Q_BLUETOOTH_DATA_IN ||
		 queue_id == Q_BLUETOOTH_DATA_OUT)
		reset_bluetooth_queues_trackers();
	else
		printf("Error: %s: invalid queue_id (%d)\n", __func__, queue_id);
}

void report_queue_usage(uint8_t queue_id)
{
	int check_expire = 0;

	if (queue_limits[queue_id]) {
		queue_limits[queue_id]--;
		check_expire = 1;
	}

	if (queue_update_callbacks[queue_id]) {
		(*queue_update_callbacks[queue_id])(queue_id,
						    queue_limits[queue_id],
						    queue_timeouts[queue_id],
						    LIMIT_UPDATE);
	}

	if (check_expire && (queue_limits[queue_id] == 0))
		queue_expired(queue_id);
}

void timer_tick(void)
{
	int i, check_expire;

	for (i = 1; i < (NUM_QUEUES + 1); i++) {
		check_expire = 0;

		if (queue_timeouts[i]) {
			queue_timeouts[i]--;
			check_expire = 1;
		}

		if (queue_update_callbacks[i]) {
			(*queue_update_callbacks[i])(i, queue_limits[i],
						     queue_timeouts[i],
						     TIMEOUT_UPDATE);
		}
		
		/* FIXME: this can be a little late as the queue might
		 * have expired a little bit earlier due to the error
		 * margin in the mailbox timeouts.
		 */
		if (check_expire && (queue_timeouts[i] == 0))
			queue_expired(i);
	}
}

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
extern bool has_network_access;
extern int network_access_count;
#ifndef ARCH_SEC_HW
static void *tcp_receive(void *_data)
{
	while (1) {
		uint8_t *buf = (uint8_t *) malloc(MAILBOX_QUEUE_MSG_SIZE_LARGE);
		if (!buf) {
			printf("Error: %s: could not allocate memory for buf\n",
			       __func__);
			exit(-1);
		}

		uint8_t *data;
		uint16_t data_size;

		data = ip_receive(buf, &data_size);
		if (!data_size) {
			printf("Error: %s: bad network data message\n",
			       __func__);
			continue;
		}

		struct pkbuf *pkb = (struct pkbuf *) data;
		pkb->pk_refcnt = 2; /* prevents the TCP code from freeing the pkb */
		list_init(&pkb->pk_list);
		/* FIXME: add */
		//pkb_safe();
		if (data_size != (pkb->pk_len + sizeof(*pkb))) {
			printf("Error: %s: packet size is not correct.\n",
			       __func__);
			return NULL;
		}

		/* FIXME: is the call to raw_in() needed? */
		raw_in(pkb);
		tcp_in(pkb);
		free(buf);
	}
}
#else /*ARCH_SEC_HW*/
bool had_network_access;
#define NETWRORK_RECEIVE_INTR_WORK
uint8_t net_buf[MAILBOX_QUEUE_MSG_SIZE_LARGE];
extern UINTPTR			Mbox_ctrl_regs[NUM_QUEUES + 1];
extern _Bool octopos_mailbox_attest_owner_fast(UINTPTR base);

int tcp_receive()
{


	int bytes_read;
	if(!has_network_access){
		had_network_access = has_network_access;
		return -1;
	}
	if(has_network_access & !had_network_access){
		for(int i =0 ; i<100000; i++){
		}
		had_network_access = true;

	}
	_Bool result = TRUE;
	UINTPTR queue_ptr = Mbox_ctrl_regs[Q_NETWORK_DATA_OUT];
	result &= octopos_mailbox_attest_owner_fast(queue_ptr);
#ifdef NETWRORK_RECEIVE_INTR_WORK
	if (!result){
		while(1);
	}
	if (OCTOPOS_XMbox_IsEmptyHw(Mbox_regs[Q_NETWORK_DATA_OUT]->Config.BaseAddress)){
		return XST_NO_DATA;
	}

	bytes_read = sem_wait_one_time_receive_buf_large(&interrupts[Q_NETWORK_DATA_OUT], Mbox_regs[Q_NETWORK_DATA_OUT], net_buf);

	if (bytes_read == NULL){
		return -1;
	}



	HW_NETWORK_GET_ZERO_ARGS_DATA
	if (!data_size) {
		printf("%s: Error: bad network data message\n", __func__);
		return -1;
	}

	struct pkbuf *pkb = (struct pkbuf *) data;
	pkb->pk_refcnt = 2; /* prevents the TCP code from freeing the pkb */
	list_init(&pkb->pk_list);
	if (data_size != (pkb->pk_len + sizeof(*pkb))) {
		printf("%s: Error: packet size is not correct.\n", __func__);
		return -1;
	}
	tcp_in(pkb);
#endif

	return 0;
}
#endif /*ARCH_SEC_HW*/

int net_start_receive(void)
{
	/* tcp receive */
	/* FIXME: process received message on the main thread */
#ifndef ARCH_SEC_HW
	int ret = pthread_create(&tcp_threads[1], NULL, (pfunc_t) tcp_receive, NULL);
	if (ret) {
		printf("Error: couldn't launch tcp_threads[1]\n");
		return ret;
	}
#endif
	return 0;
}

void net_stop_receive(void)
{
#ifndef ARCH_SEC_HW
	int ret = pthread_cancel(tcp_threads[1]);
	if (ret)
		printf("Error: couldn't kill tcp_threads[1]");
#endif
}

int net_stack_init(void)
{
	socket_init();

	/* tcp timer */
	/* FIXME: do we need this? */
#ifndef ARCH_SEC_HW
	int ret = pthread_create(&tcp_threads[0], NULL, (pfunc_t) tcp_timer, NULL);
	if (ret) {
		printf("Error: couldn't launch tcp_threads[0]\n");
		return -1;
	}
#endif
	return 0;
}

void net_stack_exit(void)
{
#ifndef ARCH_SEC_HW
	int ret = pthread_cancel(tcp_threads[0]);
	if (ret)
		printf("Error: couldn't kill tcp_threads[0]");
#endif

}

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

int check_proc_pcr(uint8_t proc_id, uint8_t *expected_pcr)
{
#ifndef ARCH_SEC_HW
	uint8_t pcr_val[TPM_EXTEND_HASH_SIZE];
	int ret;

	ret = read_tpm_pcr_for_proc(proc_id, pcr_val);
	if (ret) {
		printf("Error: %s: read_tpm_pcr_for_proc failed\n", __func__);
		return ret;
	}

	ret = memcmp(pcr_val, expected_pcr, TPM_EXTEND_HASH_SIZE);
	if (ret) {
		printf("Error: %s: pcr val doesn't match the expected val\n",
		       __func__);
		return ERR_UNEXPECTED;
	}
#endif
	return 0;
}


static int request_secure_keyboard(limit_t limit, timeout_t timeout,
				   queue_update_callback_t callback,
				   uint8_t *expected_pcr)
{
	int ret;

	if (has_secure_keyboard_access) {
		printf("Error: %s: already has access to secure keyboard.\n",
		       __func__);
		return ERR_INVALID;
	}

	reset_queue_sync(Q_KEYBOARD, 0);

	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_SECURE_KEYBOARD, (uint32_t) limit,
			     (uint32_t) timeout)

	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	ret = mailbox_attest_queue_access(Q_KEYBOARD, limit, timeout);
	if (!ret) {
		printf("Error: %s: failed to attest secure keyboard access\n",
		       __func__);
		return ERR_FAULT;
	}

	/* Note: we set the limit/timeout values right after attestation and
	 * before we call check_proc_pcr(). This is because that call issues a
	 * syscall, which might take an arbitrary amount of time.
	 */
	queue_limits[Q_KEYBOARD] = limit;
	queue_timeouts[Q_KEYBOARD] = timeout;

#ifndef ARCH_SEC_HW
	if (expected_pcr) {
		ret = check_proc_pcr(P_KEYBOARD, expected_pcr);
		if (ret) {
			printf("Error: %s: unexpected PCR\n", __func__);
			mailbox_yield_to_previous_owner(Q_KEYBOARD);
			
			queue_limits[Q_KEYBOARD] = 0;
			queue_timeouts[Q_KEYBOARD] = 0;
			return ERR_UNEXPECTED;
		}
	}
#endif

	queue_update_callbacks[Q_KEYBOARD] = callback;

	has_secure_keyboard_access = true;

	return 0;
}

static int yield_secure_keyboard(void)
{
	if (!has_secure_keyboard_access) {
		printf("Error: %s: does not have access to secure keyboard.\n",
		       __func__);
		return ERR_INVALID;
	}

	has_secure_keyboard_access = false;

	mailbox_yield_to_previous_owner(Q_KEYBOARD);

	reset_keyboard_queue_trackers();

	return 0;
}

static int request_secure_serial_out(limit_t limit, timeout_t timeout,
				     queue_update_callback_t callback,
				     uint8_t *expected_pcr)
{
	int ret;

	if (has_secure_serial_out_access) {
		printf("Error: %s: already has access to secure serial_out.\n",
		       __func__);
		return ERR_INVALID;
	}

	reset_queue_sync(Q_SERIAL_OUT, MAILBOX_QUEUE_SIZE);

	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_SECURE_SERIAL_OUT, (uint32_t) limit,
			     (uint32_t) timeout);
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0) {
		return (int) ret0;
	}

	ret = mailbox_attest_queue_access(Q_SERIAL_OUT, limit, timeout);
	if (!ret) {
		printf("Error: %s: failed to attest secure keyboard access\n",
		       __func__);
		return ERR_FAULT;
	}

	/* Note: we set the limit/timeout values right after attestation and
	 * before we call check_proc_pcr(). This is because that call issues a
	 * syscall, which might take an arbitrary amount of time.
	 */
	queue_limits[Q_SERIAL_OUT] = limit;
	queue_timeouts[Q_SERIAL_OUT] = timeout;

#ifndef ARCH_SEC_HW
	if (expected_pcr) {
		ret = check_proc_pcr(P_SERIAL_OUT, expected_pcr);
		if (ret) {
			printf("Error: %s: unexpected PCR\n", __func__);
			wait_until_empty(Q_SERIAL_OUT, MAILBOX_QUEUE_SIZE);
			mailbox_yield_to_previous_owner(Q_SERIAL_OUT);

			queue_limits[Q_SERIAL_OUT] = 0;
			queue_timeouts[Q_SERIAL_OUT] = 0;
			return ERR_UNEXPECTED;
		}
	}
#endif

	has_secure_serial_out_access = true;

	queue_update_callbacks[Q_SERIAL_OUT] = callback;
	return 0;
}

static int yield_secure_serial_out(void)
{
	if (!has_secure_serial_out_access) {
		printf("Error: %s: does not have access to secure serial_out.\n",
		       __func__);
		return ERR_INVALID;
	}

	has_secure_serial_out_access = false;

	wait_until_empty(Q_SERIAL_OUT, MAILBOX_QUEUE_SIZE);

	mailbox_yield_to_previous_owner(Q_SERIAL_OUT);

	reset_serial_out_queue_trackers();

	return 0;
}

static int write_to_secure_serial_out(char *buf)
{
	if (!has_secure_serial_out_access) {
		printf("Error: %s: does not have access to secure serial_out.\n",
		       __func__);
		return ERR_INVALID;
	}

	runtime_send_msg_on_queue((uint8_t *) buf, Q_SERIAL_OUT);

	report_queue_usage(Q_SERIAL_OUT);

	return 0;
}

static int read_char_from_secure_keyboard(char *buf)
{
	uint8_t input_buf[MAILBOX_QUEUE_MSG_SIZE];

	if (!has_secure_keyboard_access) {
		printf("Error: %s: does not have access to secure keyboard.\n",
		       __func__);
		return ERR_INVALID;
	}

	runtime_recv_msg_from_queue(input_buf, Q_KEYBOARD);

	report_queue_usage(Q_KEYBOARD);

	*buf = (char) input_buf[0];

	return 0;
}

static int inform_os_of_termination(void)
{
#ifdef ARCH_SEC_HW
	/* FIXME: Issue #26 */
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
	mailbox_yield_to_previous_owner(Q_NETWORK_DATA_OUT);
	mailbox_yield_to_previous_owner(Q_NETWORK_DATA_IN);
	mailbox_yield_to_previous_owner(Q_NETWORK_CMD_OUT);
	mailbox_yield_to_previous_owner(Q_NETWORK_CMD_IN);
	mailbox_yield_to_previous_owner(Q_KEYBOARD);
	mailbox_yield_to_previous_owner(Q_SERIAL_OUT);
#endif

	SYSCALL_SET_ZERO_ARGS(SYSCALL_INFORM_OS_OF_TERMINATION)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0;
}

static int inform_os_of_pause(void)
{
	SYSCALL_SET_ZERO_ARGS(SYSCALL_INFORM_OS_OF_PAUSE)
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
	return (int) ret0;
}

static uint32_t open_file(char *filename, uint32_t mode)
{
	SYSCALL_SET_ONE_ARG_DATA(SYSCALL_OPEN_FILE, mode, filename,
				 strlen(filename))
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

static int write_file_blocks(uint32_t fd, uint8_t *data, int start_block,
			     int num_blocks)
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
		runtime_send_msg_on_queue_large(data + (i * STORAGE_BLOCK_SIZE),
						queue_id);

	return num_blocks;
}

static int read_file_blocks(uint32_t fd, uint8_t *data, int start_block,
			    int num_blocks)
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
		runtime_recv_msg_from_queue_large(data + (i * STORAGE_BLOCK_SIZE),
						  queue_id);
	
	return num_blocks;
}

static uint32_t get_file_size(uint32_t fd)
{
	SYSCALL_SET_ONE_ARG(SYSCALL_GET_FILE_SIZE, fd)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0;
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
	SYSCALL_SET_ZERO_ARGS_DATA(SYSCALL_REMOVE_FILE, filename,
				   strlen(filename))
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	return (int) ret0;
}

static int request_secure_ipc(uint8_t target_runtime_queue_id, limit_t limit,
			      timeout_t timeout, queue_update_callback_t callback)
{
	bool no_response;
	reset_queue_sync(target_runtime_queue_id, MAILBOX_QUEUE_SIZE);
	SYSCALL_SET_THREE_ARGS(SYSCALL_REQUEST_SECURE_IPC,
			       target_runtime_queue_id, (uint32_t) limit,
			       (uint32_t) timeout)
	change_queue = target_runtime_queue_id;
	issue_syscall_response_or_change(buf, &no_response);
	if (!no_response) {
		/* error */
		SYSCALL_GET_ONE_RET
		return (int) ret0;
	}

	/* FIXME: if any of the attetations fail, we should yield the other one */
	int attest_ret = mailbox_attest_queue_access(target_runtime_queue_id,
						     limit, timeout);
	if (!attest_ret) {
		printf("Error: %s: failed to attest secure ipc send queue "
		       "access\n", __func__);
		return ERR_FAULT;
	}

/* ARCH_SEC_HW */
#ifndef ARCH_SEC_HW 
	/* FIXME: 
	attest_ret = mailbox_attest_queue_access(q_runtime,
					WRITE_ACCESS, count, other runtime);
	if (!attest_ret) {
		printf("Error: %s: failed to attest secure ipc recv queue access\n", __func__);
		return ERR_FAULT;
	}*/
#endif


	queue_limits[target_runtime_queue_id] = limit;
	queue_timeouts[target_runtime_queue_id] = timeout;

	/* FIXME: check PCR. Need the proc_id for that. It needs to be done
	 * after setting limit/timeout. See comments in other similar funcs.
	 */	

	queue_update_callbacks[target_runtime_queue_id] = callback;

	secure_ipc_mode = true;
	secure_ipc_target_queue = target_runtime_queue_id;

	return 0;
}

static int yield_secure_ipc(void)
{
	uint8_t qid = secure_ipc_target_queue;
	secure_ipc_mode = false;

	wait_until_empty(qid, MAILBOX_QUEUE_SIZE);

	mailbox_yield_to_previous_owner(qid);
	
	reset_ipc_queue_trackers();
	secure_ipc_target_queue = 0;

#ifdef ARCH_SEC_HW
	/* OctopOS mailbox only allows the current owner
	 * to change/yield ownership.
	 * Thus, instead of explicitly yielding it, we attest it.
	 * In case the other runtime refuses to yield, we forcefully
	 * deplete the quota by repeatedly reading the mailbox.
	 */
	if (!mailbox_attest_queue_owner(q_runtime, P_OS)) {
		mailbox_force_ownership(q_runtime, P_OS);
	}
#else
	/*
	 * Or we can just wait for the timeout */
	if (!mailbox_attest_queue_owner(q_runtime, P_OS)) {
		sleep(1);
	}
#endif

	return 0;
}

static int send_msg_on_secure_ipc(char *msg, int size)
{
	if (!secure_ipc_mode)
		return ERR_UNEXPECTED;

	IPC_SET_ZERO_ARGS_DATA(msg, size)
	runtime_send_msg_on_queue(buf, secure_ipc_target_queue);

	report_queue_usage(secure_ipc_target_queue);

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

static void terminate_app(void)
{
	still_running = false;
	inform_os_of_termination();
#ifndef ARCH_SEC_HW
	terminate_app_thread_arch();
#endif
}

#ifndef ARCH_SEC_HW
/*
 * func() should terminate on its own. We don't cancel it anywhere.
 */
static int schedule_func_execution(void *(*func)(void *), void *data)
{
	return schedule_func_execution_arch(func, data);
}
#endif

/* FIXME: use libsodim for cryptographically-secure randomness. */
static uint32_t get_random_uint(void)
{
#ifndef ARCH_SEC_HW
	srand(time(NULL));

	return (uint32_t) rand();	
#else
	/* FIXME: sec_hw libc doesn't have time() */
	return 0;
#endif
}

/* Return time in seconds since some fixed time in the past */
static uint64_t get_time(void)
{
#ifndef ARCH_SEC_HW
	return (uint64_t) time(NULL);
#else
	/* FIXME: sec_hw libc doesn't have time() */
	return 0;
#endif
}

extern bool has_network_access;
extern int network_access_count;

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
		printf("Error: %s: has no or insufficient network access.\n", __func__);
		do_close = false;
	}

	network_access_count -= 5;

	if (do_close)
		_close(sock);

	syscall_close_socket();
}

static int bind_socket(struct socket *sock, struct sock_addr *skaddr)
{
	return network_domain_bind_sport(skaddr->src_port);
}

//static struct socket *accept_connection(struct socket *sock, struct sock_addr *skaddr)
//{
//	return _accept(sock, skaddr);
//}

static int connect_socket(struct socket *sock, struct sock_addr *skaddr)
{
	/* FIXME: 20 packets for connect is an over-approximation. */
	if (!has_network_access || (network_access_count < 10)) {
		printf("Error: %s: has no or insufficient network access.\n",
		       __func__);
		return ERR_INVALID;
	}

	network_access_count -= 10;

	return _connect(sock, skaddr);
}

static int read_from_socket(struct socket *sock, void *buf, int len)
{
	/* FIXME: calculate more precisely how many packets will be needed. */
	if (!has_network_access ||
	    (network_access_count < ((len / MAILBOX_QUEUE_MSG_SIZE_LARGE) + 1))) {
		printf("Error: %s: has no or insufficient network access.\n",
		       __func__);
		return 0;
	}

	/* FIXME: what if _read returns error and doesn't use up these messages */
	network_access_count -= (len / MAILBOX_QUEUE_MSG_SIZE_LARGE) + 1;

	return _read(sock, buf, len);
}

static int write_to_socket(struct socket *sock, void *buf, int len)
{
	/* FIXME: calculate more precisely how many packets will be needed. */
	if (!has_network_access ||
	    (network_access_count < ((len / MAILBOX_QUEUE_MSG_SIZE_LARGE) + 1))) {
		printf("Error: %s: has no or insufficient network access.\n",
		       __func__);
		return 0;
	}

	/* FIXME: what if _read returns error and doesn't use up these messages */
	network_access_count -= (len / MAILBOX_QUEUE_MSG_SIZE_LARGE) + 1;

	return _write(sock, buf, len);
}
#ifdef ARCH_UMODE

static int verify_bluetooth_service_state(uint8_t *device_names,
					  uint32_t num_devices,
					  uint8_t *am_addrs)
{
	uint32_t found = 0;

	BLUETOOTH_SET_ZERO_ARGS(IO_OP_QUERY_STATE)

	runtime_send_msg_on_queue(buf, Q_BLUETOOTH_CMD_IN);
	runtime_recv_msg_from_queue(buf, Q_BLUETOOTH_CMD_OUT);

	BLUETOOTH_GET_ONE_RET_DATA
	if (ret0) {
		printf("Error: %s: received error from the bluetooth service "
		       "(%d)\n", __func__, ret0);
		return (int) ret0;
	}

	/* data[0] is bound. Must be 1.
	 * data[1] is used. Must be 0.
	 * data[2] is authenticated. Must be 0.
	 * data[3] is num_devices. Must be equal to what we expect.
	 * &data[4] is the starting addr for the bound device name/am_addr pairs.
	 */
	if ((_size != (4 + (num_devices * (BD_ADDR_LEN + 1)))) ||
	    (data[0] != 1) || (data[1] != 0) || (data[2] != 0) ||
	    (((uint32_t) data[3]) != num_devices)) {
		printf("Error: %s: bluetooth service state not verified "
		       "(first check).\n", __func__);
		return ERR_UNEXPECTED;
	}

	for (int i = 0; i < num_devices; i++) {
		for (int j = 0; j < num_devices; j++) { 
			if (!memcmp(&data[4 + (i * (BD_ADDR_LEN + 1))],
				    &device_names[j * BD_ADDR_LEN],
				    BD_ADDR_LEN) &&
			    data[4 + (i * (BD_ADDR_LEN + 1)) + BD_ADDR_LEN] ==
								am_addrs[i])
				found++;
		}
	}

	if (found != num_devices) {
		printf("Error: %s: bluetooth service state not verified "
		       "(second check).\n", __func__);
		return ERR_UNEXPECTED;
	}

	return 0;
}

static int deauthenticate_bluetooth(void)
{
	BLUETOOTH_SET_ZERO_ARGS(IO_OP_DEAUTHENTICATE)

	runtime_send_msg_on_queue(buf, Q_BLUETOOTH_CMD_IN);
	runtime_recv_msg_from_queue(buf, Q_BLUETOOTH_CMD_OUT);

	BLUETOOTH_GET_ONE_RET
		
	return (int) ret0;
}

static int request_secure_bluetooth_access(uint8_t *device_names,
					   uint32_t num_devices, limit_t limit,
					   timeout_t timeout, uint8_t *am_addrs,
					   queue_update_callback_t callback,
					   uint8_t *expected_pcr,
					   uint8_t *return_pcr)
{
	int ret;
	uint8_t ret_data[MAILBOX_QUEUE_MSG_SIZE];

	/* request access to the queues */
	reset_queue_sync(Q_BLUETOOTH_CMD_IN, MAILBOX_QUEUE_SIZE);
	reset_queue_sync(Q_BLUETOOTH_CMD_OUT, 0);
	reset_queue_sync(Q_BLUETOOTH_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
	reset_queue_sync(Q_BLUETOOTH_DATA_OUT, 0);

	SYSCALL_SET_THREE_ARGS_DATA(SYSCALL_REQUEST_BLUETOOTH_ACCESS,
				  (uint32_t) limit, (uint32_t) timeout,
				  num_devices, device_names,
				  num_devices * BD_ADDR_LEN)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET_DATA(ret_data)
	if (ret0)
		return (int) ret0;

	if (((uint32_t) _size) != num_devices) {
		printf("Error: %s: invalid response from the OS\n", __func__);
		return ERR_INVALID;
	}

	memcpy(am_addrs, ret_data, _size);

	/* Verify mailbox state */
	ret = mailbox_attest_queue_access(Q_BLUETOOTH_CMD_IN, limit, timeout);
	if (!ret) {
		printf("Error: %s: failed to attest secure bluetooth cmd write "
		       "access\n", __func__);
		return ERR_FAULT;
	}

	ret = mailbox_attest_queue_access(Q_BLUETOOTH_CMD_OUT, limit, timeout);
	if (!ret) {
		printf("Error: %s: failed to attest secure bluetooth cmd read "
		       "access\n", __func__);
		wait_until_empty(Q_BLUETOOTH_CMD_IN, MAILBOX_QUEUE_SIZE);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_IN);
		return ERR_FAULT;
	}

	ret = mailbox_attest_queue_access(Q_BLUETOOTH_DATA_IN, limit, timeout);
	if (!ret) {
		printf("Error: %s: failed to attest secure bluetooth data write "
		       "access\n", __func__);
		wait_until_empty(Q_BLUETOOTH_CMD_IN, MAILBOX_QUEUE_SIZE);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_IN);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_OUT);
		return ERR_FAULT;
	}

	ret = mailbox_attest_queue_access(Q_BLUETOOTH_DATA_OUT, limit, timeout);
	if (!ret) {
		printf("Error: %s: failed to attest secure bluetooth data read "
		       "access\n", __func__);
		wait_until_empty(Q_BLUETOOTH_CMD_IN, MAILBOX_QUEUE_SIZE);
		wait_until_empty(Q_BLUETOOTH_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_IN);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_OUT);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_DATA_IN);
		return ERR_FAULT;
	}

#ifndef UNTRUSTED_DOMAIN
	/* Note: we set the limit/timeout values right after attestation and
	 * before we call check_proc_pcr(). This is because that call issues a
	 * syscall, which might take an arbitrary amount of time.
	 */
	queue_limits[Q_BLUETOOTH_CMD_IN] = limit;
	queue_timeouts[Q_BLUETOOTH_CMD_IN] = timeout;

	queue_limits[Q_BLUETOOTH_CMD_OUT] = limit;
	queue_timeouts[Q_BLUETOOTH_CMD_OUT] = timeout;

	queue_limits[Q_BLUETOOTH_DATA_IN] = limit;
	queue_timeouts[Q_BLUETOOTH_DATA_IN] = timeout;

	queue_limits[Q_BLUETOOTH_DATA_OUT] = limit;
	queue_timeouts[Q_BLUETOOTH_DATA_OUT] = timeout;

	/* Verify TPM PCR val */
	if (expected_pcr) {
		ret = check_proc_pcr(P_BLUETOOTH, expected_pcr);
		if (ret) {
			/* FIXME: the next three error blocks are almost
			 * identical.
			 */
			/* FIXME: also, has a lot in common with the yield func.
			 * (the same for other I/Os)
			 */
			printf("Error: %s: unexpected PCR\n", __func__);
			wait_until_empty(Q_BLUETOOTH_CMD_IN, MAILBOX_QUEUE_SIZE);
			wait_until_empty(Q_BLUETOOTH_DATA_IN,
					 MAILBOX_QUEUE_SIZE_LARGE);
			mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_IN);
			mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_OUT);
			mailbox_yield_to_previous_owner(Q_BLUETOOTH_DATA_IN);
			mailbox_yield_to_previous_owner(Q_BLUETOOTH_DATA_OUT);

			queue_limits[Q_BLUETOOTH_CMD_IN] = 0;
			queue_timeouts[Q_BLUETOOTH_CMD_IN] = 0;
			queue_limits[Q_BLUETOOTH_CMD_OUT] = 0;
			queue_timeouts[Q_BLUETOOTH_CMD_OUT] = 0;
			queue_limits[Q_BLUETOOTH_DATA_IN] = 0;
			queue_timeouts[Q_BLUETOOTH_DATA_IN] = 0;
			queue_limits[Q_BLUETOOTH_DATA_OUT] = 0;
			queue_timeouts[Q_BLUETOOTH_DATA_OUT] = 0;
			return ERR_UNEXPECTED;
		}
	} else if (return_pcr) {
		ret = read_tpm_pcr_for_proc(P_BLUETOOTH, return_pcr);
		if (ret) {
			printf("Error: %s: couldn't read PCR\n", __func__);
			wait_until_empty(Q_BLUETOOTH_CMD_IN, MAILBOX_QUEUE_SIZE);
			wait_until_empty(Q_BLUETOOTH_DATA_IN,
					 MAILBOX_QUEUE_SIZE_LARGE);
			mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_IN);
			mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_OUT);
			mailbox_yield_to_previous_owner(Q_BLUETOOTH_DATA_IN);
			mailbox_yield_to_previous_owner(Q_BLUETOOTH_DATA_OUT);

			queue_limits[Q_BLUETOOTH_CMD_IN] = 0;
			queue_timeouts[Q_BLUETOOTH_CMD_IN] = 0;
			queue_limits[Q_BLUETOOTH_CMD_OUT] = 0;
			queue_timeouts[Q_BLUETOOTH_CMD_OUT] = 0;
			queue_limits[Q_BLUETOOTH_DATA_IN] = 0;
			queue_timeouts[Q_BLUETOOTH_DATA_IN] = 0;
			queue_limits[Q_BLUETOOTH_DATA_OUT] = 0;
			queue_timeouts[Q_BLUETOOTH_DATA_OUT] = 0;
			return ERR_FAULT;
		}
	}

	/* Verify bluetooth service state */
	ret = verify_bluetooth_service_state(device_names, num_devices,
					     am_addrs);
	if (ret) {
		printf("Error: %s: invalid state sent from the bluetooth "
		       "service.\n", __func__);
		wait_until_empty(Q_BLUETOOTH_CMD_IN, MAILBOX_QUEUE_SIZE);
		wait_until_empty(Q_BLUETOOTH_DATA_IN,
				 MAILBOX_QUEUE_SIZE_LARGE);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_IN);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_OUT);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_DATA_IN);
		mailbox_yield_to_previous_owner(Q_BLUETOOTH_DATA_OUT);

		queue_limits[Q_BLUETOOTH_CMD_IN] = 0;
		queue_timeouts[Q_BLUETOOTH_CMD_IN] = 0;
		queue_limits[Q_BLUETOOTH_CMD_OUT] = 0;
		queue_timeouts[Q_BLUETOOTH_CMD_OUT] = 0;
		queue_limits[Q_BLUETOOTH_DATA_IN] = 0;
		queue_timeouts[Q_BLUETOOTH_DATA_IN] = 0;
		queue_limits[Q_BLUETOOTH_DATA_OUT] = 0;
		queue_timeouts[Q_BLUETOOTH_DATA_OUT] = 0;
		return ret;
	}

	queue_update_callbacks[Q_BLUETOOTH_CMD_IN] = callback;
	queue_update_callbacks[Q_BLUETOOTH_CMD_OUT] = callback;
	queue_update_callbacks[Q_BLUETOOTH_DATA_IN] = callback;
	queue_update_callbacks[Q_BLUETOOTH_DATA_OUT] = callback;
#endif

	has_secure_bluetooth_access = true;

	return 0;
}

static int authenticate_with_bluetooth_service(uint8_t *app_signature)
{
	uint32_t remaining_size = RSA_SIGNATURE_SIZE;
	uint32_t msg_size = MAILBOX_QUEUE_MSG_SIZE;
	uint32_t offset = 0;

	BLUETOOTH_SET_ZERO_ARGS(IO_OP_AUTHENTICATE)

	runtime_send_msg_on_queue(buf, Q_BLUETOOTH_CMD_IN);

	/* send the signature */
	while (remaining_size) {
		if (remaining_size < msg_size)
			msg_size = remaining_size;

		memcpy(buf, app_signature + offset, msg_size); 
		runtime_send_msg_on_queue(buf, Q_BLUETOOTH_CMD_IN);

		if (remaining_size >= msg_size)
			remaining_size -= msg_size;
		else
			remaining_size = 0;

		offset += msg_size;
	}

	runtime_recv_msg_from_queue(buf, Q_BLUETOOTH_CMD_OUT);

	BLUETOOTH_GET_ONE_RET
		
	return (int) ret0;
}

static int yield_secure_bluetooth_access(void)
{
	int ret;

	if (!has_secure_bluetooth_access) {
		return ERR_INVALID;
	}

	ret = deauthenticate_bluetooth();
	if (ret) {
		printf("%s: Error: failed to deauthenticate with the bluetooth "
		       "service\n", __func__);
		return ERR_FAULT;
	}

	has_secure_bluetooth_access = false;

	wait_until_empty(Q_BLUETOOTH_CMD_IN, MAILBOX_QUEUE_SIZE);
	wait_until_empty(Q_BLUETOOTH_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

	mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_IN);
	mailbox_yield_to_previous_owner(Q_BLUETOOTH_CMD_OUT);
	mailbox_yield_to_previous_owner(Q_BLUETOOTH_DATA_IN);
	mailbox_yield_to_previous_owner(Q_BLUETOOTH_DATA_OUT);

#ifndef UNTRUSTED_DOMAIN
	reset_bluetooth_queues_trackers();
#endif

	return 0;
}

/* FIXME: ugly. */
/* FIXME: duplicate in bluetooth/bluetooth.c */
static int set_btp_am_addr(struct btpacket *btp, uint8_t am_addr)
{
	switch(am_addr) {
	case 0:
		btp->header1.am_addr = 0;
		return 0;
	case 1:
		btp->header1.am_addr = 1;
		return 0;
	case 2:
		btp->header1.am_addr = 2;
		return 0;
	case 3:
		btp->header1.am_addr = 3;
		return 0;
	case 4:
		btp->header1.am_addr = 4;
		return 0;
	case 5:
		btp->header1.am_addr = 5;
		return 0;
	case 6:
		btp->header1.am_addr = 6;
		return 0;
	case 7:
		btp->header1.am_addr = 7;
		return 0;
	default:
		return ERR_INVALID;
	}
}

int bluetooth_send_data(uint8_t am_addr, uint8_t *data, uint32_t len)
{
	uint8_t buf_large[MAILBOX_QUEUE_MSG_SIZE_LARGE];
	struct btpacket *btp = (struct btpacket *) buf_large;
	int ret;

	if (len > BTPACKET_FIXED_DATA_SIZE) {
		printf("Error: %s: can't send more than %d bytes\n", __func__,
		       BTPACKET_FIXED_DATA_SIZE);
		return ERR_INVALID;
	}

	memset(buf_large, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE);
	memcpy(btp->data, data, len);

	ret = set_btp_am_addr(btp, am_addr);
	if (ret) {
		printf("Error: %s: invalid am_addr (%d)\n", __func__, am_addr);
		return ret;
	}

	/* the arg is the number of packets */
	BLUETOOTH_SET_ONE_ARG(IO_OP_SEND_DATA, 1)

	runtime_send_msg_on_queue(buf, Q_BLUETOOTH_CMD_IN);
	runtime_send_msg_on_queue_large(buf_large, Q_BLUETOOTH_DATA_IN);
	runtime_recv_msg_from_queue(buf, Q_BLUETOOTH_CMD_OUT);

	BLUETOOTH_GET_ONE_RET
	if (ret0) {
		printf("Error: %s: received error from the bluetooth service "
		       "(%d)\n", __func__, ret0);
		return (int) ret0;
	}

	return 0;
}

int bluetooth_recv_data(uint8_t am_addr, uint8_t *data, uint32_t len)
{
	uint8_t buf_large[MAILBOX_QUEUE_MSG_SIZE_LARGE];
	struct btpacket *btp = (struct btpacket *) buf_large;

	if (len > BTPACKET_FIXED_DATA_SIZE) {
		printf("Error: %s: can't receive more than %d bytes\n",
		       __func__, BTPACKET_FIXED_DATA_SIZE);
		return ERR_INVALID;
	}

	runtime_recv_msg_from_queue_large(buf_large, Q_BLUETOOTH_DATA_OUT);

	if (((uint8_t) btp->header1.am_addr) != am_addr) {
		printf("Error: %s: message from unexpected bluetooth device.\n",
		       __func__);
		return ERR_UNEXPECTED;
	}

	memcpy(data, btp->data, len);

	return 0;
}

static int request_tpm_attestation_report(uint32_t *pcr_list, size_t pcr_list_size, 
					  char* nonce, uint8_t **signature,
					  size_t *sig_size, uint8_t **quote,
					  size_t *quote_size)
{
	int rc = 0;
	rc = tpm_attest((uint8_t *) nonce, pcr_list, pcr_list_size,
			signature, sig_size, (char **) quote);
	if (rc != 0)
		return rc;
	
	*quote_size = strlen((char *) *quote);
	return 0;
}

/* FIXME: why do we need this func? Why not just directly use
 * tpm_processor_read_pcr()?
 */
int read_tpm_pcr_for_proc(uint8_t proc_id, uint8_t *pcr_val)
{
	tpm_processor_read_pcr(PROC_TO_PCR(proc_id), pcr_val);
	return 0;
}
#endif

#ifdef ARCH_SEC_HW_EVALUATION
extern long long global_counter;
#endif

#ifndef ARCH_SEC_HW_BOOT
static void load_application(char *msg)
{
#ifdef ARCH_SEC_HW_EVALUATION
	global_counter = 0;
#endif

	/* The bound is the length of load_buf minus one (for the null
	 * terminator)
	 */
	size_t msg_str_len = strlen(msg);
	if (msg_str_len > (MAILBOX_QUEUE_MSG_SIZE - 2)) {
		printf("Error: %s: invalid msg string len (%lu).\n", __func__,
		       msg_str_len);
		return;
	}

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
		.get_file_size = get_file_size,
		.close_file = close_file,
		.remove_file = remove_file,
		.request_secure_storage_access = request_secure_storage_access,
		.yield_secure_storage_access = yield_secure_storage_access,
		.delete_and_yield_secure_storage =
					delete_and_yield_secure_storage,
		.write_secure_storage_blocks = write_secure_storage_blocks,
		.read_secure_storage_blocks = read_secure_storage_blocks,
		.write_to_secure_storage_block = write_to_secure_storage_block,
		.read_from_secure_storage_block = read_from_secure_storage_block,
		.set_up_context = set_up_context,
		.write_context_to_storage = write_context_to_storage,
		.request_secure_ipc = request_secure_ipc,
		.yield_secure_ipc = yield_secure_ipc,
		.send_msg_on_secure_ipc = send_msg_on_secure_ipc,
		.recv_msg_on_secure_ipc = recv_msg_on_secure_ipc,
#ifndef ARCH_SEC_HW
		.request_tpm_attestation_report = request_tpm_attestation_report,
#endif
		.get_runtime_proc_id = get_runtime_proc_id,
		.get_runtime_queue_id = get_runtime_queue_id,
		.terminate_app = terminate_app,
#ifndef ARCH_SEC_HW
		.schedule_func_execution = schedule_func_execution,
#endif
		.get_random_uint = get_random_uint,
		.get_time = get_time,
		.create_socket = create_socket,
		//.listen_on_socket = listen_on_socket,
		.close_socket = close_socket,
		.bind_socket = bind_socket,
		//.accept_connection = accept_connection,
		.connect_socket = connect_socket,
		.read_from_socket = read_from_socket,
		.write_to_socket = write_to_socket,
		.request_network_access = request_network_access,
		.yield_network_access = yield_network_access,
#ifndef ARCH_SEC_HW
		.request_secure_bluetooth_access =
					request_secure_bluetooth_access,
		.authenticate_with_bluetooth_service =
					authenticate_with_bluetooth_service,
		.yield_secure_bluetooth_access = yield_secure_bluetooth_access,
		.bluetooth_send_data = bluetooth_send_data,
		.bluetooth_recv_data = bluetooth_recv_data,
#endif
	};

#ifndef ARCH_SEC_HW
	/* Retrieve app from FS */
	uint32_t fd = open_file(msg, FILE_OPEN_MODE);
	if (!fd) {
		printf("Error: %s: couldn't retrieve app.\n", __func__);
		return;
	}

	uint32_t file_size = get_file_size(fd);
	if (!file_size) {
		printf("Error: %s: couldn't retrieve file size.\n", __func__);
		close_file(fd);
		return;
	}

	int num_blocks = file_size / STORAGE_BLOCK_SIZE;
	if (file_size % STORAGE_BLOCK_SIZE)
		num_blocks++;

	uint8_t *file_data = (uint8_t *) malloc(num_blocks * STORAGE_BLOCK_SIZE);
	if (!file_data) {
		printf("Error: %s: couldn't allocate memory.\n", __func__);
		close_file(fd);
		return;
	}

	int num_read_blocks = read_file_blocks(fd, file_data, 0, num_blocks);
	if (num_read_blocks != num_blocks) {
		printf("Error: %s: couldn't read all file blocks.\n", __func__);
		close_file(fd);
		return;
	}

	close_file(fd);

	/* write to a local file */
	char path[2 * MAILBOX_QUEUE_MSG_SIZE];
	memset(path, 0x0, 2 * MAILBOX_QUEUE_MSG_SIZE);
	/* FIXME: use a different path. */
	strcpy(path, "./bootloader/");
	strcat(path, msg);
	strcat(path, ".so");

	FILE *filep = fopen(path, "w");
	if (!filep) {
		printf("Error: %s: Couldn't open the file (%s).\n", __func__,
		       path);
		return;
	}

	fseek(filep, 0, SEEK_SET);
	size_t write_ret = fwrite(file_data, sizeof(uint8_t),
				  (size_t) file_size, filep);
	if (write_ret != (size_t) file_size) {
		printf("Error: %s: Couldn't write to local file (%lu).\n",
		       __func__, write_ret);
		return;
	}

	fclose(filep);

	/* Finally, run the app. */
	load_application_arch(path, &api);
#else
	load_application_arch(msg, &api);
#endif

	return;
}

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

#else /* ARCH_SEC_HW_BOOT */

void *run_app(void *load_buf) {}

#endif /* ARCH_SEC_HW_BOOT */

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

void *store_context(void *data)
{
	int ret;

	ret = write_context_to_storage(1);
	if (ret)
		return NULL;

#ifdef ARCH_SEC_HW
	async_syscall_mode = false;
#endif
	still_running = false;
	inform_os_of_pause();

	return NULL;
}

#ifdef ARCH_UMODE
int main(int argc, char **argv)
#else
int main()
#endif
{
	int runtime_id = -1;

	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);

	/* Need to make sure msgs are big enough so that we don't overflow
	 * when processing incoming msgs and preparing outgoing ones.
	 */
	/* FIXME: find the smallest bound. 64 is conservative. */
	if (MAILBOX_QUEUE_MSG_SIZE < 64) {
		printf("Error: %s: MAILBOX_QUEUE_MSG_SIZE is too small (%d).\n",
		       __func__, MAILBOX_QUEUE_MSG_SIZE);
		return -1;
	}
	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error: %s: storage data queue msg size must be equal "
		       "to storage block size\n", __func__);
		return -1;
	}

#ifdef ARCH_UMODE
	if (argc != 2) {
		printf("Error: %s: incorrect command. Use ``runtime "
		       "<runtime_ID>''.\n", __func__);
		return -1;
	}

	runtime_id = atoi(argv[1]);
#else
	runtime_id = RUNTIME_ID;

#endif
	printf("%s: runtime%d init\n", __func__, runtime_id);

	if (runtime_id < 1 || runtime_id > 2) {
		printf("Error: %s: invalid runtime ID.\n", __func__);
		return -1;
	}
	int ret = init_runtime(runtime_id);

	if (ret) {
		printf("Error: %s: couldn't initialize the runtime\n", __func__);
		return -1;
	}

#ifndef ARCH_SEC_HW
	enforce_running_process(p_runtime);
#endif

	/* initialize syscall response queue */
	/* FIXME: release memory on exit */
	syscall_resp_queue = allocate_memory_for_queue(MAILBOX_QUEUE_SIZE,
						       MAILBOX_QUEUE_MSG_SIZE);
	srq_size = MAILBOX_QUEUE_SIZE;
	srq_msg_size = MAILBOX_QUEUE_MSG_SIZE;
	srq_counter = 0;
	srq_head = 0;
	srq_tail = 0;

	sem_init(&srq_sem, 0, MAILBOX_QUEUE_SIZE);

	for (int i = 0; i < (NUM_QUEUES + 1); i++) {
		queue_limits[i] = 0;
		queue_timeouts[i] = 0;
		queue_update_callbacks[i] = NULL;
	}

#ifdef ARCH_UMODE
	ret = net_stack_init();
	if (ret) {
		printf("Error: %s: couldn't initialize the runtime network "
		       "stack\n", __func__);
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
