/* OctopOS runtime mailbox interface */
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
#include <network/tcp_timer.h>
#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/error.h>

/* FIXME: also repeated in runtime.c */
typedef int bool;
#define true	(int) 1
#define false	(int) 0

extern int p_runtime;
extern int q_runtime;
extern int q_os;

uint8_t load_buf[MAILBOX_QUEUE_MSG_SIZE - 1];
extern bool still_running;

extern int change_queue;

extern bool secure_ipc_mode;

char fifo_runtime_out[64];
char fifo_runtime_in[64];
char fifo_runtime_intr[64];
int fd_out, fd_in, fd_intr;

/* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];
sem_t interrupt_change;

sem_t load_app_sem;

pthread_spinlock_t mailbox_lock;

void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id)
{
	uint8_t opcode[4];

	opcode[0] = MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	opcode[3] = proc_id;
	pthread_spin_lock(&mailbox_lock);	
	write(fd_out, opcode, 4);
	pthread_spin_unlock(&mailbox_lock);	
}

int mailbox_attest_queue_access(uint8_t queue_id, uint8_t access, uint8_t count)
{
	uint8_t opcode[4], ret;

	opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	opcode[3] = count;
	pthread_spin_lock(&mailbox_lock);	
	write(fd_out, opcode, 4);
	read(fd_in, &ret, 1);
	pthread_spin_unlock(&mailbox_lock);	

	return (int) ret; 
}

static void _runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	/* wait for message */
	sem_wait(&interrupts[queue_id]);
	pthread_spin_lock(&mailbox_lock);	
	write(fd_out, opcode, 2), 
	read(fd_in, buf, queue_msg_size);
	pthread_spin_unlock(&mailbox_lock);	
}

static void _runtime_send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	sem_wait(&interrupts[queue_id]);
	pthread_spin_lock(&mailbox_lock);	
	write(fd_out, opcode, 2);
	write(fd_out, buf, queue_msg_size);
	pthread_spin_unlock(&mailbox_lock);	
}

void runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_recv_msg_from_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE);
}

void runtime_send_msg_on_queue(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_send_msg_on_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE);
}

void runtime_recv_msg_from_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_recv_msg_from_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_send_msg_on_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void is_ownership_change(int *is_change)
{
	sem_getvalue(&interrupt_change, is_change);
	if (*is_change)
		sem_wait(&interrupt_change);
}

void reset_queue_sync(uint8_t queue_id, int init_val)
{
	sem_init(&interrupts[queue_id], 0, init_val);
}

void queue_sync_getval(uint8_t queue_id, int *val)
{
	sem_getvalue(&interrupts[queue_id], val);
}

void wait_on_queue(uint8_t queue_id)
{
	sem_wait(&interrupts[queue_id]);
}

void wait_for_app_load(void)
{
	sem_wait(&load_app_sem);
}

typedef void (*app_main_proc)(struct runtime_api *);

void load_application_arch(char *msg, struct runtime_api *api)
{
	void *app;
	char path[2 * MAILBOX_QUEUE_MSG_SIZE] = "../applications/bin/";
	app_main_proc app_main;

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

	runtime_send_msg_on_queue_large((uint8_t *)path, Q_TPM_DATA_IN);

	(*app_main)(api);
}

pthread_t app_thread, ctx_thread;
bool has_ctx_thread = false;

/* FIXME: move to a header file */
int write_syscall_response(uint8_t *buf);
void *store_context(void *data);
void *run_app(void *data);

void runtime_core(void)
{
	uint8_t interrupt;
	bool keep_polling = true;

	/* interrupt handling loop */
	while (keep_polling) {
		read(fd_intr, &interrupt, 1);
		if (interrupt < 1 || interrupt > (2 * NUM_QUEUES)) {
			printf("Error: invalid interrupt (%d)\n", interrupt);
			exit(-1);
		} else if (interrupt > NUM_QUEUES) {
			if ((interrupt - NUM_QUEUES) == change_queue)
			{
				sem_post(&interrupt_change);
				sem_post(&interrupts[q_runtime]);
			}
			else if ((interrupt - NUM_QUEUES) == Q_TPM_DATA_IN)
			{
				sem_post(&interrupts[Q_TPM_DATA_IN]);
			}

			/* ignore the rest */
			continue;
		} else if (interrupt == q_runtime && !secure_ipc_mode) {
			uint8_t opcode[2];
			uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

			opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
			opcode[1] = q_runtime;
			pthread_spin_lock(&mailbox_lock);
			write(fd_out, opcode, 2);
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			pthread_spin_unlock(&mailbox_lock);
			if (buf[0] == RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG) {
				write_syscall_response(buf);
				sem_post(&interrupts[interrupt]);
				if (!still_running)
					keep_polling = false;
			} else if (buf[0] == RUNTIME_QUEUE_EXEC_APP_TAG) {
				memcpy(load_buf, &buf[1], MAILBOX_QUEUE_MSG_SIZE - 1);
				sem_post(&load_app_sem);
			} else if (buf[0] == RUNTIME_QUEUE_CONTEXT_SWITCH_TAG) {
				//TODO
				pthread_cancel(app_thread);
				pthread_join(app_thread, NULL);
				int ret = pthread_create(&ctx_thread, NULL, store_context, NULL);
				if (ret)
					printf("Error: couldn't launch the app thread\n");
				has_ctx_thread = true;
			}  else {
				printf("Error: %s: received invalid message (%d).\n", __func__, buf[0]);
				exit(-1);
			}
		} else {
			sem_post(&interrupts[interrupt]);
		}
	}
}

/* Initializes the runtime and its mailbox */
int init_runtime(int runtime_id)
{
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

	//int ret = net_stack_init();
	//if (ret) {
	//	printf("%s: Error: couldn't initialize the runtime network stack\n", __func__);
	//	return -1;
	//}

	mkfifo(fifo_runtime_out, 0666);
	mkfifo(fifo_runtime_in, 0666);
	mkfifo(fifo_runtime_intr, 0666);

	fd_out = open(fifo_runtime_out, O_WRONLY);
	fd_in = open(fifo_runtime_in, O_RDONLY);
	fd_intr = open(fifo_runtime_intr, O_RDONLY);

	sem_init(&interrupts[q_os], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[q_runtime], 0, 0);
	sem_init(&interrupts[Q_TPM_DATA_IN], 0, 0);

	sem_init(&load_app_sem, 0, 0);

	pthread_spin_init(&mailbox_lock, PTHREAD_PROCESS_PRIVATE);

	int ret = pthread_create(&app_thread, NULL, run_app, load_buf);
	if (ret) {
		printf("Error: couldn't launch the app thread\n");
		return -1;
	}

	return 0;
}

void close_runtime(void)
{
	if (has_ctx_thread)
		pthread_join(ctx_thread, NULL);

	pthread_join(app_thread, NULL);

	/* FIXME: free the memory allocated for srq */

	/* FIXME: resetting the mailbox needs to be done automatically. */
	uint8_t opcode[2];
	opcode[0] = MAILBOX_OPCODE_RESET;
	pthread_spin_lock(&mailbox_lock);	
	write(fd_out, opcode, 2);
	pthread_spin_unlock(&mailbox_lock);	

	pthread_spin_destroy(&mailbox_lock);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(fifo_runtime_out);
	remove(fifo_runtime_in);
	remove(fifo_runtime_intr);
}
