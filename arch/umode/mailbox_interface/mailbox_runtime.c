/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
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
#include <tpm/tpm.h>
#include <arch/mailbox.h>

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

pthread_t app_thread, ctx_thread;
bool has_ctx_thread = false;

/* FIXME: move to a header file */
int write_syscall_response(uint8_t *buf);
void *store_context(void *data);
void *run_app(void *data);
void timer_tick(void);

void mailbox_yield_to_previous_owner(uint8_t queue_id)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_YIELD_QUEUE_ACCESS;
	opcode[1] = queue_id;
	pthread_spin_lock(&mailbox_lock);	
	write(fd_out, opcode, 2);
	pthread_spin_unlock(&mailbox_lock);	
}

static mailbox_state_reg_t mailbox_read_state_register(uint8_t queue_id)
{
	uint8_t opcode[2];
	mailbox_state_reg_t state;

	opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
	opcode[1] = queue_id;
	pthread_spin_lock(&mailbox_lock);	
	write(fd_out, opcode, 2);
	read(fd_in, &state, sizeof(mailbox_state_reg_t));
	pthread_spin_unlock(&mailbox_lock);

	return state;
}

int mailbox_attest_queue_access(uint8_t queue_id, limit_t limit,
				timeout_t timeout)
{
	mailbox_state_reg_t state;

	state = mailbox_read_state_register(queue_id);

	return ((state.limit == limit) && (state.timeout == timeout));
}

int mailbox_attest_queue_owner(uint8_t queue_id, uint8_t owner)
{
	mailbox_state_reg_t state;

	state = mailbox_read_state_register(queue_id);

	return (state.owner == owner);
}

static void _runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	/* wait for message */
	sem_wait(&interrupts[queue_id]);
	pthread_spin_lock(&mailbox_lock);
	write(fd_out, opcode, 2);
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

int send_cmd_to_network(uint8_t *buf)
{
	runtime_send_msg_on_queue(buf, Q_NETWORK_CMD_IN);
	runtime_recv_msg_from_queue(buf, Q_NETWORK_CMD_OUT);

	return 0;
}


void runtime_recv_msg_from_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_recv_msg_from_queue(buf, queue_id,
					    MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return _runtime_send_msg_on_queue(buf, queue_id,
					  MAILBOX_QUEUE_MSG_SIZE_LARGE);
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

int schedule_func_execution_arch(void *(*func)(void *), void *data)
{
	pthread_t worker_thread;

	int ret = pthread_create(&worker_thread, NULL, (pfunc_t) func, data);
	if (ret) {
		printf("Error: couldn't launch worker thread\n");
		return ret;
	}

	return 0;
}

void wait_for_app_load(void)
{
	sem_wait(&load_app_sem);
}

typedef void (*app_main_proc)(struct runtime_api *);

void load_application_arch(char *path, struct runtime_api *api)
{
	void *app;
	app_main_proc app_main;

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

	tpm_measure_service(path, 1);

	(*app_main)(api);
}

/*
 * Can be called in the app thread or in interrupt context.
 */
void terminate_app_thread_arch(void)
{
	if (pthread_self() == app_thread) {
		pthread_exit(NULL);
	} else {
		pthread_cancel(app_thread);
		pthread_join(app_thread, NULL);
	}
}

void runtime_core(void)
{
	uint8_t interrupt;
	bool keep_polling = true;

	/* interrupt handling loop */
	while (keep_polling) {
		read(fd_intr, &interrupt, 1);
		if (interrupt == 0) {
			timer_tick();
		} else if (interrupt < 1 || interrupt > (2 * NUM_QUEUES)) {
			printf("Error: invalid interrupt (%d)\n", interrupt);
			exit(-1);
		} else if (interrupt > NUM_QUEUES) {
			if ((interrupt - NUM_QUEUES) == change_queue) {
				sem_post(&interrupt_change);
				sem_post(&interrupts[q_runtime]);
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

	fd_out = open(fifo_runtime_out, O_WRONLY);
	fd_in = open(fifo_runtime_in, O_RDONLY);
	fd_intr = open(fifo_runtime_intr, O_RDONLY);

	sem_init(&interrupts[q_os], 0, MAILBOX_QUEUE_SIZE);
	sem_init(&interrupts[q_runtime], 0, 0);

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

	pthread_spin_destroy(&mailbox_lock);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	/* Wait to be terminated by the OS. */
	while(1) {
		sleep(10);
	}
}
