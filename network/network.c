/* octopos network code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/error.h>
#include "netif.h"
#include "route.h"
#include "arp.h"
#include "lib.h"

#define NETWORK_SET_ONE_RET(ret0)	\
	*((uint32_t *) &buf[0]) = ret0; \

#define NETWORK_SET_TWO_RETS(ret0, ret1)	\
	*((uint32_t *) &buf[0]) = ret0;		\
	*((uint32_t *) &buf[4]) = ret1;		\

/* FIXME: when calling this one, we need to allocate a ret_buf. Can we avoid that? */
#define NETWORK_SET_ONE_RET_DATA(ret0, data, size)		\
	*((uint32_t *) &buf[0]) = ret0;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 5;		\
	if (max_size < 256 && size <= ((int) max_size)) {	\
		buf[4] = (uint8_t) size;			\
		memcpy(&buf[5], data, size);			\
	} else {						\
		printf("Error: invalid max_size or size\n");	\
		buf[4] = 0;					\
	}

#define NETWORK_GET_ONE_ARG		\
	uint32_t arg0;			\
	arg0 = *((uint32_t *) &buf[1]); \

#define NETWORK_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	arg0 = *((uint32_t *) &buf[1]); \
	arg1 = *((uint32_t *) &buf[5]); \

#define NETWORK_GET_THREE_ARGS		\
	uint32_t arg0, arg1, arg2;	\
	arg0 = *((uint32_t *) &buf[1]); \
	arg1 = *((uint32_t *) &buf[5]); \
	arg2 = *((uint32_t *) &buf[9]);\

#define NETWORK_GET_TWO_ARGS_DATA				\
	uint32_t arg0, arg1;					\
	uint8_t data_size, *data;				\
	arg0 = *((uint32_t *) &buf[1]);				\
	arg1 = *((uint32_t *) &buf[5]);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 10;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		NETWORK_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data_size = buf[9];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		NETWORK_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data = &buf[10];					\

#define NETWORK_GET_ZERO_ARGS_DATA				\
	uint8_t data_size, *data;				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 2;		\
	if (max_size >= 256) {					\
		printf("Error: max_size not supported\n");	\
		NETWORK_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data_size = buf[1];					\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		NETWORK_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		return;						\
	}							\
	data = &buf[2];

int fd_out, fd_in, fd_intr;

/* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];

unsigned int net_debug = 0;
pthread_t net_threads[2];

void net_stack_init(void)
{
	netdev_init();
	arp_cache_init();
	rt_init();
}

int net_stack_run(void)
{
	/* create timer thread */
	int ret = pthread_create(&net_threads[0], NULL, (pfunc_t) net_timer, NULL);
	if (ret) {
		printf("Error: couldn't launch net_thread[0]\n");
		return -1;
	}
	/* create netdev thread */
	ret = pthread_create(&net_threads[1], NULL, (pfunc_t) netdev_interrupt, NULL);
	if (ret) {
		printf("Error: couldn't launch net_thread[1]\n");
		return -1;
	}

	return 0;
}

void net_stack_exit(void)
{
	int ret = pthread_cancel(net_threads[0]);
	if (ret)
		printf("Error: couldn't kill net_threads[0]");

	ret = pthread_cancel(net_threads[1]);
	if (ret)
		printf("Error: couldn't kill net_threads[1]");

	netdev_exit();
}

static int initialize_network(void)
{
	net_stack_init();
	return net_stack_run();
}

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		read(fd_intr, &interrupt, 1);
		if (interrupt < 1 || interrupt > NUM_QUEUES) {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
		sem_post(&interrupts[interrupt]);
		if (interrupt == Q_NETWORK_DATA_IN)
			sem_post(&interrupts[Q_NETWORK_CMD_IN]);
	}
}

/* FIXME: identical copy form storage.c */
static void send_response(uint8_t *buf, uint8_t queue_id)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[queue_id]);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

int main(int argc, char **argv)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t opcode[2];
	pthread_t mailbox_thread;
	int is_data_queue = 0;

	sem_init(&interrupts[Q_NETWORK_DATA_IN], 0, 0);
	sem_init(&interrupts[Q_NETWORK_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_NETWORK_CMD_IN], 0, 0);
	sem_init(&interrupts[Q_NETWORK_CMD_OUT], 0, MAILBOX_QUEUE_SIZE);

	int ret = initialize_network();
	if (ret) {
		printf("Error: couldn't initialize the network\n");
		return -1;
	}

	mkfifo(FIFO_NETWORK_OUT, 0666);
	mkfifo(FIFO_NETWORK_IN, 0666);
	mkfifo(FIFO_NETWORK_INTR, 0666);

	fd_out = open(FIFO_NETWORK_OUT, O_WRONLY);
	fd_in = open(FIFO_NETWORK_IN, O_RDONLY);
	fd_intr = open(FIFO_NETWORK_INTR, O_RDONLY);

	ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		sem_wait(&interrupts[Q_NETWORK_CMD_IN]);
		sem_getvalue(&interrupts[Q_NETWORK_DATA_IN], &is_data_queue);
		if (!is_data_queue) {
			opcode[1] = Q_NETWORK_CMD_IN;
			write(fd_out, opcode, 2), 
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			//process_cmd(buf);
			send_response(buf, Q_NETWORK_CMD_OUT);
		} else {
			sem_wait(&interrupts[Q_NETWORK_DATA_IN]);
			opcode[1] = Q_NETWORK_DATA_IN;
			write(fd_out, opcode, 2); 
			/* FIXME: where to read to? */
			//read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			//process_data(buf);
		}
	}
	
	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_NETWORK_OUT);
	remove(FIFO_NETWORK_IN);
	remove(FIFO_NETWORK_INTR);

	net_stack_exit();
}
