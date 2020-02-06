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
#include <network/netif.h>
#include <network/route.h>
#include <network/arp.h>
#include <network/lib.h>
#include <network/ip.h>
#include <network/tcp.h>

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


#define NETWORK_GET_ZERO_ARGS_DATA				\
	uint8_t *data;						\
	uint16_t data_size;					\
	uint16_t max_size = MAILBOX_QUEUE_MSG_SIZE_LARGE - 2;	\
	if (max_size >= 65536) {				\
		printf("Error: max_size not supported\n");	\
		NETWORK_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		exit(-1);					\
		return;						\
	}							\
	data_size = *((uint16_t *) &buf[0]);			\
	if (data_size > max_size) {				\
		printf("Error: size not supported\n");		\
		NETWORK_SET_ONE_RET((uint32_t) ERR_INVALID)	\
		exit(-1);					\
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
	printf("%s [1]\n", __func__);
	net_stack_init();
	printf("%s [2]\n", __func__);
	return net_stack_run();
}

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		printf("%s [1]\n", __func__);
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

static void send_packet(uint8_t *buf)
{
	printf("%s [1]\n", __func__);
	NETWORK_GET_ZERO_ARGS_DATA
	printf("%s [1.1]: data_size = %d\n", __func__, data_size);
	struct pkbuf *pkb = (struct pkbuf *) data;
	pkb->pk_refcnt = 2; /* prevents the network code from freeing the pkb */
	list_init(&pkb->pk_list);
	//pkb_safe();
	if (data_size != (pkb->pk_len + sizeof(*pkb))) {
		printf("%s: Error: packet size is not correct.\n", __func__);
		NETWORK_SET_ONE_RET((uint32_t) ERR_INVALID)
		//free_pkb(pkb);
		exit(-1);
		return;
	}
	//for (int i = 0; i < data_size; i++)
	//	printf("%d = %d\n", i, (int) data[i]);	

	//struct tcp *otcp = (struct tcp *)pkb2ip(pkb)->ip_data;
	//printf("%s [2]: otcp->dst = %d, octp->src = %d\n", __func__, _ntohs(otcp->dst), _ntohs(otcp->src));

	printf("%s [3]: pkb = %p\n", __func__, pkb);
	ip_send_out(pkb);
	printf("%s [4]\n", __func__);
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

/* FIXME: identical copy form storage.c */
static void send_response_large(uint8_t *buf, uint8_t queue_id)
{
	uint8_t opcode[2];

	sem_wait(&interrupts[queue_id]);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void tcp_in(struct pkbuf *pkb)
{
	printf("%s [1]: pkb->pk_len = %d\n", __func__, pkb->pk_len);
	int size = pkb->pk_len + sizeof(*pkb);
	printf("%s [3.1]: size = %d\n", __func__, size);
	NETWORK_SET_ZERO_ARGS_DATA(pkb, size);
	printf("%s [3.2]\n", __func__);
	send_response_large(buf, Q_NETWORK_DATA_OUT);
	printf("%s [3.3]\n", __func__);
	//for (int i = 2; i < (size + 2); i++)
	//	printf("%d = %d\n", i - 2, (int) buf[i]);
}

int main(int argc, char **argv)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE_LARGE];
	uint8_t opcode[2];
	pthread_t mailbox_thread;
	int is_data_queue = 0;
	printf("%s [1]\n", __func__);

	sem_init(&interrupts[Q_NETWORK_DATA_IN], 0, 0);
	sem_init(&interrupts[Q_NETWORK_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);
	sem_init(&interrupts[Q_NETWORK_CMD_IN], 0, 0);
	sem_init(&interrupts[Q_NETWORK_CMD_OUT], 0, MAILBOX_QUEUE_SIZE);

	int ret = initialize_network();
	if (ret) {
		printf("Error: couldn't initialize the network\n");
		return -1;
	}
	printf("%s [2]\n", __func__);

	mkfifo(FIFO_NETWORK_OUT, 0666);
	mkfifo(FIFO_NETWORK_IN, 0666);
	mkfifo(FIFO_NETWORK_INTR, 0666);
	printf("%s [2.1]\n", __func__);

	fd_out = open(FIFO_NETWORK_OUT, O_WRONLY);
	printf("%s [2.2]\n", __func__);
	fd_in = open(FIFO_NETWORK_IN, O_RDONLY);
	printf("%s [2.3]\n", __func__);
	fd_intr = open(FIFO_NETWORK_INTR, O_RDONLY);
	printf("%s [2.4]\n", __func__);

	ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}
	printf("%s [3]\n", __func__);

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	
	while(1) {
		printf("%s [4]\n", __func__);
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE);
		sem_wait(&interrupts[Q_NETWORK_CMD_IN]);
		sem_getvalue(&interrupts[Q_NETWORK_DATA_IN], &is_data_queue);
		if (!is_data_queue) {
			printf("%s [5]\n", __func__);
			opcode[1] = Q_NETWORK_CMD_IN;
			write(fd_out, opcode, 2), 
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			//process_cmd(buf);
			send_response(buf, Q_NETWORK_CMD_OUT);
		} else {
			uint8_t *dbuf = malloc(MAILBOX_QUEUE_MSG_SIZE_LARGE);
			if (!dbuf) {
				printf("%s: Error: could not allocate memory\n", __func__);
				continue;
			}
			printf("%s [6]\n", __func__);
			sem_wait(&interrupts[Q_NETWORK_DATA_IN]);
			opcode[1] = Q_NETWORK_DATA_IN;
			write(fd_out, opcode, 2); 
			read(fd_in, dbuf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
			send_packet(dbuf);
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
