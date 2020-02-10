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

#define NETWORK_GET_FOUR_ARGS			\
	uint32_t arg0, arg1, arg2, arg3;	\
	arg0 = *((uint32_t *) &buf[0]);		\
	arg1 = *((uint32_t *) &buf[4]);		\
	arg2 = *((uint32_t *) &buf[8]);		\
	arg3 = *((uint32_t *) &buf[12]);	\

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

static int tcp_init_pkb(struct pkbuf *pkb)
{
	struct ip *iphdr = pkb2ip(pkb);
	/* fill ip head */
	iphdr->ip_hlen = IP_HRD_SZ >> 2;
	iphdr->ip_ver = IP_VERSION_4;
	iphdr->ip_tos = 0;
	iphdr->ip_len = _htons(pkb->pk_len - ETH_HRD_SZ);
	iphdr->ip_fragoff = 0;
	iphdr->ip_ttl = TCP_DEFAULT_TTL;
	iphdr->ip_pro = IP_P_TCP;
		
	if (rt_output(pkb) < 0)
		return -1;

	return 0;
}

unsigned int saddr = 0, daddr = 0;
unsigned short sport = 0, dport = 0;
int filter_set = 0;

static void send_packet(uint8_t *buf)
{
	if (!filter_set) {
		printf("%s: Error: queue filter not set.\n", __func__);
		return;
	}

	NETWORK_GET_ZERO_ARGS_DATA
	struct pkbuf *pkb = (struct pkbuf *) data;
	pkb->pk_refcnt = 2; /* prevents the network code from freeing the pkb */
	list_init(&pkb->pk_list);
	/* FIXME: add */
	//pkb_safe();
	if (data_size != (pkb->pk_len + sizeof(*pkb))) {
		printf("%s: Error: packet size is not correct.\n", __func__);
		return;
	}

	/* check the IP addresses */
	struct ip *iphdr = pkb2ip(pkb);
	if ((saddr != iphdr->ip_src) || (daddr != iphdr->ip_dst)) {
		printf("%s: Error: invalid src or dst IP addresses.\n", __func__);
		return;
	}

	/* check the port numbers */
	struct tcp *tcphdr = (struct tcp *) iphdr->ip_data;
	if ((sport != tcphdr->src) || (dport != tcphdr->dst)) {
		printf("%s: Error: invalid src or dst port numbers.\n", __func__);
		return;
	}

	tcp_init_pkb(pkb);
	/* TCP checksum */
	tcp_set_checksum(iphdr, tcphdr);

	ip_send_out(pkb);
}

static void process_cmd(uint8_t *buf)
{
	NETWORK_GET_FOUR_ARGS
	saddr = (unsigned int) arg0;
	sport = (unsigned short) arg1;
	daddr = (unsigned int) arg2;
	dport = (unsigned short) arg3;

	filter_set = 1;
	NETWORK_SET_ONE_RET((unsigned int) 0)
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
static void send_received_packet(uint8_t *buf, uint8_t queue_id)
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
	/* check the IP addresses */
	struct ip *iphdr = pkb2ip(pkb);
	if ((daddr != iphdr->ip_src) || (saddr != iphdr->ip_dst)) {
		printf("%s: Error: invalid src or dst IP addresses. Dropping the packet\n", __func__);
		return;
	}

	/* check the port numbers */
	struct tcp *tcphdr = (struct tcp *) iphdr->ip_data;
	if ((dport != tcphdr->src) || (sport != tcphdr->dst)) {
		printf("%s: Error: invalid src or dst port numbers. Dropping the packet\n", __func__);
		return;
	}

	int size = pkb->pk_len + sizeof(*pkb);
	NETWORK_SET_ZERO_ARGS_DATA(pkb, size);
	send_received_packet(buf, Q_NETWORK_DATA_OUT);
}

int main(int argc, char **argv)
{
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
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	
	while(1) {
		sem_wait(&interrupts[Q_NETWORK_CMD_IN]);
		sem_getvalue(&interrupts[Q_NETWORK_DATA_IN], &is_data_queue);
		if (!is_data_queue) {
			memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
			opcode[1] = Q_NETWORK_CMD_IN;
			write(fd_out, opcode, 2), 
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			process_cmd(buf);
			send_response(buf, Q_NETWORK_CMD_OUT);
		} else {
			uint8_t *dbuf = malloc(MAILBOX_QUEUE_MSG_SIZE_LARGE);
			if (!dbuf) {
				printf("%s: Error: could not allocate memory\n", __func__);
				continue;
			}
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
