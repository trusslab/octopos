#ifndef ARCH_SEC_HW
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
#include <arch/mailbox.h>
#include <octopos/io.h>
#include <arch/syscall.h> 

/* Need to make sure msgs are big enough so that we don't overflow
 * when processing incoming msgs and preparing outgoing ones.
 */
#if MAILBOX_QUEUE_MSG_SIZE < 64
#error MAILBOX_QUEUE_MSG_SIZE is too small.
#endif

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


#define NETWORK_GET_ONE_ARG		\
	uint32_t arg0;			\
	DESERIALIZE_32(&arg0, &buf[1])	\

uint32_t bound_sport = 0; /* 0xFF is an invalid partition number. */
uint8_t bound = 0;
uint8_t used = 0;
extern uint8_t dbuf[MAILBOX_QUEUE_MSG_SIZE_LARGE];

#define ARBITER_UNTRUSTED 1
#define ARBITER_UNTRUSTED_FLAG 0xF0F0F0F0
#define ARBITER_TRUSTED 0
#define ARBITER_TRUSTED_FLAG 0
#define ARBITER_BASE_ADDRESS 0xF0880000
#define TRUSTED_PORT_BOUNDARY 5000
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
			printf("Error: interrupt from an invalid queueee (%d)\n", interrupt);
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
	/* FIXME: set in the client only. */
	//iphdr->ip_id = _htons(tcp_id);
	iphdr->ip_fragoff = 0;
	iphdr->ip_ttl = TCP_DEFAULT_TTL;
	iphdr->ip_pro = IP_P_TCP;
		
	if (rt_output(pkb) < 0)
		return -1;

	return 0;
}

void dump_packet(struct pkbuf *pkb)
{
	printf("%s: pkb->pk_len = %d\n", __func__, pkb->pk_len);

	struct ip *iphdr = pkb2ip(pkb);

	printf("%s: ip_src = %#x, ip_dst = %#x\n", __func__, iphdr->ip_src, iphdr->ip_dst);
	printf("%s: ETH_HRD_SZ = %d\n", __func__, (int) ETH_HRD_SZ);
	printf("%s: IP_HRD_SZ = %d\n", __func__, (int) IP_HRD_SZ);
	printf("%s: TCP_HRD_SZ = %d\n", __func__, (int) TCP_HRD_SZ);
	printf("%s: ip_pro = %d, ip checksum = %d\n", __func__, iphdr->ip_pro, iphdr->ip_cksum);
	printf("%s: ip_len = %d\n", __func__, iphdr->ip_len);

	struct tcp *tcphdr = (struct tcp *) iphdr->ip_data;

	printf("%s: tcphdr->src = %d, tcphdr->dst = %d\n", __func__, tcphdr->src, tcphdr->dst);
	printf("%s: tcphdr->seq = %d, tcphdr->ackn = %d\n", __func__, tcphdr->seq, tcphdr->ackn);
	printf("%s: tcphdr->reserved = %d, tcphdr->doff = %d\n", __func__, tcphdr->reserved, tcphdr->doff);
	printf("%s: tcphdr->fin = %d, tcphdr->syn = %d\n", __func__, tcphdr->fin, tcphdr->syn);
	printf("%s: tcphdr->rst = %d, tcphdr->psh = %d\n", __func__, tcphdr->rst, tcphdr->psh);
	printf("%s: tcphdr->ack = %d, tcphdr->urg = %d\n", __func__, tcphdr->ack, tcphdr->urg);
	printf("%s: tcphdr->ece = %d, tcphdr->cwr = %d\n", __func__, tcphdr->ece, tcphdr->cwr);
	printf("%s: tcphdr->window = %d, tcphdr->checksum = %d\n", __func__, tcphdr->window, tcphdr->checksum);
	printf("%s: tcphdr->urgptr = %d, tcphdr->data[0] = %d\n", __func__, tcphdr->urgptr, tcphdr->data[0]);

	/* print data */
	int dsize = (pkb->pk_len - 54) - ((tcphdr->doff - 5) * 4);
	int dindex = (tcphdr->doff - 5) * 4;
	printf("%s: dsize = %d, dindex = %d\n", __func__, dsize, dindex);
	if (dsize) printf("%s: data = %s\n", __func__, &tcphdr->data[dindex]);
}


unsigned int saddr = 0, daddr = 0;
unsigned short sport = 0, dport = 0;
int filter_set = 0;
#undef PACKET_IP_FILTER
static void send_packet(uint8_t *buf)
{
#ifdef PACKET_IP_FILTER	
	if (!filter_set) {
		printf("%s: Error: queue filter not set.\n", __func__);
		return;
	}
#else	
	if (!bound) {
		printf("%s: Error: sport did not bound yet.\n", __func__);
		return;
	}
#endif
	NETWORK_GET_ZERO_ARGS_DATA
	struct pkbuf *pkb = (struct pkbuf *) data;
	// pkb->pk_refcnt = 2; /* prevents the network code from freeing the pkb */
	pkb->pk_refcnt = 1;
	list_init(&pkb->pk_list);
	/* FIXME: add */
	//pkb_safe();
	if (data_size != (pkb->pk_len + sizeof(*pkb))) {
		printf("%s: Error: packet size is not correct.\n", __func__);
		// return;
		exit(-1);
	}

#ifdef PACKET_IP_FILTER
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
#else
	/* check the port numbers */
	struct ip *iphdr = pkb2ip(pkb);
	struct tcp *tcphdr = (struct tcp *) iphdr->ip_data;
	if ((bound_sport != tcphdr->src)) {
		printf("%s: Error: invalid src  port number bound_sport  = %d , tcphdr->src= %d.\n", __func__, bound_sport, tcphdr->src);
		return;
	}

#endif
	tcp_init_pkb(pkb);

	ip_send_out(pkb);
}


void network_arbiter_change(unsigned int trusted){
	return;
}

/*
 * Bound or not?
 * Used or not?
 * If bound, resouce name.
 * If global flag "used" not set, set it.
 * This is irreversible until reset.
 */
static void network_query_state(uint8_t *buf)
{
	uint8_t state[3];
	uint32_t state_size = 3;

	state[0] = bound;
	state[1] = used;
	used = 1;
	state[2] = bound_sport;

	NETWORK_SET_ONE_RET_DATA(0, state, state_size)
}

/*
 * Return error if bound, or used is set.
 * Return error if invalid resource name
 * Bind the resource to the data queues.
 * Set the global var "bound"
 * This is irreversible until reset.
 */
static void network_bind_resource(uint8_t *buf, uint8_t owner_id)
{
	uint32_t sport;

	if (bound || used) {
		printf("Error: %s: the bind op is invalid if bound (%d), "
		      " or used (%d) is set.\n", __func__,
		       bound, used);
		NETWORK_SET_ONE_RET(ERR_INVALID)
		return;
	}

	NETWORK_GET_ONE_ARG
	sport = arg0;

	printf("%s:  bound_sport  = %d .\n", __func__, sport);
#ifdef ARCH_SEC_HW
	if (sport >= TRUSTED_PORT_BOUNDARY) {
		network_arbiter_change(ARBITER_TRUSTED);
	} else {
		if ( owner_id != UNTRUSTED_DOMAIN_OWNER_ID) {
			print("trusted domains cannot bound port less than 50000\r\n");
			NETWORK_SET_ONE_RET(ERR_INVALID)
			return;
		}
		network_arbiter_change(ARBITER_UNTRUSTED);
	}
#endif	

	bound_sport = sport;
	bound = 1;

	NETWORK_SET_ONE_RET(0)
}
void process_cmd(uint8_t *buf, uint8_t owner_id)
{
	switch (buf[0]) {
	case IO_OP_BIND_RESOURCE:
		network_bind_resource(buf, owner_id);
		break;

	case IO_OP_QUERY_STATE:
		network_query_state(buf);
		break;

	default:
		/*
		 * If global flag "used" not set, set it.
		 * This is irreversible until reset.
		 */
		printf("Error: %s: unsupported op (%d)\n", __func__, buf[0]);
		used = 1;
		NETWORK_SET_ONE_RET(ERR_INVALID)
		break;
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
	// printf("send_response write: [%u, %u]\n", opcode[0], opcode[1]);
	// printf("send_response write buf: [%u, %u, ...]\n", buf[0], buf[1]);
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
	// printf("send_received_packet write: [%u, %u]\n", opcode[0], opcode[1]);
	// printf("send_received_packet write buf: [%u, %u, ...]\n", buf[0], buf[1]);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

void tcp_in(struct pkbuf *pkb)
{
	printf("tcp_in\n");
	/* check the IP addresses */
	struct ip *iphdr = pkb2ip(pkb);
#ifdef PACKET_IP_FILTER
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
#endif
	struct tcp *tcphdr = (struct tcp *) iphdr->ip_data;
	if (bound_sport != tcphdr->dst) {
		printf("%s: Error: invalid src port number. Dropping the packet\n", __func__);
		return;
	}
	
	int size = pkb->pk_len + sizeof(*pkb);
	NETWORK_SET_ZERO_ARGS_DATA(pkb, size);
	// printf("received packet size: %d\n", size);
	send_received_packet(buf, Q_NETWORK_DATA_OUT);
	free_pkb(pkb);
}

pthread_t mailbox_thread;

int init_network(void)
{
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
	return 0;
}

void close_network(void)
{
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

void network_event_loop(void)
{
	uint8_t opcode[2];
	int is_data_queue = 0;
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	while(1) {
		sem_wait(&interrupts[Q_NETWORK_CMD_IN]);
		sem_getvalue(&interrupts[Q_NETWORK_DATA_IN], &is_data_queue);
		if (!is_data_queue) {
			memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
			opcode[1] = Q_NETWORK_CMD_IN;
			write(fd_out, opcode, 2);
			// printf("Loop B1 write: [%u, %u]\n", opcode[0], opcode[1]);
			read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
			process_cmd(buf, 1);
			send_response(buf, Q_NETWORK_CMD_OUT);
		} else {
			memset(dbuf, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE);
			sem_wait(&interrupts[Q_NETWORK_DATA_IN]);
			opcode[1] = Q_NETWORK_DATA_IN;
			write(fd_out, opcode, 2);
			// printf("Loop B2 write: [%u, %u]\n", opcode[0], opcode[1]);
			read(fd_in, dbuf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
			send_packet(dbuf);
		}
	}

}

int main(int argc, char **argv)
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: network init\n", __func__);
	init_network();
	network_event_loop();
	close_network();
}
#endif /*ARCH_SEC_HW*/
