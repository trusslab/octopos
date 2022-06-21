/* octopos network code */
#ifdef ARCH_SEC_HW_NETWORK /*ARCH_SEC_HW_NETWORK*/
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#ifndef ARCH_SEC_HW_NETWORK
#include <semaphore.h>
#else /*ARCH_SEC_HW_NETWORK*/
#include "arch/semaphore.h"
#endif /*ARCH_SEC_HW_NETWORK*/

#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/error.h>
#include <network/netif.h>
#include <network/route.h>
#include <network/arp.h>
#include <network/lib.h>
#include <network/ip.h>
#include <network/tcp.h>
#include <octopos/io.h>
#ifndef ARCH_SEC_HW_NETWORK
#include <arch/mailbox.h>
#endif /*ARCH_SEC_HW_NETWORK*/

#include "arch/mailbox_network.h"
#include "arch/syscall.h"

#define UNTRUSTED_DOMAIN_OWNER_ID 3

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
		printf("Error: size not supported data_size=%d\n",data_size);		\
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

unsigned int net_debug = 0;

#define ARBITER_UNTRUSTED 1
#define ARBITER_UNTRUSTED_FLAG 0xF0F0F0F0
#define ARBITER_TRUSTED 0
#define ARBITER_TRUSTED_FLAG 0
#define ARBITER_BASE_ADDRESS 0xF0880000
#define TRUSTED_PORT_BOUNDARY 5000

void network_arbiter_change(unsigned int trusted) {
	unsigned int * arbitter_base = (unsigned int *) ARBITER_BASE_ADDRESS;
	if (trusted == ARBITER_TRUSTED){
		printf("Arbiter changed to trusted\n\r");
		*arbitter_base = ARBITER_TRUSTED_FLAG;
	}else{
		printf("Arbiter changed to untrusted\n\r");
		*arbitter_base = ARBITER_UNTRUSTED_FLAG;
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

void send_packet(uint8_t *buf)
{
	if (!bound) {
		printf("%s: Error: sport did not bound yet.\n", __func__);
		return;
	}

	NETWORK_GET_ZERO_ARGS_DATA
	struct pkbuf *pkb = (struct pkbuf *) data;
	pkb->pk_refcnt = 2; /* prevents the network code from freeing the pkb */
	list_init(&pkb->pk_list);
	if (data_size != (pkb->pk_len + sizeof(*pkb))) {
		printf("%s: Error: packet size is not correct. data_size = %d, (pkb->pk_len + sizeof(*pkb)) = %d, pkb->pk_len=%d, sizeof(*pkb) =%d\n",
				__func__, data_size,(pkb->pk_len + sizeof(*pkb)), pkb->pk_len,sizeof(*pkb));
		return;
	}

struct ip *iphdr = pkb2ip(pkb);
#ifdef PACKET_IP_FILTER
	/* check the IP addresses */
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
	struct tcp *tcphdr = (struct tcp *) iphdr->ip_data;
	if ((bound_sport != tcphdr->src)) {
		printf("%s: Error: invalid src  port number bound_sport  = %d , tcphdr->src= %d.\n", __func__, bound_sport, tcphdr->src);
		return;
	}
#endif
	tcp_init_pkb(pkb);
	ip_send_out(pkb);

}



void network_stack_init(void)
{
        netdev_init();
        arp_cache_init();
        rt_init();
    	//MJ FIXME remove the static ARP
    	unsigned char host_mac_ethernet_address[] = {
    		0xd0, 0x50, 0x99, 0x5e, 0x71, 0x0b };
    	arp_insert(xileth, 0x0800, 0x100a8c0, host_mac_ethernet_address);
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
	uint8_t state[3], sport;
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
static void network_bind_resource(uint8_t *buf, u8 owner_id)
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

	bound_sport = sport;
	bound = 1;

	NETWORK_SET_ONE_RET(0)
}

void process_cmd(uint8_t *buf, u8 owner_id)
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


void tcp_in(struct pkbuf *pkb)
{
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
	send_received_packet(buf, Q_NETWORK_DATA_OUT);
	free_pkb(pkb);

}



int main(int argc, char **argv)
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: network init s\n", __func__);
	init_network();
	network_event_loop();
	close_network();
}
#endif /*ARCH_SEC_HW_NETWORK*/
