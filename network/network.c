/* octopos network code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#ifndef ARCH_SEC_HW_NETWORK
#include <semaphore.h>
#else /*ARCH_SEC_HW_STORAGE*/
#include "arch/semaphore.h"
#endif /*ARCH_SEC_HW_STORAGE*/

#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/error.h>
#include <network/netif.h>
#include <network/route.h>
#include <network/arp.h>
#include <network/lib.h>
#include <network/ip.h>
#include <network/tcp.h>
#ifndef ARCH_SEC_HW_NETWORK
#include <arch/mailbox.h>
#endif /*ARCH_SEC_HW_STORAGE*/

#include "arch/mailbox_network.h"

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



unsigned int net_debug = 0;




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
	if (!filter_set) {
		printf("%s: Error: queue filter not set.\n", __func__);
		return;
	}

	NETWORK_GET_ZERO_ARGS_DATA
	struct pkbuf *pkb = (struct pkbuf *) data;
        dump_packet(pkb);
//	pkb->pk_refcnt = 2; /* prevents the network code from freeing the pkb */
//	list_init(&pkb->pk_list);
//	/* FIXME: add */
//	//pkb_safe();
//	if (data_size != (pkb->pk_len + sizeof(*pkb))) {
//		printf("%s: Error: packet size is not correct.\n", __func__);
//		return;
//	}
//
//	/* check the IP addresses */
//	struct ip *iphdr = pkb2ip(pkb);
//	if ((saddr != iphdr->ip_src) || (daddr != iphdr->ip_dst)) {
//		printf("%s: Error: invalid src or dst IP addresses.\n", __func__);
//		return;
//	}
//
//	/* check the port numbers */
//	struct tcp *tcphdr = (struct tcp *) iphdr->ip_data;
//	if ((sport != tcphdr->src) || (dport != tcphdr->dst)) {
//		printf("%s: Error: invalid src or dst port numbers.\n", __func__);
//		return;
//	}
//
//	tcp_init_pkb(pkb);
//
//	ip_send_out(pkb);
}

void process_cmd(uint8_t *buf)
{
	NETWORK_GET_FOUR_ARGS
	saddr = (unsigned int) arg0;
	sport = (unsigned short) arg1;
	daddr = (unsigned int) arg2;
	dport = (unsigned short) arg3;

	filter_set = 1;
	NETWORK_SET_ONE_RET((unsigned int) 0)
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

	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: network init\n", __func__);

	init_network();
	network_event_loop();
	close_network();
	
	
}
