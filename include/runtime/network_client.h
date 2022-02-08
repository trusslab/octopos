#include <octopos/runtime.h>

#ifdef CONFIG_UML
/* FIXME: copied from include/network/list.h */
/* list head */
struct list_head_new {
	struct list_head_new *prev, *next;
};

/* FIXME: copied from include/network/netif.h */
/* packet buf */
struct pkbuf {
	struct list_head_new pk_list;	/* for ip fragment or arp waiting list */
	unsigned short pk_pro;		/* ethernet packet type ID */
	unsigned short pk_type;		/* packet hardware address type */
	int pk_len;
	int pk_refcnt;
	struct netdev *pk_indev;
	struct rtentry *pk_rtdst;
	struct sock *pk_sk;
	unsigned char pk_data[0];
} __attribute__((packed));
#endif

void ip_send_out(struct pkbuf *pkb);
uint8_t *ip_receive(uint8_t *buf, uint16_t *size);
int syscall_allocate_tcp_socket(unsigned int *saddr, unsigned short *sport,
		unsigned int daddr, unsigned short dport);
int yield_network_access(void);
int request_network_access(limit_t limit, timeout_t timeout,
			   queue_update_callback_t callback,
			   uint8_t *expected_pcr, uint8_t *return_pcr);
void syscall_close_socket(void);
#ifndef UNTRUSTED_DOMAIN
void reset_network_queues_tracker(void);
#endif

int net_start_receive(void);
void net_stop_receive(void);
