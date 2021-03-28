#ifndef ARCH_SEC_HW_NETWORK
/*
 * special net device independent L2 code
 */
#include <net/if.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/if_tun.h>

#include "netif.h"
#include "ether.h"
#include "ip.h"
#include "arp.h"
#include "lib.h"
#include "netcfg.h"
#else /*ARCH_SEC_HW_NETWORK*/
#include <network/netif.h>
#include <network/ether.h>
#include <network/ip.h>
#include <network/arp.h>
#include <network/lib.h>
#include <network/netcfg.h>
#endif /*ARCH_SEC_HW_NETWORK*/

/* referred to eth_trans_type() in linux */
static struct ether *eth_init(struct netdev *dev, struct pkbuf *pkb)
{
	struct ether *ehdr = (struct ether *)pkb->pk_data;
	if (pkb->pk_len < ETH_HRD_SZ) {
		free_pkb(pkb);
		dbg("received packet is too small:%d bytes", pkb->pk_len);
		return NULL;
	}
	/* hardware address type */
	if (is_eth_multicast(ehdr->eth_dst)) {
		if (is_eth_broadcast(ehdr->eth_dst))
			pkb->pk_type = PKT_BROADCAST;
		else
			pkb->pk_type = PKT_MULTICAST;
	} else if (!hwacmp(ehdr->eth_dst, dev->net_hwaddr)) {
			pkb->pk_type = PKT_LOCALHOST;
	} else {
			pkb->pk_type = PKT_OTHERHOST;
	}
	/* packet protocol */
	pkb->pk_pro = _ntohs(ehdr->eth_pro);
	return ehdr;
}
#undef l2dbg
#define l2dbg(fmt, args...)\
do {\
          printf(fmt, ##args);\
} while (0)

/* L2 protocol parsing */
void net_in(struct netdev *dev, struct pkbuf *pkb)
{
	struct ether *ehdr = eth_init(dev, pkb);
	if (!ehdr)
		return;
	l2dbg(MACFMT " -> " MACFMT "(%s)",
				macfmt(ehdr->eth_src),
				macfmt(ehdr->eth_dst),
				ethpro(pkb->pk_pro));
	pkb->pk_indev = dev;
	switch (pkb->pk_pro) {
	case ETH_P_RARP:
//		rarp_in(dev, pkb);
		break;
	case ETH_P_ARP:
		//MJ temp
		printf("%s: arp message recved\n\r",__func__);
		arp_in(dev, pkb);
		break;
	case ETH_P_IP:
		printf("%s: IP  message recved\n\r",__func__);
		ip_in(dev, pkb);
		break;
	default:
		l2dbg("drop unkown-type packet");
		printf("%s:drop unkown-type packet  \n\r",__func__);
		free(pkb->pk_data);
		free_pkb(pkb);
		break;
	}
}

void net_timer(void)
{
	/* timer runs */
	while (1) {
		sleep(1);
		arp_timer(1);
		ip_timer(1);
	}
}
