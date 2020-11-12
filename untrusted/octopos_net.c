// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Octopos network driver.
 *
 *  Based on:
 *  TUN - Universal TUN/TAP device driver.
 *  Copyright (C) 1999-2002 Maxim Krasnyansky <maxk@qualcomm.com>
 *
 *  $Id: tun.c,v 1.15 2002/03/01 02:44:24 maxk Exp $
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define DRV_NAME	"octopos_net"
#define DRV_VERSION	"1.0"
#define DRV_DESCRIPTION	"OctopOS network driver"
#define DRV_COPYRIGHT	"(C) 2020 Ardalan Amiri Sani, University of California, Irvine <arrdalan@gmail.com>"

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_tun.h>
#include <net/rtnetlink.h>
#include <net/sock.h>

#define UNTRUSTED_DOMAIN
#include <octopos/mailbox.h>
#include "network_client.h"

/* octopos */
#include <net/ip.h>
#include <linux/ip.h>
#include <net/tcp.h>

/* FIXME: modified from octopos/util/network/pkb.c */
static struct pkbuf *alloc_pkb(int size)
{
        struct pkbuf *pkb;
        pkb = kzalloc(sizeof(*pkb) + size, GFP_KERNEL);
        pkb->pk_len = size;
        pkb->pk_pro = 0xffff;
        pkb->pk_type = 0;
        pkb->pk_refcnt = 1;
        pkb->pk_indev = NULL;
        pkb->pk_rtdst = NULL;
        return pkb;
}

/* FIXME: modified from octopos/util/network/pkb.c */
static void free_pkb(struct pkbuf *pkb)
{
        if (--pkb->pk_refcnt <= 0) {
                kfree(pkb);
        }
}

static void ip_send_out_skb(struct sk_buff *skb)
{
	int i, len, seg_len;

	struct pkbuf *pkb = alloc_pkb(skb->len);
	/* copy the header */
	/* FIXME: use macros, ETH_HRD_SZ is 14 */
	void *wptr = &pkb->pk_data[0] + 14;
	skb_copy_from_linear_data(skb, wptr, skb->len - skb->data_len);
	wptr += skb->len - skb->data_len;

	/* copy the data, code based on skb_dump() */
	len = skb->data_len;
	for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		u32 p_off, p_len, copied;
		struct page *p;
		u8 *vaddr;

		skb_frag_foreach_page(frag, skb_frag_off(frag),
				      skb_frag_size(frag), p, p_off, p_len,
				      copied) {
			seg_len = min_t(int, p_len, len);
			vaddr = kmap_atomic(p);
			memcpy(wptr, vaddr + p_off, seg_len);
			kunmap_atomic(vaddr);
			len -= seg_len;
			if (!len)
				break;
			wptr += seg_len;
		}
	}

	pkb->pk_len = skb->len + 14;
	ip_send_out(pkb);
	free_pkb(pkb);
}

struct dst_entry *ond_dst_check(struct dst_entry *dst, __u32 cookie)
{
	return dst;
}

struct dst_ops ond_dst_ops = {
	.check = ond_dst_check,
};

/* FIXME: get rid of globals */
uint8_t *net_buf = NULL;
struct net_device *g_dev;
struct dst_entry g_dst_entry;

/* default: host order is little-endian */
struct my_ip {
	unsigned char	ip_hlen:4,	/* header length(in 4-octet's) */
			ip_ver:4;	/* version */
	unsigned char ip_tos;		/* type of service */
	unsigned short ip_len;		/* total ip packet data length */
	unsigned short ip_id;		/* datagram id */
	unsigned short ip_fragoff;	/* fragment offset(in 8-octet's) */
	unsigned char ip_ttl;		/* time to live, in gateway hops */
	unsigned char ip_pro;		/* L4 protocol */
	unsigned short ip_cksum;	/* header checksum */
	unsigned int ip_src;		/* source address */
	unsigned int ip_dst;		/* dest address */
	unsigned char ip_data[0];	/* data field */
} __attribute__((packed));

#define pkb2ip(pkb) ((struct my_ip *)((pkb)->pk_data + 14))
#define pkb2tcp(pkb) ((struct my_ip *)((pkb)->pk_data + 34))

#define TCP_LITTLE_ENDIAN
struct my_tcp {
	unsigned short src;	/* source port */
	unsigned short dst;	/* dest port */
	unsigned int seq;	/* sequence number */
	unsigned int ackn;	/* acknowledgment number */
#ifdef TCP_LITTLE_ENDIAN
	unsigned short	reserved:4,
			doff:4,	/* data offset(head length)in 32 bits long */
				/* control bits */
			fin:1,
			syn:1,
			rst:1,
			psh:1,	/* push */
			ack:1,	/* acknowlegment */
			urg:1,	/* urgent */
			ece:1,	/* See RFC 3168 */
			cwr:1;	/* See RFC 3168 */

#else
	unsigned short	doff:4,	/* data offset(head length)in 32 bits long */
			reserved:4,
				/* control bits */
			cwr:1,	/* See RFC 3168 */
			ece:1,	/* See RFC 3168 */
			urg:1,	/* urgent */
			ack:1,	/* acknowlegment */
			psh:1,	/* push */
			rst:1,
			syn:1,
			fin:1;
#endif
	unsigned short window;
	unsigned short checksum;
	unsigned short urgptr;		/* urgent pointer */
	unsigned char data[0];
} __attribute__((packed));

void *ond_tcp_receive(void)
{
	uint8_t *data;
	uint16_t data_size;

	data = ip_receive(net_buf, &data_size);
	if (!data_size) {
		printk("%s: Error: bad network data message\n", __func__);
		BUG();
	}

	struct pkbuf *pkb = (struct pkbuf *) data;
	int len = pkb->pk_len - 14;
	struct sk_buff *skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		BUG();
	skb->len = len - 20; /* 20 being the IP header size */
	skb->data_len = 0; /* 0 for linear data */
	/* FIXME: need to check TCP checksum.
	 * Debug notes: runs into problems at tcp_checksum_complete() in tcp_v4_do_rcv() and
	 * in tcp_checksum_init() in tcp_v4_rcv().
	 */
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb_copy_to_linear_data(skb, pkb2ip(pkb), len);

	skb_reset_mac_header(skb);
	skb->protocol = htons(ETH_P_IP);
	skb->dev = g_dev;

	skb_reset_network_header(skb);
	skb_probe_transport_header(skb);

#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->tail = skb->len;
#else
	BUG();
#endif
	skb->data += 20;
	/* FIXME: this is a hack. Needed in __inet_lookup_skb() */
	dst_hold(&g_dst_entry);
	skb_dst_set(skb, &g_dst_entry);
	
	int ret = tcp_v4_rcv(skb);
}

bool octopos_net_access = false;

int octopos_open_socket(__be32 daddr, __be32 saddr, __be16 dport, __be16 sport)
{
	unsigned int _saddr = 0;
	unsigned short _sport = sport;
	int ret;

	ret = syscall_allocate_tcp_socket(&_saddr, &_sport, (unsigned int) daddr, (unsigned short) dport);
	if (ret) {
		printk("Error: %s: couldn't register a TCP socket with octopos.\n", __func__);
		return ret;
	}

	if (_saddr != (unsigned int) saddr || _sport != (unsigned short) sport) {
		printk("Error: %s: unexpected saddr or sport.\n", __func__);
		syscall_close_socket();
		return -EEXIST;
	}
	
	if (!octopos_net_access) {
		request_network_access(200, 100, NULL, NULL, NULL);
		octopos_net_access = true;
	}

	return 0;
}

static void octopos_close_socket(struct work_struct *work)
{
	if (octopos_net_access) {
		yield_network_access();
		octopos_net_access = false;
	}

	syscall_close_socket();
}

static struct work_struct close_socket_wq;

void octopos_close_socket_atomic(struct sock *sk)
{
	schedule_work(&close_socket_wq);
}

/* Network device part of the driver */

/* Net device open. */
static int ond_net_open(struct net_device *dev)
{
	return 0;
}

/* Net device close. */
static int ond_net_close(struct net_device *dev)
{
	return 0;
}

/* Net device start xmit */
static netdev_tx_t ond_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	ip_send_out_skb(skb);

	return NETDEV_TX_OK;
}

static netdev_features_t ond_net_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	return 0;
}

static const struct net_device_ops ond_netdev_ops = {
	.ndo_open		= ond_net_open,
	.ndo_stop		= ond_net_close,
	.ndo_start_xmit		= ond_net_xmit,
	.ndo_fix_features	= ond_net_fix_features,
};

#define MIN_MTU 68
#define MAX_MTU 65535

/* Initialize net device. */
static void ond_net_init(struct net_device *dev)
{
	dev->netdev_ops = &ond_netdev_ops;

	/* Point-to-Point TUN Device */
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->mtu = 1500;

	/* Zero header length */
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;

	dev->min_mtu = MIN_MTU;
	dev->max_mtu = MAX_MTU - dev->hard_header_len;
}

static void ond_setup(struct net_device *dev)
{
}

static int ond_set_iff(void)
{
	struct net_device *dev;
	int err;

	char *name = "octopos_net";
	unsigned long flags = 0;
	int queues = 1;

	/* TUN device */
	//flags |= IFF_TUN;

	dev = alloc_netdev_mqs(0, name,
			       NET_NAME_UNKNOWN, ond_setup, queues,
			       queues);

	if (!dev)
		return -ENOMEM;

	ond_net_init(dev);

	dev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST;
	dev->features = dev->hw_features;

	err = register_netdevice(dev);
	if (err < 0)
		goto err_free_dev;

	netif_carrier_on(dev);

	/* Make sure persistent devices do not get stuck in
	 * xoff state.
	 */
	if (netif_running(dev))
		netif_tx_wake_all_queues(dev);

	/* FIXME: use priv data */
	g_dev = dev;
	dst_init(&g_dst_entry, &ond_dst_ops, dev, 1, 0, DST_NOCOUNT);

	return 0;

err_free_dev:
	free_netdev(dev);
	return err;
}

int net_start_receive(void)
{
	return 0;
}

void net_stop_receive(void)
{
}

static int __init ond_init(void)
{
	int ret = 0;

	pr_info("%s, %s\n", DRV_DESCRIPTION, DRV_VERSION);

	rtnl_lock();
	
	ret = ond_set_iff();
	if (ret) {
		pr_err("Can't set iff\n");
		goto err_setiff;
	}

	rtnl_unlock();

	INIT_WORK(&close_socket_wq, octopos_close_socket);

	net_buf = (uint8_t *) kmalloc(MAILBOX_QUEUE_MSG_SIZE_LARGE, GFP_KERNEL);
	if (!net_buf) {
		printk("%s: Error: could not allocate memory for net_buf\n", __func__);
		return -ENOMEM;
	}

	return  0;

err_setiff:
	return ret;
}

static void ond_cleanup(void)
{
	kfree(net_buf);
}

module_init(ond_init);
module_exit(ond_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_ALIAS("devname:net/octopos_net");
