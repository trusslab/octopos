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
#include <linux/sched/signal.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/miscdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/if_vlan.h>
#include <linux/crc32.h>
#include <linux/nsproxy.h>
#include <linux/virtio_net.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/xdp.h>
#include <linux/seq_file.h>
#include <linux/uio.h>
#include <linux/skb_array.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/mutex.h>

#include <linux/uaccess.h>
#include <linux/proc_fs.h>

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
	printk("%s [1]: skb->len = %d\n", __func__, skb->len);
	printk("%s [2]: skb->data_len = %d\n", __func__, skb->data_len);
	printk("%s [3]: skb->hdr_len = %d\n", __func__, skb->hdr_len);
	if (skb->len == 62) skb_dump("3", skb, true);
	/* copy the header */
	/* ETH_HRD_SZ is 14 */ 
	/* FIXME: use macros */
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

/* FIXME: get rid of globals */
uint8_t *net_buf = NULL;
struct net_device *g_dev;

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
	printk("%s [1]\n", __func__);

	data = ip_receive(net_buf, &data_size);
	if (!data_size) {
		printk("%s: Error: bad network data message\n", __func__);
		BUG();
	}

	printk("%s [2]: data_size = %d\n", __func__, data_size);

	/* some sanity checks */
	struct pkbuf *pkb = (struct pkbuf *) data;
	printk("%s [3]: pkb->pk_len = %d\n", __func__, pkb->pk_len);
	struct my_ip *iphdr = pkb2ip(pkb);
	printk("%s [3.1]: ip_src = %#x, ip_dst = %#x\n", __func__, iphdr->ip_src, iphdr->ip_dst);
	printk("%s [3.2]: ip_pro = %d\n", __func__, iphdr->ip_pro);
	struct my_tcp *tcphdr = (struct my_tcp *) iphdr->ip_data;
	printk("%s [3.3]: tcphdr->src = %d, tcphdr->dst = %d\n", __func__, tcphdr->src, tcphdr->dst);
	printk("%s [2.1]: tcphdr->seq = %d, tcphdr->ackn = %d\n", __func__, tcphdr->seq, tcphdr->ackn);
	printk("%s [2.2]: tcphdr->reserved = %d, tcphdr->doff = %d\n", __func__, tcphdr->reserved, tcphdr->doff);
	printk("%s [2.3]: tcphdr->fin = %d, tcphdr->syn = %d\n", __func__, tcphdr->fin, tcphdr->syn);
	printk("%s [2.4]: tcphdr->rst = %d, tcphdr->psh = %d\n", __func__, tcphdr->rst, tcphdr->psh);
	printk("%s [2.5]: tcphdr->ack = %d, tcphdr->urg = %d\n", __func__, tcphdr->ack, tcphdr->urg);
	printk("%s [2.6]: tcphdr->ece = %d, tcphdr->cwr = %d\n", __func__, tcphdr->ece, tcphdr->cwr);
	printk("%s [2.7]: tcphdr->window = %d, tcphdr->checksum = %d\n", __func__, tcphdr->window, tcphdr->checksum);
	printk("%s [2.8]: tcphdr->urgptr = %d, tcphdr->data[0] = %d\n", __func__, tcphdr->urgptr, tcphdr->data[0]);

	int dsize = (pkb->pk_len - 54) - ((tcphdr->doff - 5) * 4);
	int dindex = (tcphdr->doff - 5) * 4;
	printk("%s [2.9]: dsize = %d, dindex = %d\n", __func__, dsize, dindex);
	if (dsize) printk("%s [3]: data = %s\n", __func__, &tcphdr->data[dindex]);

	int len = pkb->pk_len - 14;
	struct sk_buff *skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		BUG();
	skb->len = len - 20; /* 20 being the IP header size */
	skb->data_len = 0; /* 0 for linear data */
	/* FIXME: need to check TCP checksum */
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb_copy_to_linear_data(skb, pkb2ip(pkb), len);

	skb_reset_mac_header(skb);
	skb->protocol = htons(ETH_P_IP);
	/* FIXME */
	skb->dev = g_dev;
	printk("%s [2.9]\n", __func__);

	skb_reset_network_header(skb);
	printk("%s [2.91]\n", __func__);
	/* FIXME: needed? */
	skb_probe_transport_header(skb);
	printk("%s [2.92]\n", __func__);
	printk("%s [2.93]: skb->head = %#lx, skb->data = %#lx, skb->tail = %#lx, skb->end = %#lx\n",
	       __func__, skb->head, skb->data, skb->tail, skb->end);

#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->tail = skb->len;
#else
	BUG();
#endif
	skb->data += 20;
	printk("%s [2.94]: skb->head = %#lx, skb->data = %#lx, skb->tail = %#lx, skb->end = %#lx\n",
	       __func__, skb->head, skb->data, skb->tail, skb->end);
	printk("%s [3.1]: skb->sk = %#lx\n", __func__, skb->sk);
	
	int ret = tcp_v4_rcv(skb);
	printk("%s [4]: ret = %d\n", __func__, ret);
}

bool octopos_net_access = false;

static void __ond_detach(struct tun_file *tfile, bool clean)
{
	printk("%s [1]\n", __func__);
}

static void ond_detach(struct tun_file *tfile, bool clean)
{
	printk("%s [1]\n", __func__);
}

/* Network device part of the driver */

/* Net device detach from fd. */
static void ond_net_uninit(struct net_device *dev)
{
	printk("%s [1]\n", __func__);
}

/* Net device open. */
static int ond_net_open(struct net_device *dev)
{
	printk("%s [1]\n", __func__);
	return 0;
}

/* Net device close. */
static int ond_net_close(struct net_device *dev)
{
	printk("%s [1]\n", __func__);
	return 0;
}

/* Net device start xmit */
static netdev_tx_t ond_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct flow_dissector_key_ports ports;
	int noff = skb_network_offset(skb);	
	printk("%s [1]: noff = %d\n", __func__, noff);
	int proto = -1;
	struct iphdr *iph;
	if (skb->protocol == htons(ETH_P_IP)) {
		if (unlikely(!pskb_may_pull(skb, noff + sizeof(*iph))))
			BUG();
        iph = (const struct iphdr *)(skb->data + noff);
        noff += iph->ihl << 2;
	printk("%s [2]: noff = %d\n", __func__, noff);
	printk("%s [2.1]: skb->data = %#x, skb->head = %#x, skb->network_header = %d(%#x)\n",
		__func__, skb->data, skb->head, skb->network_header, skb->network_header);
	printk("%s [2.2]: iph->tot_len = %d\n", __func__, iph->tot_len);
        if (!ip_is_fragment(iph))
                proto = iph->protocol;
	} else 
		BUG();
	if (proto != IPPROTO_TCP)
		BUG();
	ports.ports = skb_flow_get_ports(skb, noff, proto);
	printk("%s [3]: src port = %d, dst port = %d\n", __func__, ports.src, ports.dst);
	if (!octopos_net_access) {
		request_network_access(200);
		octopos_net_access = true;
	}
	ip_send_out_skb(skb);
	/* FIXME: when to yield? */
	//yield_network_access();

	return NETDEV_TX_OK;

//drop:
//	return NET_XMIT_DROP;
}

static netdev_features_t ond_net_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	printk("%s [1]\n", __func__);
	return 0;
}

static void ond_set_headroom(struct net_device *dev, int new_hr)
{
	printk("%s [1]\n", __func__);
}

static void
ond_net_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	printk("%s [1]\n", __func__);
}

static int ond_net_change_carrier(struct net_device *dev, bool new_carrier)
{
	printk("%s [1]\n", __func__);
	return 0;
}

static const struct net_device_ops ond_netdev_ops = {
	.ndo_uninit		= ond_net_uninit,
	.ndo_open		= ond_net_open,
	.ndo_stop		= ond_net_close,
	.ndo_start_xmit		= ond_net_xmit,
	.ndo_fix_features	= ond_net_fix_features,
	.ndo_set_rx_headroom	= ond_set_headroom,
	.ndo_get_stats64	= ond_net_get_stats64,
	.ndo_change_carrier	= ond_net_change_carrier,
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
	/* FIXME: needed? */
	dev->needs_free_netdev = true;
}

/* Trivial set of netlink ops to allow deleting tun or tap
 * device with netlink.
 */
static int ond_validate(struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	NL_SET_ERR_MSG(extack,
		       "octopos_net creation via rtnetlink is not supported.");
	return -EOPNOTSUPP;
}

static size_t ond_get_size(const struct net_device *dev)
{
	printk("%s [1]\n", __func__);

	return 0;
}

static int ond_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	printk("%s [1]\n", __func__);

	return 0;
}

static struct rtnl_link_ops ond_link_ops __read_mostly = {
	.kind		= DRV_NAME,
	.priv_size	= 0,
	.setup		= ond_setup,
	.validate	= ond_validate,
	.get_size       = ond_get_size,
	.fill_info      = ond_fill_info,
};

/* FIXME: needed? */
#define TUN_USER_FEATURES (NETIF_F_HW_CSUM|NETIF_F_TSO_ECN|NETIF_F_TSO| \
			  NETIF_F_TSO6)

static int ond_set_iff(void)
{
	struct net_device *dev;
	int err;

	char *name = "octopos_net";
	unsigned long flags = 0;
	int queues = 1;

	/* TUN device */
	flags |= IFF_TUN;

	dev = alloc_netdev_mqs(0, name,
			       NET_NAME_UNKNOWN, ond_setup, queues,
			       queues);

	if (!dev)
		return -ENOMEM;

	dev->rtnl_link_ops = &ond_link_ops;

	ond_net_init(dev);

	dev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST |
			   TUN_USER_FEATURES | NETIF_F_HW_VLAN_CTAG_TX |
			   NETIF_F_HW_VLAN_STAG_TX;
	dev->features = dev->hw_features | NETIF_F_LLTX;
	dev->vlan_features = dev->features &
			     ~(NETIF_F_HW_VLAN_CTAG_TX |
			       NETIF_F_HW_VLAN_STAG_TX);

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

	return 0;

err_free_dev:
	free_netdev(dev);
	return err;
}

static int ond_device_event(struct notifier_block *unused,
			    unsigned long event, void *ptr)
{
	return NOTIFY_DONE;
}

static struct notifier_block ond_notifier_block __read_mostly = {
	.notifier_call	= ond_device_event,
};

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
	printk("%s [1]\n", __func__);

	pr_info("%s, %s\n", DRV_DESCRIPTION, DRV_VERSION);

	ret = rtnl_link_register(&ond_link_ops);
	if (ret) {
		pr_err("Can't register link_ops\n");
		goto err_linkops;
	}

	ret = register_netdevice_notifier(&ond_notifier_block);
	if (ret) {
		pr_err("Can't register netdevice notifier\n");
		goto err_notifier;
	}
	printk("%s [2]\n", __func__);

	ret = ond_set_iff();
	if (ret) {
		pr_err("Can't set iff\n");
		goto err_notifier;
	}

	/* FIXME */
	unsigned int saddr = 0, daddr = 0x0200000a;
	unsigned short sport = 0, dport = htons(12345);

	ret = syscall_allocate_tcp_socket(&saddr, &sport, daddr, dport);
	if (ret) {
		printk("Error: %s: couldn't register a TCP socket with octopos.\n", __func__);
		goto err_notifier;
	}

	net_buf = (uint8_t *) kmalloc(MAILBOX_QUEUE_MSG_SIZE_LARGE, GFP_KERNEL);
	if (!net_buf) {
		printk("%s: Error: could not allocate memory for net_buf\n", __func__);
		return -ENOMEM;
	}

	return  0;

err_notifier:
	rtnl_link_unregister(&ond_link_ops);
err_linkops:
	return ret;
}

static void ond_cleanup(void)
{
	kfree(net_buf);
	rtnl_link_unregister(&ond_link_ops);
	unregister_netdevice_notifier(&ond_notifier_block);
}

module_init(ond_init);
module_exit(ond_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(OCTOPOS_NET_MINOR);
MODULE_ALIAS("devname:net/octopos_net");
