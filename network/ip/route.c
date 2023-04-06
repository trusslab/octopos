/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef ARCH_SEC_HW_NETWORK
#include "netif.h"
#include "ip.h"
#include "icmp.h"
#include "lib.h"
#include "route.h"
#include "list.h"
#include "netcfg.h"
#else /*ARCH_SEC_HW_NETWORK*/
#include <network/netif.h>
#include <network/ether.h>
#include <network/list.h>
#include <network/ip.h>
#include <network/icmp.h>
#include <network/route.h>
#include <network/lib.h>
#include <network/netcfg.h>
#endif /*ARCH_SEC_HW_NETWORK*/

static LIST_HEAD(rt_head);

struct rtentry *rt_lookup(unsigned int ipaddr)
{
	struct rtentry *rt;
	/* FIXME: lock found route entry, which may be deleted */
	list_for_each_entry(rt, &rt_head, rt_list) {
		if ((rt->rt_netmask & ipaddr) ==
			(rt->rt_netmask & rt->rt_net))
			return rt;
	}
	return NULL;
}

struct rtentry *rt_alloc(unsigned int net, unsigned int netmask,
	unsigned int gw, int metric, unsigned int flags, struct netdev *dev)
{
	struct rtentry *rt;
	rt = malloc(sizeof(*rt));
	rt->rt_net = net;
	rt->rt_netmask = netmask;
	rt->rt_gw = gw;
	rt->rt_metric = metric;
	rt->rt_flags = flags;
	rt->rt_dev = dev;
	list_init(&rt->rt_list);
	return rt;
}

void rt_add(unsigned int net, unsigned int netmask, unsigned int gw,
			int metric, unsigned int flags, struct netdev *dev)
{
	struct rtentry *rt, *rte;
	struct list_head *l;

	rt = rt_alloc(net, netmask, gw, metric, flags, dev);
	/* insert according to netmask descend-order */
	l = &rt_head;
	list_for_each_entry(rte, &rt_head, rt_list) {
		if (rt->rt_netmask >= rte->rt_netmask) {
			l = &rte->rt_list;
			break;
		}
	}
	/* if not found or the list is empty, insert to prev of head*/
	list_add_tail(&rt->rt_list, l);
}

void rt_init(void)
{
	/* loopback */
	rt_add(LOCALNET(loop), loop->net_mask, 0, 0, RT_LOCALHOST, loop);
	/* local host */
#ifndef ARCH_SEC_HW_NETWORK	
	rt_add(veth->net_ipaddr, 0xffffffff, 0, 0, RT_LOCALHOST, loop);
	/* local net */
	rt_add(LOCALNET(veth), veth->net_mask, 0, 0, RT_NONE, veth);
#ifndef CONFIG_TOP1
	/* default route: next-hop is tap ipaddr */
	rt_add(0, 0, tap->dev.net_ipaddr, 0, RT_DEFAULT, veth);
#else
	rt_add(0, 0, DEFAULT_GW, 0, RT_DEFAULT, veth);
#endif /*CONFIG_TOP1*/

#else
	rt_add(xileth->net_ipaddr, 0xffffffff, 0, 0, RT_LOCALHOST, loop);
	/* local net */
	rt_add(LOCALNET(xileth), xileth->net_mask, 0, 0, RT_NONE, xileth);
	rt_add(0, 0, 0x100a8c0, 0, RT_DEFAULT, xileth);
#endif /*ARCH_SEC_HW_NETWORK*/

	dbg("route table init");
}

/* Assert pkb is host-order */
int rt_input(struct pkbuf *pkb)
{
	struct ip *iphdr = pkb2ip(pkb);
	struct rtentry *rt = rt_lookup(iphdr->ip_dst);
	if (!rt) {
#ifndef CONFIG_TOP1
		/*
		 * RFC 1812 #4.3.3.1
		 * If a router cannot forward a packet because it has no routes
		 * at all (including no default route) to the destination
		 * specified in the packet, then the router MUST generate a
		 * Destination Unreachable, Code 0 (Network Unreachable) ICMP
		 * message.
		 */
		ip_hton(iphdr);
		icmp_send(ICMP_T_DESTUNREACH, ICMP_NET_UNREACH, 0, pkb);
#endif
		free_pkb(pkb);
		return -1;
	}
	pkb->pk_rtdst = rt;
	return 0;
}

/* Assert pkb is net-order */
int rt_output(struct pkbuf *pkb)
{
	struct ip *iphdr = pkb2ip(pkb);
	struct rtentry *rt = rt_lookup(iphdr->ip_dst);
	if (!rt) {
		/* FIXME: icmp dest unreachable to localhost */
		ipdbg("No route entry to "IPFMT, ipfmt(iphdr->ip_dst));
		return -1;
	}
	pkb->pk_rtdst = rt;
	iphdr->ip_src = rt->rt_dev->net_ipaddr;
	ipdbg("Find route entry from "IPFMT" to "IPFMT,
			ipfmt(iphdr->ip_src), ipfmt(iphdr->ip_dst));
	return 0;
}

void rt_traverse(void)
{
	struct rtentry *rt;

	if (list_empty(&rt_head))
		return;
	printf("Destination     Gateway         Genmask         Metric Iface\n");
	list_for_each_entry(rt, &rt_head, rt_list) {
		if (rt->rt_flags & RT_LOCALHOST)
			continue;
		if (rt->rt_flags & RT_DEFAULT)
			printf("default         ");
		else
			printfs(16, IPFMT, ipfmt(rt->rt_net));
		if (rt->rt_gw == 0)
			printf("*               ");
		else
			printfs(16, IPFMT, ipfmt(rt->rt_gw));
		printfs(16, IPFMT, ipfmt(rt->rt_netmask));
		printf("%-7d", rt->rt_metric);
		printf("%s\n", rt->rt_dev->net_name);
	}
}

