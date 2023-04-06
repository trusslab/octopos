/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef ARCH_SEC_HW_NETWORK
#include "netif.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
//#include "raw.h"
#include "icmp.h"
#include "route.h"
#include "lib.h"
#else /*ARCH_SEC_HW_NETWORK*/
#include <network/netif.h>
#include <network/ether.h>
#include <network/arp.h>
#include <network/ip.h>
#include <network/icmp.h>
#include <network/route.h>
#include <network/lib.h>
#endif /*ARCH_SEC_HW_NETWORK*/

/* Assert pkb is net-order */
void ip_forward(struct pkbuf *pkb)
{
	struct ip *iphdr = pkb2ip(pkb);
	struct rtentry *rt = pkb->pk_rtdst;
	struct netdev *indev = pkb->pk_indev;
	unsigned int dst;

#ifdef ARCH_SEC_HW_NETWORK
//	printf("%s:host doesnt support forward,droping message!\r\n",__func__);
//	free(pkb->pk_data);
	free_pkb(pkb);
	return;
#endif
#ifdef CONFIG_TOP1
	ipdbg("host doesnt support forward!");
	goto drop_pkb;
#endif
	ipdbg(IPFMT " -> " IPFMT "(%d/%d bytes) forwarding",
				ipfmt(iphdr->ip_src), ipfmt(iphdr->ip_dst),
				iphlen(iphdr), _ntohs(iphdr->ip_len));

	if (iphdr->ip_ttl <= 1) {
		icmp_send(ICMP_T_TIMEEXCEED, ICMP_EXC_TTL, 0, pkb);
		goto drop_pkb;
	}

	/* FIXME: ajacent checksum for decreased ttl */
	iphdr->ip_ttl--;
	ip_set_checksum(iphdr);

	/* default route or remote dst */
	if ((rt->rt_flags & RT_DEFAULT) || rt->rt_metric > 0)
		dst = rt->rt_gw;
	else
		dst = iphdr->ip_dst;
	ipdbg("forward to next-hop "IPFMT, ipfmt(dst));
	if (indev == rt->rt_dev) {
		/*
		 * ICMP REDIRECT conditions(RFC 1812):
		 * 1. The packet is being forwarded out the same physical
		 *    interface that it was received from.
		 * 2. The IP source address in the packet is on the same Logical IP
		 *    (sub)network as the next-hop IP address.
		 * 3. The packet does not contain an IP source route option.
		 *    (Not implemented)
		 */
		struct rtentry *srt = rt_lookup(iphdr->ip_src);
		if (srt && srt->rt_metric == 0 &&
			equsubnet(srt->rt_netmask, iphdr->ip_src, dst)) {
			if (srt->rt_dev != indev) {
				ipdbg("Two NIC are connected to the same LAN");
			}
			icmp_send(ICMP_T_REDIRECT, ICMP_REDIRECT_HOST, dst, pkb);
		}
	}
	/* ip fragment */
	if (_ntohs(iphdr->ip_len) > rt->rt_dev->net_mtu) {
		if (iphdr->ip_fragoff & _htons(IP_FRAG_DF)) {
			icmp_send(ICMP_T_DESTUNREACH, ICMP_FRAG_NEEDED, 0, pkb);
			goto drop_pkb;
		}
		ip_send_frag(rt->rt_dev, pkb);
	} else {
		ip_send_dev(rt->rt_dev, pkb);
	}
	return;
drop_pkb:
	free_pkb(pkb);
}
