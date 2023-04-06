/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef ARCH_SEC_HW_NETWORK
#include "netif.h"
#include "ip.h"
#include "lib.h"
#else  /*ARCH_SEC_HW_NETWORK*/
#include <network/netif.h>
#include <network/ip.h>
#include <network/lib.h>
#endif /*ARCH_SEC_HW_NETWORK*/

#define LOOPBACK_MTU		1500
#define LOOPBACK_IPADDR		0x0100007F	/* 127.0.0.1 */
#define LOOPBACK_NETMASK	0x000000FF	/* 255.0.0.0 */

struct netdev *loop;

static int loop_dev_init(struct netdev *dev)
{
	/* init veth: information for our netstack */
	dev->net_mtu = LOOPBACK_MTU;
	dev->net_ipaddr = LOOPBACK_IPADDR;
	dev->net_mask = LOOPBACK_NETMASK;
	dbg("%s ip address: " IPFMT, dev->net_name, ipfmt(dev->net_ipaddr));
	dbg("%s netmask:    " IPFMT, dev->net_name, ipfmt(dev->net_mask));
	/* net stats have been zero */
	return 0;
}

static void loop_recv(struct netdev *dev, struct pkbuf *pkb)
{
	dev->net_stats.rx_packets++;
	dev->net_stats.rx_bytes += pkb->pk_len;
	net_in(dev, pkb);
}

static int loop_xmit(struct netdev *dev, struct pkbuf *pkb)
{
	get_pkb(pkb);
	/* loop back to itself */
	loop_recv(dev, pkb);
	dev->net_stats.tx_packets++;
	dev->net_stats.tx_bytes += pkb->pk_len;
	return pkb->pk_len;
}

static struct netdev_ops loop_ops = {
	.init = loop_dev_init,
	.xmit = loop_xmit,
	.exit = NULL,
};

void loop_init(void)
{
	loop = netdev_alloc("lo", &loop_ops);
}

void loop_exit(void)
{
	netdev_free(loop);
}

