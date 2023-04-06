/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef ARCH_SEC_HW
#include "netif.h"
#include "socket.h"
#include "list.h"
#include "raw.h"
#include "ip.h"
#else /*ARCH_SEC_HW*/
#include <network/netif.h>
#include <network/socket.h>
#include <network/list.h>
#include <network/raw.h>
#include <network/ip.h>
#endif /*ARCH_SEC_HW*/

static void raw_recv(struct pkbuf *pkb, struct sock *sk)
{
	/* FIFO queue */
	list_add_tail(&pkb->pk_list, &sk->recv_queue);
	/* Should we get sk? */
	pkb->pk_sk = sk;
	sk->ops->recv_notify(sk);
}

void raw_in(struct pkbuf *pkb)
{
	struct ip *iphdr = pkb2ip(pkb);
	struct pkbuf *rawpkb;
	struct sock *sk;
	/* FIXME: lock for raw lookup */
	sk = raw_lookup_sock(iphdr->ip_src, iphdr->ip_dst, iphdr->ip_pro);
	while (sk) {
		rawpkb = copy_pkb(pkb);
		raw_recv(rawpkb, sk);
		/* for all matched raw sock */
		sk = raw_lookup_sock_next(sk, iphdr->ip_src, iphdr->ip_dst,
							iphdr->ip_pro);
	}
}
