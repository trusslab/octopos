/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __UDP_H
#define __UDP_H

#include "sock.h"

struct udp {
	unsigned short src;	/* source port */
	unsigned short dst;	/* destination port */
	unsigned short length;	/* udp head and data */
	unsigned short checksum;
	unsigned char data[0];
} __attribute__((packed));

struct udp_sock {
	struct sock sk;
};

#define UDP_HRD_SZ sizeof(struct udp)
#define ip2udp(ip) ((struct udp *)ipdata(ip))
#define UDP_MAX_BUFSZ (0xffff - UDP_HRD_SZ)
#define UDP_DEFAULT_TTL 64

extern struct sock *udp_lookup_sock(unsigned short port);
extern void udp_in(struct pkbuf *pkb);
extern void udp_init(void);
extern struct sock *udp_alloc_sock(int protocol);

#endif	/* udp.h */
