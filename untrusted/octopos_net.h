/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef _OCTOPOS_NET_H_
#define _OCTOPOS_NET_H_
/* FIXME */
#define CONFIG_OCTOPOS
int octopos_open_socket(__be32 daddr, __be32 saddr, __be16 dport, __be16 sport);
void octopos_close_socket_atomic(struct sock *sk);
#endif
