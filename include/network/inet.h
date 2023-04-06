/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __INET_H
#define __INET_H

#include "socket.h"

struct inet_type {
	struct sock *(*alloc_sock)(int);
	int type;
	int protocol;
};

extern struct socket_ops inet_ops;
extern void inet_init(void);

#endif	/* inet.h */
