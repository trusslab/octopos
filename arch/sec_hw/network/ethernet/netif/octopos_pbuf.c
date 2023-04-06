/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef ARCH_SEC_HW_NETWORK
#include "arch/network/netif/octopos_pbuf.h"
#include <stdlib.h>

struct octopos_pbuf *octopos_pbuf_alloc(unsigned short length)
{
	struct octopos_pbuf *p;
	p = (struct octopos_pbuf *) malloc(sizeof(struct octopos_pbuf));
	p->payload = malloc(length);
	p->len = length;
//	p->next = (void *)0;
	return p;
}

void octopos_pbuf_free(struct octopos_pbuf *p)
{
	if (p->payload)
		free(p->payload);
	if (p)
		free(p);
}
#endif /* ARCH_SEC_HW_NETWORK */
