/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef ARCH_SEC_HW_NETWORK
#ifndef OCTOPOS_HDR_PBUF_H
#define OCTOPOS_HDR_PBUF_H

/* Main packet buffer struct */
struct octopos_pbuf {
	/* pointer to the actual data in the buffer */
//	struct octopos_pbuf *next;
	void *payload;
	unsigned short len;
};

struct octopos_pbuf *octopos_pbuf_alloc(unsigned short length);
void octopos_pbuf_free(struct octopos_pbuf *p);

#endif
#endif /* ARCH_SEC_HW_NETWORK */
