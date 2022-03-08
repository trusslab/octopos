#ifdef ARCH_SEC_HW_NETWORK
/*
 * Copyright (C) 2010 - 2019 Xilinx, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 */

#ifndef __NETIF_XAXIEMACIF_H__
#define __NETIF_XAXIEMACIF_H__



#include "arch/network/ethernet_hw_params.h"
#include "xadapter.h"
//#include "xstatus.h"

#include "xaxiethernet.h"
#include "xllfifo.h"


#include "xpqueue.h"
#include "xlwipconfig.h"



typedef unsigned   char    u8_t;
typedef signed     char    s8_t;
typedef unsigned   short   u16_t;
typedef signed     short   s16_t;
typedef unsigned   int    u32_t;
typedef signed     int    s32_t;
typedef unsigned   long long    u64_t;
typedef signed     long long    s64_t;
typedef s8_t err_t;

void 	xaxiemacif_setmac(u32_t index, u8_t *addr);
u8_t*	xaxiemacif_getmac(u32_t index);


unsigned get_IEEE_phy_speed(XAxiEthernet *xaxiemacp);
unsigned configure_IEEE_phy_speed(XAxiEthernet *xaxiemacp, unsigned speed);
unsigned phy_setup_axiemac (XAxiEthernet *xaxiemacp);

/* xaxiemacif_hw.c */
void 	xaxiemac_error_handler(XAxiEthernet * Temac);

/* structure within each netif, encapsulating all information required for
 * using a particular temac instance
 */
typedef struct {
	XLlFifo      axififo;
	XAxiEthernet axi_ethernet;

	/* queue to store overflow packets */
	pq_queue_t *recv_q;
	pq_queue_t *send_q;

	/* pointers to memory holding buffer descriptors (used only with SDMA) */
	void *rx_bdspace;
	void *tx_bdspace;
} xaxiemacif_s;

extern xaxiemacif_s xaxiemacif;

#endif /* __NETIF_XAXIEMACIF_H__ */
#endif /* ARCH_SEC_HW_NETWORK */
