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

#include <stdio.h>
#include <string.h>

#include <xparameters.h>


#include "arch/network/netif/xaxiemacif.h"
#include "arch/network/netif/xadapter.h"
#include "arch/network/netif/xpqueue.h"

#include "xaxiemacif_fifo.h"
#include "xaxiemacif_hw.h"

#include "xparameters.h"
#include "xintc.h"

#define LWIP_DEBUGF(debug, message)

/* Define those to better describe your network interface. */
#define IFNAME0 't'
#define IFNAME1 'e'
#define NETIF_DEBUG 0
#define ERR_MEM -1
#define ERR_OK 0



err_t octopos_xemac_init(struct xemac_s *xemac, unsigned char * mac_addr,  unsigned  mac_baseaddr)
{

	xaxiemacif_s *xaxiemacif;
	XAxiEthernet_Config *mac_config;
//	xaxiemacif = mem_malloc(sizeof *xaxiemacif);
	xaxiemacif = malloc(sizeof *xaxiemacif);
	if (xaxiemacif == NULL) {
		LWIP_DEBUGF(NETIF_DEBUG, ("xaxiemacif_init: out of memory\r\n"));
		return ERR_MEM;
	}


	xemac->state = (void *)xaxiemacif;
	xemac->topology_index = xtopology_find_index(mac_baseaddr);
	xemac->type = xemac_type_axi_ethernet;

	xaxiemacif->send_q = NULL;
	xaxiemacif->recv_q = pq_create_queue();
	if (!xaxiemacif->recv_q)
		return ERR_MEM;


	/* obtain config of this emac */
	mac_config = xaxiemac_lookup_config(mac_baseaddr);
	XAxiEthernet_Initialize(&xaxiemacif->axi_ethernet, mac_config,
				mac_config->BaseAddress);

	/* initialize the locallink FIFOs */
	init_axi_fifo(xemac);
	/* initialize the mac */
	octopos_init_axiemac(xaxiemacif, mac_addr);


	return ERR_OK;
}



