#ifdef ARCH_SEC_HW_NETWORK
/*
 * Copyright (C) 2007 - 2019 Xilinx, Inc.
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

#include "arch/network/netif/lwipopts.h"
#include "arch/network/netif/xlwipconfig.h"
#include "xemac_ieee_reg.h"



#include "arch/network/netif/xadapter.h"



#include "arch/network/netif/xaxiemacif.h"




/* global lwip debug variable used for debugging */
int lwip_runtime_debug = 0;

enum ethernet_link_status eth_link_status = ETH_LINK_UNDEFINED;
u32_t phyaddrforemac;




int
xtopology_find_index(unsigned base)
{
	int i;

	for (i = 0; i < xtopology_n_emacs; i++) {
		if (xtopology[i].emac_baseaddr == base)
			return i;
	}

	return -1;
}


#ifdef OCT_NOT_DEFINE
static u32_t phy_link_detect(XAxiEthernet *xemacp, u32_t phy_addr)
{
	u16_t status;

	/* Read Phy Status register twice to get the confirmation of the current
	 * link status.
	 */
	XAxiEthernet_PhyRead(xemacp, phy_addr, IEEE_STATUS_REG_OFFSET, &status);
	XAxiEthernet_PhyRead(xemacp, phy_addr, IEEE_STATUS_REG_OFFSET, &status);

	if (status & IEEE_STAT_LINK_STATUS)
		return 1;
	return 0;
}



static u32_t phy_autoneg_status(XAxiEthernet *xemacp, u32_t phy_addr)
{
	u16_t status;

	/* Read Phy Status register twice to get the confirmation of the current
	 * link status.
	 */
	XAxiEthernet_PhyRead(xemacp, phy_addr, IEEE_STATUS_REG_OFFSET, &status);
	XAxiEthernet_PhyRead(xemacp, phy_addr, IEEE_STATUS_REG_OFFSET, &status);

	if (status & IEEE_STAT_AUTONEGOTIATE_COMPLETE)
		return 1;
	return 0;
}


void eth_link_detect(struct netif *netif)
{
	u32_t link_speed, phy_link_status;
	struct xemac_s *xemac = (struct xemac_s *)(netif->state);


	xaxiemacif_s *xemacs = (xaxiemacif_s *)(xemac->state);
	XAxiEthernet *xemacp = &xemacs->axi_ethernet;

	if ((xemacp->IsReady != (u32)XIL_COMPONENT_IS_READY) ||
			(eth_link_status == ETH_LINK_UNDEFINED))
		return;

	phy_link_status = phy_link_detect(xemacp, phyaddrforemac);

	if ((eth_link_status == ETH_LINK_UP) && (!phy_link_status))
		eth_link_status = ETH_LINK_DOWN;

	switch (eth_link_status) {
		case ETH_LINK_UNDEFINED:
		case ETH_LINK_UP:
			return;
		case ETH_LINK_DOWN:
			netif_set_link_down(netif);
			eth_link_status = ETH_LINK_NEGOTIATING;
			xil_printf("Ethernet Link down\r\n");
			break;
		case ETH_LINK_NEGOTIATING:
			if (phy_link_status &&
				phy_autoneg_status(xemacp, phyaddrforemac)) {

				/* Initiate Phy setup to get link speed */

				link_speed = phy_setup_axiemac(xemacp);
				XAxiEthernet_SetOperatingSpeed(xemacp,
							       link_speed);
				netif_set_link_up(netif);
				eth_link_status = ETH_LINK_UP;
				xil_printf("Ethernet Link up\r\n");
			}
			break;
	}
}
#endif
#endif /* ARCH_SEC_HW_NETWORK */

