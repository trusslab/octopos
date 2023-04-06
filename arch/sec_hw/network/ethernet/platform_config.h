/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef ARCH_SEC_HW_NETWORK
#ifndef __PLATFORM_CONFIG_H_
#define __PLATFORM_CONFIG_H_


#define PLATFORM_EMAC_BASEADDR XPAR_ETHERNET_SUBSYSTEM_AXI_ETHERNET_0_BASEADDR

#define PLATFORM_TIMER_BASEADDR XPAR_ETHERNET_SUBSYSTEM_AXI_TIMER_MB5_BASEADDR
#define PLATFORM_TIMER_INTERRUPT_INTR XPAR_ETHERNET_SUBSYSTEM_MICROBLAZE_AXI_INTC_ETHERNET_SUBSYSTEM_AXI_TIMER_MB5_INTERRUPT_INTR
#define PLATFORM_TIMER_INTERRUPT_MASK (1 << XPAR_ETHERNET_SUBSYSTEM_MICROBLAZE_AXI_INTC_ETHERNET_SUBSYSTEM_AXI_TIMER_MB5_INTERRUPT_INTR)


#endif

#endif /* ARCH_SEC_HW_NETWORK */
