/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef ARCH_SEC_HW_NETWORK
#include "arch/network/netif/xtopology.h"
#include "xparameters.h"

struct xtopology_t xtopology[] = {
	{
		0x12000000,
		xemac_type_axi_ethernet,
		0x41200000,
		-1,
		0x0,
		0x0,
	},
};

int xtopology_n_emacs = 1;
#endif /* ARCH_SEC_HW_NETWORK */
