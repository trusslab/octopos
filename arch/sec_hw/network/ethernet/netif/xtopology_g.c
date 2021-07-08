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
