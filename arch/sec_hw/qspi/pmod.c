#ifdef ARCH_SEC_HW_STORAGE

#include "PmodSD.h"

DXSPISDVOL disk(XPAR_PMODSD_0_AXI_LITE_SPI_BASEADDR,
    XPAR_PMODSD_0_AXI_LITE_SDCS_BASEADDR);

void initialize_pmodsd()
{
	static const char szDriveNbr[] = "0:";
	DFATFS::fsmount(disk, szDriveNbr, 1);
}

#endif /* ARCH_SEC_HW_STORAGE */
