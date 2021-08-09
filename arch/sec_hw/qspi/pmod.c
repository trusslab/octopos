#ifdef ARCH_SEC_HW_STORAGE

#include "PmodSD.h"
#include <stdio.h>
#include <stdlib.h>
#include <octopos/error.h>

DXSPISDVOL *disk;

void initialize_pmodsd()
{
	static const char szDriveNbr[] = "0:";
	
	disk = new DXSPISDVOL(XPAR_STORAGE_SUBSYSTEM_PMODSD_0_AXI_LITE_SPI_BASEADDR,
		XPAR_STORAGE_SUBSYSTEM_PMODSD_0_AXI_LITE_SDCS_BASEADDR);
	DFATFS::fsmount(*disk, szDriveNbr, 1);
}

DFILE* fop_open(const char *filename, const char *mode)
{
	DFILE * filep = new DFILE;
	BYTE _mode;
	FRESULT result;

	if (strcmp(mode, "r") == 0) {
		_mode = FA_READ;
	} else if (strcmp(mode, "r+") == 0) {
		_mode = FA_READ | FA_WRITE;
	} else if (strcmp(mode, "w") == 0) {
		_mode = FA_CREATE_ALWAYS | FA_WRITE;
	} else if (strcmp(mode, "w+") == 0) {
		_mode = FA_CREATE_ALWAYS | FA_WRITE | FA_READ;
	} else if (strcmp(mode, "wx") == 0) {
		_mode = FA_CREATE_NEW | FA_WRITE;
	} else if (strcmp(mode, "w+x") == 0) {
		_mode = FA_CREATE_NEW | FA_WRITE | FA_READ;
	} else {
		return NULL;
	}

	result = filep->fsopen(filename, _mode);
	if (result == FR_OK) {
		return filep;
	} else {
		return NULL;
	}
}

int fop_close(DFILE *filep)
{
	FRESULT result;

	if (!filep) {
		return ERR_INVALID;
	}

	result = filep->fsclose();

	if (result == FR_OK) {
		free(filep);
		return 0;
	} else {
		return ERR_FAULT;
	}
}

int fop_seek(DFILE *filep, long int offset, int origin)
{
	FRESULT result;

	if (origin != SEEK_SET) {
		return ERR_INVALID;
	}

	result = filep->fslseek(offset);
	if (result == FR_OK) {
		return 0;
	} else {
		return ERR_FAULT;
	}
}

size_t fop_read(void *ptr, size_t size, size_t count, DFILE *filep)
{
	FRESULT result;
	UINT NumBytesRead = 0;
	UINT _size = size * count;

	result = filep->fsread(ptr, _size, &NumBytesRead);
	if (result == FR_OK) {
		return (size_t) NumBytesRead;
	} else {
		return 0;
	}
}

size_t fop_write(void *ptr, size_t size, size_t count, DFILE *filep)
{
	FRESULT result;
	UINT NumBytesWrite = 0;
	UINT _size = size * count;

	result = filep->fswrite(ptr, _size, &NumBytesWrite);
	if (result == FR_OK) {
		return (size_t) NumBytesWrite;
	} else {
		return 0;
	}
}
#endif /* ARCH_SEC_HW_STORAGE */
