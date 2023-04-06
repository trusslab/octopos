/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef ARCH_SEC_HW_BOOT_STORAGE

/* Simple wrapper for OctopOS file system
 * To use the file system as a standalone component.
 * This wrapper is customized for sec_hw.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <octopos/storage.h>
#include <octopos/io.h>
#include <arch/syscall.h>
#include "arch/pmod_fop.h"

#define FILE DFILE

/* FIXME: copied from storage/storage.c */
#define STORAGE_SET_TWO_RETS(ret0, ret1)	\
	SERIALIZE_32(ret0, &buf[0])		\
	SERIALIZE_32(ret1, &buf[4])		\

/* FIXME: copied from storage/storage.c */
#define STORAGE_GET_TWO_ARGS		\
	uint32_t arg0, arg1;		\
	DESERIALIZE_32(&arg0, &buf[1])	\
	DESERIALIZE_32(&arg1, &buf[5])	\

uint32_t start_block;
uint32_t num_blocks;
uint32_t size;
FILE *filep;
uint32_t total_blocks = 0;

int wait_for_storage_for_os_use(void)
{
	/* No op */
	return 0;
}

int send_msg_to_storage_no_response(uint8_t *buf)
{
	/* write */
	if (buf[0] == IO_OP_SEND_DATA) {
		STORAGE_GET_TWO_ARGS
		start_block = arg0;
		num_blocks = arg1;
		if (start_block + num_blocks > total_blocks) {
			total_blocks = start_block + num_blocks;
		}
		size = 0;
	} else if (buf[0] == IO_OP_RECEIVE_DATA) { /* read */
		STORAGE_GET_TWO_ARGS
		start_block = arg0;
		num_blocks = arg1;
		if (start_block + num_blocks > total_blocks) {
			printf("%s: Error: invalid args (read)\n", __func__);
		}
		size = 0;
	} else {
		printf("Error: %s: invalid operation (%d)\n", __func__, buf[0]);
	}

	return 0;
}

int get_response_from_storage(uint8_t *buf)
{
	STORAGE_SET_TWO_RETS(0, size);
	return 0;
}

void read_from_storage_data_queue(uint8_t *buf)
{
	if (num_blocks == 0) {
		printf("Error: %s: too many block reads\n", __func__);
		return;
	}

	uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
	memcpy(buf, 
		(void *) (RAM_ROOT_PARTITION_BASE + seek_off),
		STORAGE_BLOCK_SIZE);
	size += STORAGE_BLOCK_SIZE;
	start_block++;
	num_blocks--;
}

void write_to_storage_data_queue(uint8_t *buf)
{
	uint32_t seek_off = start_block * STORAGE_BLOCK_SIZE;
	if (num_blocks == 0) {
		printf("Error: %s: too many block writes\n", __func__);
		return;
	}

	fop_seek(filep, seek_off, SEEK_SET);
	size += (uint32_t) fop_write(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE,
				  filep);
	start_block++;
	num_blocks--;
}

#endif
