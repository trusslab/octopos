/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef ARCH_SEC_HW

/* fs_test app */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>

#ifdef ARCH_SEC_HW_RUNTIME
#include "xil_io.h"
#include "arch/sec_hw.h"
#include "arch/app_utilities.h"
#endif

#include <octopos/runtime.h>
#include <octopos/storage.h>

/* FIXME: how does the app know the size of the buf? */
#ifndef ARCH_SEC_HW

char output_buf[64];
int num_chars = 0;
#define secure_printf(fmt, args...) {memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args);	\
				     api->write_to_secure_serial_out(output_buf);}			\

#define insecure_printf(fmt, args...) {memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args);\
				     api->write_to_shell(output_buf, num_chars);}				 \

#endif

#if RUNTIME_ID == 1
extern long long global_counter;
#else
long long global_counter;
#endif

uint8_t block[STORAGE_BLOCK_SIZE * 31];

void mailbox_yield_to_previous_owner(uint8_t queue_id);

#ifndef ARCH_SEC_HW
extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
#else
void storage_benchmark(struct runtime_api *api)
#endif
{
	int ret;
	memset(block, 0xf0, STORAGE_BLOCK_SIZE * 31);

	_SEC_HW_ERROR("Start");

	int total_read = 0;
	int total_write = 0;
	int total_req = 0;

	global_counter = 0;
	ret = api->request_secure_storage_access(100, MAILBOX_MAX_LIMIT_VAL,
						MAILBOX_MAX_LIMIT_VAL,
						 NULL, NULL, NULL);
	total_req = global_counter;
	if (ret) {
		printf("Error: no access to storage.\n %d", ret);
		return;
	}
	printf("Write");

	/* BENCHMARK: write to flash */
	global_counter = 0;
	for (int jj = 0; jj < 65; jj++)
		ret = api->write_secure_storage_blocks(block, 0, 31);
	total_write = global_counter;

	/* BENCHMARK: read from flash */
	memset(block, 0x0, STORAGE_BLOCK_SIZE * 31);

	printf("Read");
	global_counter = 0;
	for (int jj = 0; jj < 65; jj++)
		ret = api->read_secure_storage_blocks(block, 0, 31);
	total_read = global_counter;

	printf("Yield");
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);

	printf("(verify %02x) Write %d, Read %d, Req %d\r\n", 
		block[0],
		total_write,
		total_read,
		total_req);

	sleep(1);
}

#endif /* ARCH_SEC_HW */