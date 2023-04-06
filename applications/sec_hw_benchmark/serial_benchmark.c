/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef ARCH_SEC_HW

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>

#ifdef ARCH_SEC_HW_RUNTIME
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
					 api->write_to_secure_serial_out(output_buf);}

#define insecure_printf(fmt, args...) {memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args);\
					 api->write_to_shell(output_buf, num_chars);}

#endif

extern long long global_counter;

#ifndef ARCH_SEC_HW
#define LINE_MAX_LENGTH 1024
extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
#else
#define LINE_MAX_LENGTH 64
void serial_benchmark(struct runtime_api *api)
#endif
{
	char line[LINE_MAX_LENGTH];
	int i, size;
	int ret;

	_SEC_HW_ERROR("load take %lld", global_counter);

	ret = api->request_secure_keyboard(100, 100, NULL, NULL);
	if (ret) {
		printf("Error: could not get secure access to keyboard\n");
		insecure_printf("Failed to switch.\n");
		return;
	}

	_SEC_HW_ERROR("keyboard %lld", global_counter);

	ret = api->request_secure_serial_out(200, 100, NULL, NULL);
	if (ret) {
		api->yield_secure_keyboard();
		printf("Error: could not get secure access to serial_out\n");
		insecure_printf("Failed to switch.\n");
		return;
	}
	_SEC_HW_ERROR("serialout %lld", global_counter);
	
	secure_printf("Please enter your secure phrase: \r\n");

	memset(line, 0x0, LINE_MAX_LENGTH);
	for (i = 0; i < LINE_MAX_LENGTH; i++) {
		api->read_char_from_secure_keyboard(&line[i]);
#ifdef ARCH_SEC_HW
		if (line[i] == '\r') {
#else
		if (line[i] == '\n') {
#endif
			break;
		}
	}

	secure_printf("\nYour secure phrase is: %s\n", line);

	api->yield_secure_keyboard();
	api->yield_secure_serial_out();
}

#endif /* ARCH_SEC_HW */