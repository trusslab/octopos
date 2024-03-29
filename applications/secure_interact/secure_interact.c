/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* secure_interact app */
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

#ifndef ARCH_SEC_HW
extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
#else
void secure_interact(struct runtime_api *api)
#endif
{
	char line[1024];
	int i, size;
	int ret;

	insecure_printf("This is secure_interact speaking.\n");
	insecure_printf("Provide an insecure phrase: \n");

	api->read_from_shell(line, &size);
	insecure_printf("Your insecure phrase: %s\n", line);

	insecure_printf("Switching to secure interaction mode now.\n");

	ret = api->request_secure_keyboard(100, 100, NULL, NULL);
	if (ret) {
		printf("Error: could not get secure access to keyboard\n");
		insecure_printf("Failed to switch.\n");
		return;
	}

	insecure_printf("keyboard switched");

	ret = api->request_secure_serial_out(200, 100, NULL, NULL);
	if (ret) {
		api->yield_secure_keyboard();
		printf("Error: could not get secure access to serial_out\n");
		insecure_printf("Failed to switch.\n");
		return;
	}
	
	secure_printf("Please enter your secure phrase: \r\n");

	memset(line, 0x0, 1024);
	for (i = 0; i < 1024; i++) {
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
