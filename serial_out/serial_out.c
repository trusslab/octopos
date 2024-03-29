/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* octopos serial output code */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <octopos/mailbox.h>
#include <arch/mailbox_serial_out.h>
#include <arch/defines.h>
#ifdef ARCH_SEC_HW
#include <sleep.h>
#endif

/* Need to make sure msgs are big enough so that we don't overflow
 * when processing incoming msgs and preparing outgoing ones.
 */
#if MAILBOX_QUEUE_MSG_SIZE < 64
#error MAILBOX_QUEUE_MSG_SIZE is too small.
#endif

static int serial_out_core(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	
	while(1) {
		get_chars_from_serial_out_queue(buf);
		write_chars_to_serial_out(buf);
	}

	return 0;
}

int main(int argc, char **argv)
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: serial_out init\n", __func__);

	int ret = init_serial_out();
	if (ret)
		return ret;

	serial_out_core();

	close_serial_out();
}
