/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* OctopOS keyboard code */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arch/mailbox_keyboard.h>
#include <octopos/mailbox.h>

/* Need to make sure msgs are big enough so that we don't overflow
 * when processing incoming msgs and preparing outgoing ones.
 */
#if MAILBOX_QUEUE_MSG_SIZE < 64
#error MAILBOX_QUEUE_MSG_SIZE is too small.
#endif

static int keyboard_core(void)
{
	while (1) {
		uint8_t kchar = read_char_from_keyboard();
		put_char_on_keyboard_queue(kchar);

		if (kchar == 3) { /* ETX */
			printf("^C");
			return 0;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: keyboard init\n", __func__);

	int ret = init_keyboard();
	if (ret)
		return ret;

	keyboard_core();

	close_keyboard();
}	
