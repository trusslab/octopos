/* OctopOS keyboard code */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arch/mailbox_keyboard.h>
#include <octopos/mailbox.h>
#include <tpm/tpm.h>

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

	/* Need to make sure msgs are big enough so that we don't overflow
	 * when processing incoming msgs and preparing outgoing ones.
	 */
	/* FIXME: find the smallest bound. 64 is conservative. */
	if (MAILBOX_QUEUE_MSG_SIZE < 64) {
		printf("Error: %s: MAILBOX_QUEUE_MSG_SIZE is too small (%d).\n",
		       __func__, MAILBOX_QUEUE_MSG_SIZE);
		return -1;
	}

	int ret = init_keyboard();
	if (ret)
		return ret;

	keyboard_core();

	close_keyboard();
}	
