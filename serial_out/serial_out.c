/* octopos serial output code */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <octopos/mailbox.h>
#include <octopos/io.h>
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

		/* The client is asking us to stop processing messages,
		 * which will force the OS to reset this domain after the
		 * client yields.
		 */
		if (buf[0] == IO_OP_TERMINATE_DOMAIN)
			break;

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

#ifdef ARCH_UMODE
	/* Wait to be terminated by the OS. */
	while(1) {
		sleep(10);
	}
#endif
}
