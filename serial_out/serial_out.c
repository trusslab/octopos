/* octopos serial output code */
#include <stdint.h>
#include <octopos/mailbox.h>
#include <arch/mailbox_serial_out.h>
#include <arch/defines.h>
#ifdef ARCH_SEC_HW
#include <sleep.h>
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
	int ret = init_serial_out();
	if (ret)
		return ret;

	serial_out_core();

	close_serial_out();
}
