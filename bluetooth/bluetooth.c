/* OctopOS bluetooth code */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arch/mailbox_bluetooth.h>
#include <octopos/mailbox.h>
#include <tpm/tpm.h>

static int bluetooth_core(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

	while (1) {
		read_msg_from_bluetooth_queue(buf);
		printf("%s [1]: buf[0] = %d\n", __func__, buf[0]);
		put_msg_on_bluetooth_queue(buf);
	}

	return 0;
}

int main(int argc, char **argv)
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: bluetooth init\n", __func__);

	int ret = init_bluetooth();
	if (ret)
		return ret;

	bluetooth_core();

	close_bluetooth();
}	
