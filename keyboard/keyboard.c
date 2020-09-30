/* OctopOS keyboard code */
#include <stdio.h>
#include <stdint.h>
#include <arch/mailbox_keyboard.h>

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
