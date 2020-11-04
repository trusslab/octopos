/* OctopOS mailbox interface for UML
 * Copyright (C) 2020 Ardalan Amiri Sani <arrdalan@gmail.com>
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#define UNTRUSTED_DOMAIN
#include <octopos/mailbox_umode.h>

/* FIXME: no op. Remove. */
int init_octopos_mailbox_interface(void)
{
	return 0;
}

void close_octopos_mailbox_interface(void)
{
	remove(FIFO_UNTRUSTED_OUT); 
	remove(FIFO_UNTRUSTED_IN);
	remove(FIFO_UNTRUSTED_INTR);
}
