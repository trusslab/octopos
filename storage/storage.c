/* octopos storage code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#ifndef ARCH_SEC_HW_STORAGE
#include <semaphore.h>
#else
#include "arch/semaphore.h"
#endif
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/error.h>

#include "arch/mailbox_storage.h"


/* FIXME: determine partitions and their sizes dynamically. */
struct partition partitions[NUM_PARTITIONS];
uint32_t partition_sizes[NUM_PARTITIONS] = {1000, 2048, 100, 100, 100};

int main(int argc, char **argv)
{

	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error: storage data queue msg size must be equal to storage block size\n");
		return -1;
	}

	init_storage();
	storage_event_loop();
	close_storage();
}
