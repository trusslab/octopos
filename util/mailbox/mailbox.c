#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <octopos/mailbox.h>

uint8_t RUNTIME_PROC_IDS[NUM_RUNTIME_PROCS] = {P_RUNTIME1, P_RUNTIME2, P_UNTRUSTED};
uint8_t RUNTIME_QUEUE_IDS[NUM_RUNTIME_PROCS] = {Q_RUNTIME1, Q_RUNTIME2, Q_UNTRUSTED};

uint8_t get_runtime_queue_id(uint8_t runtime_proc_id)
{
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		if (RUNTIME_PROC_IDS[i] == runtime_proc_id)
			return RUNTIME_QUEUE_IDS[i];
	}

	return 0;
}

int is_valid_runtime_queue_id(int queue_id)
{
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		if (RUNTIME_QUEUE_IDS[i] == queue_id)
			return 1;
	}

	return 0;
}

uint8_t get_runtime_proc_id(uint8_t runtime_queue_id)
{
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		if (RUNTIME_QUEUE_IDS[i] == runtime_queue_id)
			return RUNTIME_PROC_IDS[i];
	}

	return 0;
}
