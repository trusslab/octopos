#include <octopos/runtime.h>

#ifdef ARCH_SEC_HW
#define bool _Bool
#endif

/* The number of limits on the storage cmd
 * queues needed to lock the partition.
 * FIXME: Secure HW limit is 16 per r/w. This can be fixed in hardware.
 */
#ifdef ARCH_SEC_HW
#define STORAGE_CLIENT_MIN_CMD_LIMIT    16
#else
#define STORAGE_CLIENT_MIN_CMD_LIMIT    1
#endif

int set_up_secure_storage_key(uint8_t *key);
int yield_secure_storage_access(void);
int request_secure_storage_access(uint32_t partition_size,
				  limit_t limit, timeout_t timeout,
				  queue_update_callback_t callback,
				  uint8_t *expected_pcr, uint8_t *return_pcr);
int delete_and_yield_secure_storage(void);
int write_secure_storage_blocks(uint8_t *data, uint32_t start_block,
				uint32_t num_blocks);
int read_secure_storage_blocks(uint8_t *data, uint32_t start_block,
			       uint32_t num_blocks);
int read_from_secure_storage_block(uint8_t *data, uint32_t block_num,
				   uint32_t block_offset, uint32_t read_size);
int write_to_secure_storage_block(uint8_t *data, uint32_t block_num,
				  uint32_t block_offset, uint32_t write_size);
int set_up_context(void *addr, uint32_t size, int do_yield, int *context_found,
		   uint32_t partition_size, limit_t limit, timeout_t timeout,
		   queue_update_callback_t callback, uint8_t *expected_pcr,
		   uint8_t *return_pcr);
int write_context_to_storage(int do_yield);
#ifndef UNTRUSTED_DOMAIN
void reset_storage_queues_trackers(void);
#endif
