#include <octopos/mailbox.h>
#include <openssl/sha.h>

#if (MAILBOX_QUEUE_MSG_SIZE >= (SHA256_DIGEST_LENGTH + 1))
/* In this case, one message will be needed, which is what is assumed in the
 * code that sends/receives the hash over the mailbox.
 */
#define TPM_EXTEND_HASH_SIZE			SHA256_DIGEST_LENGTH
#define TPM_EXTEND_HASH_NUM_MAILBOX_MSGS	1
#endif

int hash_file(char *path, uint8_t *hash_buf);
void convert_hash_to_str(uint8_t *hash_buf, char *hash_str);
int hash_buffer(uint8_t *buffer, uint32_t buffer_size, uint8_t *hash_buf);
int hash_multiple_buffers(uint8_t **buffers, uint32_t *buffer_sizes,
			  uint32_t num_buffers, uint8_t *hash_buf);
void print_hash_buf(uint8_t *hash_buf);
