#include <openssl/sha.h>

#define TPM_AT_ID_LENGTH			16
#define TPM_AT_NONCE_LENGTH			16
#define TPM_EXTEND_HASH_SIZE			SHA256_DIGEST_LENGTH

int hash_file(char *path, uint8_t *hash_buf);
void convert_hash_to_str(uint8_t *hash_buf, char *hash_str);
int hash_buffer(uint8_t *buffer, uint32_t buffer_size, uint8_t *hash_buf);
int hash_multiple_buffers(uint8_t **buffers, uint32_t *buffer_sizes,
			  uint32_t num_buffers, uint8_t *hash_buf);
void print_hash_buf(uint8_t *hash_buf);
