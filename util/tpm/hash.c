#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/sha.h>

/*
 * @hash_buf: an array of uint8_t with a minimum size of SHA256_DIGEST_LENGTH.
 */
int hash_file(char *path, uint8_t *hash_buf)
{
	FILE *bin = fopen(path, "rb");
	if (!bin) {
		fprintf(stderr, "File %s cannot be opened.", path);
		return -1;
	}

	const int per_buf_size = 32768;
	unsigned char *buffer = (unsigned char *)
		malloc(per_buf_size * sizeof(unsigned char));
	if(!buffer)
		return EOF;

	SHA256_CTX hash_ctx;
	SHA256_Init(&hash_ctx);

	int bytes_read = 0;
	while ((bytes_read = fread(buffer, 1, per_buf_size, bin))) {
		SHA256_Update(&hash_ctx, buffer, bytes_read);
	}

	SHA256_Final((unsigned char *) hash_buf, &hash_ctx);

	fclose(bin);
	free(buffer);
	return 0;
}

void convert_hash_to_str(uint8_t *hash_buf, char *hash_str)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(hash_str + (i * 2), "%02x", hash_buf[i]);
	}
}

/*
 * @hash_buf: an array of uint8_t with a minimum size of SHA256_DIGEST_LENGTH.
 */
int hash_buffer(uint8_t *buffer, uint32_t buffer_size, uint8_t *hash_buf)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX hash_ctx;

	SHA256_Init(&hash_ctx);
	SHA256_Update(&hash_ctx, buffer, buffer_size);
	SHA256_Final(hash, &hash_ctx);

	return 0;
}
