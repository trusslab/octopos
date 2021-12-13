#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "hash.h"

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

/*
 * @hash_buf: an array of uint8_t with a minimum size of SHA256_DIGEST_LENGTH.
 * @hash_str: an array of char with a minimum size of
 *	      (2 * SHA256_DIGEST_LENGTH + 1).
 */
void convert_hash_to_str(uint8_t *hash_buf, char *hash_str)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(hash_str + (i * 2), "%02x", hash_buf[i]);
	}

	hash_str[2 * SHA256_DIGEST_LENGTH] = '\0';
}

/*
 * @hash_buf: an array of uint8_t with a minimum size of SHA256_DIGEST_LENGTH.
 */
int hash_buffer(uint8_t *buffer, uint32_t buffer_size, uint8_t *hash_buf)
{
	SHA256_CTX hash_ctx;

	SHA256_Init(&hash_ctx);
	SHA256_Update(&hash_ctx, buffer, buffer_size);
	SHA256_Final((unsigned char *) hash_buf, &hash_ctx);

	return 0;
}

int hash_multiple_buffers(uint8_t **buffers, uint32_t *buffer_sizes,
			  uint32_t num_buffers, uint8_t *hash_buf)
{
	SHA256_CTX hash_ctx;
	uint32_t i;

	SHA256_Init(&hash_ctx);

	for (i = 0; i < num_buffers; i++)
		SHA256_Update(&hash_ctx, buffers[i], buffer_sizes[i]);

	SHA256_Final((unsigned char *) hash_buf, &hash_ctx);

	return 0;
}

/*
 * @hash_buf: an array of uint8_t with a minimum size of SHA256_DIGEST_LENGTH.
 */
void print_hash_buf(uint8_t *hash_buf)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02x", hash_buf[i]);
	}
	printf("\n");
}
