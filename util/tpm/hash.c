/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <tpm/hash.h>

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

	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_sha256();
	EVP_DigestInit_ex(mdctx, md, NULL);

	int bytes_read = 0;
	unsigned int hashLen = 0;

	while ((bytes_read = fread(buffer, 1, per_buf_size, bin))) {
		EVP_DigestUpdate(mdctx, buffer, bytes_read);
	}

	EVP_DigestFinal_ex(mdctx, hash_buf, &hashLen);
	EVP_MD_CTX_free(mdctx);

	fclose(bin);
	free(buffer);
	return 0;
}

/*
 * @hash_buf: an array of uint8_t with a minimum size of SHA256_DIGEST_LENGTH.
 * @hash_str: an array of char with a minimum size of
 *	      (2 * SHA256_DIGEST_LENGTH + 1).
 */
void convert_hash_to_str(uint8_t *hash_buf, uint8_t *hash_str)
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf((char *)hash_str + (i * 2), "%02x", hash_buf[i]);
	}

	hash_str[2 * SHA256_DIGEST_LENGTH] = '\0';
}

/*
 * @hash_buf: an array of uint8_t with a minimum size of SHA256_DIGEST_LENGTH.
 */
int hash_buffer(uint8_t *buffer, uint32_t buffer_size, uint8_t *hash_buf)
{
	unsigned int hashLen = 0;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_sha256();
	
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, buffer, buffer_size);
	EVP_DigestFinal_ex(mdctx, hash_buf, &hashLen);

	EVP_MD_CTX_free(mdctx);

	return 0;
}

int hash_multiple_buffers(uint8_t **buffers, uint32_t *buffer_sizes,
			  uint32_t num_buffers, uint8_t *hash_buf)
{
	unsigned int hashLen = 0;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_sha256();
	
	EVP_DigestInit_ex(mdctx, md, NULL);
	for (uint32_t i = 0; i < num_buffers; i++)
		EVP_DigestUpdate(mdctx, buffers[i], buffer_sizes[i]);
	EVP_DigestFinal_ex(mdctx, hash_buf, &hashLen);
	
	EVP_MD_CTX_free(mdctx);

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