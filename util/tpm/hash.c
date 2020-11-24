#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

int hash_file(char *path, char *hash_buf)
{
	FILE *bin = fopen(path, "rb");
	if (!bin) {
		fprintf(stderr, "File %s can not be opened.", path);
		return -1;
	}

	const int per_buf_size = 32768;
	unsigned char *buffer = (unsigned char *)
		malloc(per_buf_size * sizeof(unsigned char));
	if(!buffer)
		return EOF;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX hash_ctx;
	SHA256_Init(&hash_ctx);

	int bytes_read = 0;
	while((bytes_read = fread(buffer, 1, per_buf_size, bin))) {
		SHA256_Update(&hash_ctx, buffer, bytes_read);
	}
	SHA256_Final(hash, &hash_ctx);

	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(hash_buf + (i * 2), "%02x", hash[i]);
	}
	hash_buf[64] = 0;
	
	fclose(bin);
	free(buffer);
	return 0;
}
