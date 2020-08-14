#include <tpm/libtpm.h>
#include <ctype.h>
#include <openssl/sha.h>

int hash_to_byte_structure(const char *input_string, UINT16 *byte_length, BYTE *byte_buffer)
{
    if (input_string == NULL || byte_length == NULL || byte_buffer == NULL) {
        return -1;
	}
    
    int str_length = strlen(input_string);
	if (str_length % 2 || *byte_length < str_length / 2) {
		return -1;
	}

	int i = 0;
	for (i = 0; i < str_length; i++) {
        if (!isxdigit(input_string[i])) {
            return -1;
		}
    }

    *byte_length = str_length / 2;
    for (i = 0; i < *byte_length; i++) {
        char tmp_str[4] = { 0 };
        tmp_str[0] = input_string[i * 2];
        tmp_str[1] = input_string[i * 2 + 1];
        byte_buffer[i] = strtol(tmp_str, NULL, 16);
    }

    return 0;
}

int hash_file(char *path, char *hash_buffer)
{
    FILE *bin = fopen(path, "rb");
	if (!bin) {
		fprintf(stderr, "File %s can not be opened.", path);
		return -1;
	}

	const int per_buf_size = 32768;
    unsigned char *buffer = (unsigned char *)malloc(per_buf_size * sizeof(unsigned char));
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
        sprintf(hash_buffer + (i * 2), "%02x", hash[i]);
    }
    hash_buffer[64] = 0;
    
	fclose(bin);
	free(buffer);
    return 0;
}

int prepare_extend(char *path, TPML_DIGEST_VALUES *digest_value)
{
	char hash_buffer[65] = { 0 };
	hash_file(path, hash_buffer);

	BYTE *digest_data = (BYTE *) &digest_value->digests->digest;
	UINT16 hash_size = TPM2_SHA256_DIGEST_SIZE;
	int rc = hash_to_byte_structure(hash_buffer, &hash_size, digest_data);
	if (rc) {
		fprintf(stderr, "Error converting hex string as data, got: \"%s\"", hash_buffer);
		return -1;
	}

	return 0;
}