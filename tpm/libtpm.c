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

int prepare_extend(char *hash_buf, TPML_DIGEST_VALUES *digest_value)
{
	BYTE *digest_data = (BYTE *) &digest_value->digests->digest;
	UINT16 hash_size = TPM2_SHA256_DIGEST_SIZE;
	int rc = hash_to_byte_structure(hash_buf, &hash_size, digest_data);
	if (rc) {
		fprintf(stderr, "Error converting hex string as data, got: \"%s\"",
			hash_buf);
		return -1;
	}

	return 0;
}
