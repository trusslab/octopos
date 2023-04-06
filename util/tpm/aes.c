/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#include <tpm/aes.h>

/* AES-GCM-256
 * Referenced from https://github.com/bawejakunal/AES-GCM-256 licensed under MIT
 *
 * The cipher contains the encrypted ciphertext and the authentication tag.
 * The cipher_size is the sum of ciphertext's length and tag_size bytes.
 * In our context, the cipher_size is
 *   cipher_size = sizeof(app_context) + TAG_SIZE = 362 + 16 = 378
 */
int aes_encrypt(uint8_t *key_iv, uint8_t *plain, size_t plain_size,
		uint8_t *cipher, size_t *cipher_size)
{
	EVP_CIPHER_CTX *aes_ctx;
	int rc = 0;
	int len = 0;
	int result_size = 0;
	uint8_t key[KEY_SIZE];
	uint8_t iv[IV_SIZE];
	uint8_t tag[TAG_SIZE];

	memcpy(key, key_iv, KEY_SIZE);
	memcpy(iv, key_iv + KEY_SIZE, IV_SIZE);

	if (!(aes_ctx = EVP_CIPHER_CTX_new())) {
                printf("Context Initialization Error\n");
                return -1;
        }

	rc = EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	aes_return_if_error(rc, "Encryption Initialization Error",
			    encrypt_finalize);

	rc = EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
	aes_return_if_error(rc, "IV Length Setting Error", encrypt_finalize);

	rc = EVP_EncryptInit_ex(aes_ctx, NULL, NULL, key, iv);
	aes_return_if_error(rc, "Key and IV Initialization Error",
			    encrypt_finalize);

	while ((size_t) result_size + 16 <= plain_size) {
		rc = EVP_EncryptUpdate(aes_ctx, cipher + result_size,
				       &len, plain + result_size, 16);
		aes_return_if_error(rc, "Encryption Update Error",
				    encrypt_finalize);
		result_size += len;
	}

	rc = EVP_EncryptUpdate(aes_ctx, cipher + result_size,
			       &len, plain + result_size,
			       plain_size - result_size);
	aes_return_if_error(rc, "Encryption Update Error", encrypt_finalize);
	result_size += len;

	rc = EVP_EncryptFinal_ex(aes_ctx, cipher + result_size, &len);
	aes_return_if_error(rc, "Encryption Finalization Error", encrypt_finalize);
	result_size += len;

	rc = EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
	aes_return_if_error(rc, "Tag Generation Error", encrypt_finalize);

	memcpy(cipher + result_size, tag, TAG_SIZE);
	*cipher_size = (result_size + TAG_SIZE);

encrypt_finalize:
	EVP_CIPHER_CTX_free(aes_ctx);
	return rc;
}


int aes_decrypt(uint8_t *key_iv, uint8_t *plain, size_t *plain_size,
		uint8_t *cipher, size_t cipher_size)
{
	EVP_CIPHER_CTX *aes_ctx;
	int rc = 0;
	int len = 0;
	int result_size = 0;
	uint8_t key[KEY_SIZE];
	uint8_t iv[IV_SIZE];
	uint8_t tag[TAG_SIZE];
	uint8_t *cipher_real = NULL;
	size_t cipher_size_real = cipher_size - TAG_SIZE;

	memcpy(key, key_iv, KEY_SIZE);
	memcpy(iv, key_iv + KEY_SIZE, IV_SIZE);
	cipher_real = (uint8_t *) malloc(cipher_size_real * sizeof(uint8_t));
	memcpy(cipher_real, cipher, cipher_size_real);
	memcpy(tag, cipher + cipher_size_real, TAG_SIZE);

	if (!(aes_ctx = EVP_CIPHER_CTX_new())) {
		printf("Context Initialization Error\n");
		return -1;
	}

	rc = EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	aes_return_if_error(rc, "Encryption Initialization Error",
			    decrypt_finalize);

	rc = EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
	aes_return_if_error(rc, "IV Length Setting Error", decrypt_finalize);

	rc = EVP_DecryptInit_ex(aes_ctx, NULL, NULL, key, iv);
	aes_return_if_error(rc, "Key and IV Initialization Error",
			    decrypt_finalize);


	while ((size_t) result_size + 16 <= cipher_size_real) {
		rc = EVP_DecryptUpdate(aes_ctx, plain + result_size,
				       &len, cipher + result_size, 16);
		aes_return_if_error(rc, "Decryption Update Error",
				    decrypt_finalize);
		result_size += len;
	}

	rc = EVP_DecryptUpdate(aes_ctx, plain + result_size,
			       &len, cipher_real + result_size,
			       cipher_size_real - result_size);
	aes_return_if_error(rc, "Decryption Update Error", decrypt_finalize);
	result_size += len;

	rc = EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag);
	aes_return_if_error(rc, "Tag Length Setting Error", decrypt_finalize);

	rc = EVP_DecryptFinal_ex(aes_ctx, plain + result_size, &len);
	aes_return_if_error(rc, "Decryption Final Error", decrypt_finalize);
	result_size += len;

	*plain_size = result_size;

decrypt_finalize:
	EVP_CIPHER_CTX_free(aes_ctx);
	free(cipher_real);

	return rc;
}