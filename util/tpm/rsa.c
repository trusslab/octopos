/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/*
 * RSA-related code taken/adapted from:
 * http://hayageek.com/rsa-encryption-decryption-openssl-c/
 */
#include <stdio.h>
#include <tpm/rsa.h>
#include <openssl/pem.h>

int padding = RSA_PKCS1_PADDING;
 
EVP_PKEY *create_rsa(unsigned char *key, int _public)
{
	EVP_PKEY *pubKey = NULL;
	BIO *keybio;

	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL) {
		printf( "Failed to create key BIO");
		return 0;
	}

	if (_public)
		pubKey = PEM_read_bio_PUBKEY(keybio, NULL, NULL, NULL);
	else
		pubKey = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);

	if (pubKey == NULL)
		printf("Failed to create RSA");

	return pubKey;
}
 
// int public_encrypt(unsigned char *data, int data_len, unsigned char *key,
// 		   unsigned char *encrypted)
// {
// 	EVP_PKEY *pubKey = create_rsa(key, 1);

// 	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
// 	if (!ctx) {
// 		printf("Failed to create ctx");
// 		return -1;
// 	}
// 	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
// 		printf("Failed to init ctx");
// 		return -1;
// 	}
// 	if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
// 		printf("Failed to set padding");
// 		return -1;
// 	}
// 	size_t encrypted_length;
// 	if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_length, data, data_len) <= 0) {
// 		printf("Failed to encrypt");
// 		return -1;
// 	}
// 	encrypted = (unsigned char *)malloc(encrypted_length);
// 	return EVP_PKEY_encrypt(ctx, encrypted, &encrypted_length, data, data_len);
// }

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
		   unsigned char *decrypted)
{
	EVP_PKEY *pubKey = create_rsa(key, 1);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
	if (!ctx) {
		printf("Failed to create ctx");
		return -1;
	}
	if (EVP_PKEY_verify_recover_init(ctx) <= 0) {
		printf("Failed to init ctx");
		return -1;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
		printf("Failed to set padding");
		return -1;
	}
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
		printf("Failed to set md");
		return -1;
	}

	size_t decrypted_length;
	EVP_PKEY_verify_recover(ctx, decrypted, &decrypted_length, enc_data, data_len);
	return (int)decrypted_length;

	// EVP_PKEY *pubKey = create_rsa(key, 1);

	// EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
	// if (!ctx) {
	// 	printf("Failed to create ctx\n");
	// 	return -1;
	// }
	// if (EVP_PKEY_decrypt_init(ctx) <= 0) {
	// 	printf("Failed to init ctx\n");
	// 	return -1;
	// }
	// if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
	// 	printf("Failed to set padding\n");
	// 	return -1;
	// }

	// size_t decrypted_length;
	// if (EVP_PKEY_decrypt(ctx, decrypted, &decrypted_length, enc_data, data_len) <= 0) {
	// 	printf("Failed to decrypt\n");
	// 	return -1;
	// }

	// return decrypted_length;
}
 
int private_encrypt(unsigned char *data, int data_len, unsigned char *key,
		    unsigned char *encrypted)
{
	EVP_PKEY *pubKey = create_rsa(key, 0);
	size_t encrypted_length;

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
	if (!ctx) {
		printf("Failed to create ctx");
		return -1;
	}
	if (EVP_PKEY_sign_init(ctx) <= 0) {
		printf("Failed to init ctx");
		return -1;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
		printf("Failed to set padding");
		return -1;
	}
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
		printf("Failed to set md");
		return -1;
	}
	
	if (EVP_PKEY_sign(ctx, encrypted, &encrypted_length, data, data_len) <= 0) {
		printf("Failed to encrypt");
		return -1;
	}
	
	return (int)encrypted_length;
}

// int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
// 		    unsigned char *decrypted)
// {
// 	EVP_PKEY *pubKey = create_rsa(key, 0);

// 	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubKey, NULL);
// 	if (!ctx) {
// 		printf("Failed to create ctx");
// 		return -1;
// 	}
// 	if (EVP_PKEY_verify_init(ctx) <= 0) {
// 		printf("Failed to init ctx");
// 		return -1;
// 	}
// 	if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
// 		printf("Failed to set padding");
// 		return -1;
// 	}
// 	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
// 		printf("Failed to set md");
// 		return -1;
// 	}

// 	size_t decrypted_length;
// 	EVP_PKEY_verify(ctx, NULL, &decrypted_length, enc_data, data_len);
// 	if (decrypted_length > SHA256_DIGEST_LENGTH) {
// 		printf("Failed to decrypt");
// 		return -1;
// 	}

// 	return EVP_PKEY_verify(ctx, decrypted, &decrypted_length, enc_data, data_len);
// }
