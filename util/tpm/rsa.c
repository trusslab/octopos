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
#include <openssl/pem.h>

int padding = RSA_PKCS1_PADDING;
 
RSA *create_rsa(unsigned char *key, int _public)
{
	RSA *rsa = NULL;
	BIO *keybio;

	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL) {
		printf( "Failed to create key BIO");
		return 0;
	}

	if (_public)
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	else
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	if (rsa == NULL)
		printf( "Failed to create RSA");

	return rsa;
}
 
int public_encrypt(unsigned char *data, int data_len, unsigned char *key,
		   unsigned char *encrypted)
{
	RSA *rsa = create_rsa(key, 1);

	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);

	return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
		    unsigned char *decrypted)
{
	RSA *rsa = create_rsa(key, 0);

	int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa,
	    			      padding);

	return result;
}
 
 
int private_encrypt(unsigned char *data, int data_len, unsigned char *key,
		    unsigned char *encrypted)
{
	RSA *rsa = create_rsa(key, 0);

	int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);

	return result;
}

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
		   unsigned char *decrypted)
{
	RSA *rsa = create_rsa(key, 1);

	int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);

	return result;
}