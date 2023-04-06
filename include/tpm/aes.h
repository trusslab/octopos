/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define KEY_SIZE 	32
#define IV_SIZE 	16
#define AES_GEN_SIZE 	(KEY_SIZE + IV_SIZE)
#define TAG_SIZE	16

#define aes_return_if_error(r,msg,label) \
	if (r != 1) { \
		fprintf(stderr, "%s\n", msg); \
                rc = -1; \
		goto label; \
	}

int aes_encrypt(uint8_t *key_iv, uint8_t *plain, size_t plain_size,
		uint8_t *cipher, size_t *cipher_size);
int aes_decrypt(uint8_t *key_iv, uint8_t *plain, size_t *plain_size,
		uint8_t *cipher, size_t cipher_size);