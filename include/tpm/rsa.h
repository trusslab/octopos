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

#define RSA_SIGNATURE_SIZE 256

int public_encrypt(unsigned char *data, int data_len, unsigned char *key,
		   unsigned char *encrypted);
int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
		    unsigned char *decrypted);
int private_encrypt(unsigned char *data, int data_len, unsigned char *key,
		    unsigned char *encrypted);
int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
		   unsigned char *decrypted);