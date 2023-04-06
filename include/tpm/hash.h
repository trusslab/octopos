/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef ARCH_SEC_HW

#include <openssl/sha.h>

#define TPM_AT_ID_LENGTH 16
#define TPM_AT_NONCE_LENGTH 16
#define TPM_EXTEND_HASH_SIZE SHA256_DIGEST_LENGTH

int hash_file(char *path, uint8_t *hash_buf);
void convert_hash_to_str(uint8_t *hash_buf, char *hash_str);
int hash_buffer(uint8_t *buffer, uint32_t buffer_size, uint8_t *hash_buf);
int hash_multiple_buffers(uint8_t **buffers, uint32_t *buffer_sizes,
			  uint32_t num_buffers, uint8_t *hash_buf);
void print_hash_buf(uint8_t *hash_buf);

#else

#define TPM_EXTEND_HASH_SIZE 32

#endif