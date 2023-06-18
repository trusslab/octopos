/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* OctopOS installer
 *
 * Helps with the following:
 * - Preparing the boot partition including executables and signatures needed
 *   for secure boot.
 * - Preparing some files needed for the untrusted rootfs partition
 * - Generating The hash of the bluetooth service needed for secure boot
 * - Preparing the signature for authorized apps needed to enforce restricted
 *   access.
 *
 * RSA-related code taken/adapted from:
 * http://hayageek.com/rsa-encryption-decryption-openssl-c/
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <octopos/storage.h>
#include <tpm/hash.h>
#include <tpm/rsa.h>
#include <os/file_system.h>

unsigned char admin_private_key[] = 
"-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEogIBAAKCAQEAwWFcfENwpIqWp3spCLTgXncdEG4eBQQK6YV4cvX//b2ab8rk\n"\
"wo+xmLD0lGqpFrtWHAvtiI5fqh5jPHZwrd541bIXcrJOrhhAJGiEW/i/aQB/XQyF\n"\
"WDWt/+wr6SE7J5KZEHZpVxsSeu9yuIWDSYTpcOk674/leUjIpPpxZkbHVQe0R/Dj\n"\
"a1Xi5SRnyeuYX7fSV2mDNltZ3sCuCXyVNgJ1wtFGZj87NCHw7vbPJxI8hb2ro3RE\n"\
"bUUzfeB0A+tizU54MkCot50iqgX0C3TLavC4UysSb22EZY89zS6eZ174Lru4XYEI\n"\
"pStT6IzurmvLbU2AECkkRNlJBc6e+jMR8z34cQIDAQABAoIBAFk4b3BRuT3hR0L8\n"\
"euEuerp64Gj9NVKBG/vD/d+kijhq6z8a8FKn83uMYTu8vkjjpAYKpswzTAX0QTrb\n"\
"Nn+xvjRyF4lupQiD3cwugKriaIWsmha3OSqKkb4bG+NS1rUaWQ6UY2Ox9OPNaDOk\n"\
"Pf+EmCPlJ7DxxiEgKJqdhgZ3L26V8nFXbk4IjM4v2aEr+m+Il3t/T9t/h/CsRJDt\n"\
"Zm3IEEUPX4XmRSLOBBWNN86xkiHAtqP7BzTPorpbFbizyfhR4yv8Up1XVpgZH8Kr\n"\
"vzPkXnAthcKC8E2pE4SJbslE3geBG/ONHOeRTW9Aflr9Z5lWtHRxnOnlwc1nlcJk\n"\
"DaCTUrECgYEA8KD4kMTH+QgkbbmFgcXBDtMSKe59O+r7Wmlii6in2X3Bc7m6O7yJ\n"\
"WHC7//5k6DmZ5pQPttZiKsD1HzUSpHi3I82wEQNtBkkCYL2EI/hVVUXzzDSsz4EY\n"\
"EjNLYUuHJmCNmrqg4o89Oi140dvWRNVLh/eW5VRnpzLZVn8CCTPmkRUCgYEAzbu7\n"\
"FojudTKmQD4E8pSwaEx24h347TE1xqhJ/ymMGteVztptJctNdPaLOp2ldPvPtic+\n"\
"3gn4/dVQDCjBiirv+kkWRdG4JE7umMRdS+/Yp+M/gRaE14g2PVdzrG/GHRpTghob\n"\
"p9QGhrTJ4dDZufqUeWty4hMtEJ1YZgEBXi99CO0CgYAXX6uFdHfwSsgvGFxNlMYC\n"\
"CKK1DAOCNHsh9yapZkKXr82AzkO21cOJobnBThbDMAUxDqTQH9b9TC0DUQZ0j31K\n"\
"rwoxPOH0QFdIyl/xlofDdr4N0fgPV/zcl7r0wn9oTOy0YPiLyVorMouP5wjTOtzR\n"\
"Yk14DVDcPuY5rrCl8DKvWQKBgE1zPxtcsWitiKjmsDYig8bAAoFdhzjELdp7wF+u\n"\
"5G+2eU9GK5Du2FoP9po6fu9rXObWH3S3jGUCyP/K2BGL2IwAt8HREeGZVXltczID\n"\
"OSz7AA04zQnW3ZR6N7HS4mJSZt2ztnWX/Fz58oZweYbqLrsHGFjDn1OB6KV9+2XZ\n"\
"utiBAoGABHyjf2q6Iuj2D0G0kllzII6+9SlmURo8ZYJKIKPdwtOc4pNuPx6XQRCX\n"\
"cWUtGi+7E3ewkXMqLrBU3YWLTOvs3AeN9ocXxlPBc4Zol3nhmoFc+saXa7iAmc69\n"\
"2NkFhmh6fbgIkQTUJTgn4OTw5e+tkP065duvJbAKE78/kqiqRj0=\n"\
"-----END RSA PRIVATE KEY-----\n";

/* in file system wrapper */
extern FILE *filep;
extern uint32_t total_blocks;

static int generate_signature(char *file_path, char *signature_file_path)
{
	FILE *filep;
	uint8_t file_hash[TPM_EXTEND_HASH_SIZE];
	uint8_t signature[RSA_SIGNATURE_SIZE];
	uint32_t size;
	int ret;

	hash_file(file_path, file_hash);

	/* generate signature */
	ret = private_encrypt((unsigned char *) file_hash, TPM_EXTEND_HASH_SIZE,
			      admin_private_key, (unsigned char *) signature);
	if (ret != RSA_SIGNATURE_SIZE) {
		printf("Error: %s: couldn't generate the signature (%d).\n",
		       __func__, ret);
		return -1;
	}

	filep = fopen(signature_file_path, "w");
	if (!filep) {
		printf("Error: %s: Couldn't open %s (w).\n", __func__,
		       signature_file_path);
		return -1;
	}

	fseek(filep, 0, SEEK_SET);
	size = (uint32_t) fwrite(signature, sizeof(uint8_t), RSA_SIGNATURE_SIZE,
				 filep);
	if (size != RSA_SIGNATURE_SIZE) {
		printf("Error: %s: couldn't write the signature.\n", __func__);
		fclose(filep);
		return -1;
	}

	fclose(filep);

	return 0;
}

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 * @block_aligned: if non-zero, we will pad the end of the copied file with
 * as many zeros as needed to align it with storage block size.
 */
static int copy_file_from_partition(char *filename, char *copy_path,
				    int block_aligned)
{
	uint32_t fd;
	FILE *copy_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int _size;
	int offset;

	fd = file_system_open_file(filename, FILE_OPEN_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file system"
		       " (copy).\n", __func__, filename);
		return -1;
	}

	copy_filep = fopen(copy_path, "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the target file (%s).\n",
		       __func__, copy_path);
		return -1;
	}

	offset = 0;

	while (1) {
		_size = file_system_read_from_file(fd, buf, STORAGE_BLOCK_SIZE,
						   offset);
		if (_size == 0)
			break;

		if (_size < 0 || _size > STORAGE_BLOCK_SIZE) {
			printf("Error: %s: reading file.\n", __func__);
			break;
		}

		fseek(copy_filep, offset, SEEK_SET);
		fwrite(buf, sizeof(uint8_t), _size, copy_filep);

		offset += _size;

		/* Last block */
		if (_size != STORAGE_BLOCK_SIZE)
			break;
	}

	if (block_aligned && (_size > 0)) {
		int rem = STORAGE_BLOCK_SIZE - _size;

		memset(buf, 0x0, rem);
		fseek(copy_filep, offset, SEEK_SET);
		fwrite(buf, sizeof(uint8_t), rem, copy_filep);
	}

	fclose(copy_filep);
	file_system_close_file(fd);

	return 0;
}

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 */
static int copy_file_to_partition(char *filename, char *path)
{
	uint32_t fd;
	FILE *src_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int _size;
	int offset;

	fd = file_system_open_file(filename, FILE_OPEN_CREATE_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file "
		       "system.\n", __func__, filename);
		return -1;
	}

	src_filep = fopen(path, "r");
	if (!src_filep) {
		printf("Error: %s: Couldn't open the source file (%s).\n",
		       __func__, path);
		return -1;
	}

	offset = 0;

	while (1) { 
		fseek(src_filep, offset, SEEK_SET);
		_size = fread(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE,
			      src_filep);
		if (_size == 0)
			break;

		if (_size < 0 || _size > STORAGE_BLOCK_SIZE) {
			printf("Error: %s: reading file.\n", __func__);
			break;
		}

		file_system_write_to_file(fd, buf, _size, offset);

		offset += _size;
	}

	fclose(src_filep);
	file_system_close_file(fd);

	return 0;
}

static int prepare_boot_partition(void)
{
	/* create new file or delete existing file */
	filep = fopen("./storage/octopos_partition_0_data", "w");
	if (!filep) {
		printf("Error: %s: Couldn't open the partition file (w).\n",
		       __func__);
		return -1;
	}
	fclose(filep);

	/* open for read and write */
	filep = fopen("./storage/octopos_partition_0_data", "r+");
	if (!filep) {
		printf("Error: %s: Couldn't open the partition file (r+).\n",
		       __func__);
		return -1;
	}

	total_blocks += DIR_DATA_NUM_BLOCKS;

	initialize_file_system(STORAGE_BOOT_PARTITION_SIZE);

	copy_file_to_partition((char *) "keyboard",
			       (char *) "./keyboard/keyboard");
	copy_file_to_partition((char *) "serial_out",
			       (char *) "./serial_out/serial_out");
	copy_file_to_partition((char *) "storage",
			       (char *) "./storage/storage");
	copy_file_to_partition((char *) "os", (char *) "./os/os");
	copy_file_to_partition((char *) "runtime",
			       (char *) "./runtime/runtime");
	copy_file_to_partition((char *) "network",
			       (char *) "./network/network");
	copy_file_to_partition((char *) "bluetooth",
			       (char *) "./bluetooth/bluetooth");
	copy_file_to_partition((char *) "linux",
			       (char *) "./arch/umode/untrusted_linux/linux");
	copy_file_to_partition((char *) "attest_client",
			       (char *) "./applications/bin/attest_client.so");
	copy_file_to_partition((char *) "bank_client",
			       (char *) "./applications/bin/bank_client.so");
	copy_file_to_partition((char *) "fs_loop",
			       (char *) "./applications/bin/fs_loop.so");
	copy_file_to_partition((char *) "fs_test",
			       (char *) "./applications/bin/fs_test.so");
	copy_file_to_partition((char *) "health_client",
			       (char *) "./applications/bin/health_client.so");
	copy_file_to_partition((char *) "ipc_receiver",
			       (char *) "./applications/bin/ipc_receiver.so");
	copy_file_to_partition((char *) "ipc_sender",
			       (char *) "./applications/bin/ipc_sender.so");
	copy_file_to_partition((char *) "secure_interact",
			       (char *) "./applications/bin/secure_interact.so");
	copy_file_to_partition((char *) "secure_login",
			       (char *) "./applications/bin/secure_login.so");
	copy_file_to_partition((char *) "simple_loop",
			       (char *) "./applications/bin/simple_loop.so");
	copy_file_to_partition((char *) "socket_client",
			       (char *) "./applications/bin/socket_client.so");

	/* For testing purposes, copy the files from partition */
	copy_file_from_partition((char *) "keyboard",
				 (char *) "./installer/copy_keyboard", 0);
	copy_file_from_partition((char *) "serial_out",
				 (char *) "./installer/copy_serial_out", 0);
	copy_file_from_partition((char *) "storage",
				 (char *) "./installer/copy_storage", 0);
	copy_file_from_partition((char *) "os",
				 (char *) "./installer/copy_os", 0);
	copy_file_from_partition((char *) "runtime",
				 (char *) "./installer/copy_runtime", 0);
	copy_file_from_partition((char *) "network",
				 (char *) "./installer/copy_network", 0);
	copy_file_from_partition((char *) "bluetooth",
				 (char *) "./installer/copy_bluetooth", 0);
	copy_file_from_partition((char *) "linux",
				 (char *) "./installer/copy_linux", 0);
	copy_file_from_partition((char *) "attest_client",
				 (char *) "./installer/copy_attest_client.so", 0);
	copy_file_from_partition((char *) "bank_client",
				 (char *) "./installer/copy_bank_client.so", 0);
	copy_file_from_partition((char *) "fs_loop",
				 (char *) "./installer/copy_fs_loop.so", 0);
	copy_file_from_partition((char *) "fs_test",
				 (char *) "./installer/copy_fs_test.so", 0);
	copy_file_from_partition((char *) "health_client",
				 (char *) "./installer/copy_health_client.so", 0);
	copy_file_from_partition((char *) "ipc_receiver",
				 (char *) "./installer/copy_ipc_receiver.so", 0);
	copy_file_from_partition((char *) "ipc_sender",
				 (char *) "./installer/copy_ipc_sender.so", 0);
	copy_file_from_partition((char *) "secure_interact",
				 (char *) "./installer/copy_secure_interact.so", 0);
	copy_file_from_partition((char *) "secure_login",
				 (char *) "./installer/copy_secure_login.so", 0);
	copy_file_from_partition((char *) "simple_loop",
				 (char *) "./installer/copy_simple_loop.so", 0);
	copy_file_from_partition((char *) "socket_client",
				 (char *) "./installer/copy_socket_client.so", 0);

	/* For attestation, we need the block-aligned version of some of the
	 * files.
	 */
	copy_file_from_partition((char *) "keyboard",
				 (char *) "./installer/aligned_keyboard", 1);
	copy_file_from_partition((char *) "serial_out",
				 (char *) "./installer/aligned_serial_out", 1);
	copy_file_from_partition((char *) "runtime",
				 (char *) "./installer/aligned_runtime", 1);
	copy_file_from_partition((char *) "network",
				 (char *) "./installer/aligned_network", 1);
	copy_file_from_partition((char *) "bluetooth",
				 (char *) "./installer/aligned_bluetooth", 1);
	copy_file_from_partition((char *) "linux",
				 (char *) "./installer/aligned_linux", 1);

	/* generate and add the signature files for secure boot. */
	generate_signature((char *) "./installer/aligned_keyboard",
			   (char *) "./installer/keyboard_signature");
	generate_signature((char *) "./installer/aligned_serial_out",
			   (char *) "./installer/serial_out_signature");
	generate_signature((char *) "./storage/storage",
			   (char *) "./installer/storage_signature");
	generate_signature((char *) "./os/os",
			   (char *) "./installer/os_signature");
	generate_signature((char *) "./installer/aligned_runtime",
			   (char *) "./installer/runtime_signature");
	generate_signature((char *) "./installer/aligned_network",
			   (char *) "./installer/network_signature");
	generate_signature((char *) "./installer/aligned_bluetooth",
			   (char *) "./installer/bluetooth_signature");
	generate_signature((char *) "./installer/aligned_linux",
			   (char *) "./installer/linux_signature");

	copy_file_to_partition((char *) "keyboard_signature",
			       (char *) "./installer/keyboard_signature");
	copy_file_to_partition((char *) "serial_out_signature",
			       (char *) "./installer/serial_out_signature");
	copy_file_to_partition((char *) "storage_signature",
			       (char *) "./installer/storage_signature");
	copy_file_to_partition((char *) "os_signature",
			       (char *) "./installer/os_signature");
	copy_file_to_partition((char *) "runtime_signature",
			       (char *) "./installer/runtime_signature");
	copy_file_to_partition((char *) "network_signature",
			       (char *) "./installer/network_signature");
	copy_file_to_partition((char *) "bluetooth_signature",
			       (char *) "./installer/bluetooth_signature");
	copy_file_to_partition((char *) "linux_signature",
			       (char *) "./installer/linux_signature");

	/* For testing purposes, copy the files from partition */
	copy_file_from_partition((char *) "keyboard_signature",
				 (char *) "./installer/copy_keyboard_signature", 0);
	copy_file_from_partition((char *) "serial_out_signature",
				 (char *) "./installer/copy_serial_out_signature", 0);
	copy_file_from_partition((char *) "storage_signature",
				 (char *) "./installer/copy_storage_signature", 0);
	copy_file_from_partition((char *) "os_signature",
				 (char *) "./installer/copy_os_signature", 0);
	copy_file_from_partition((char *) "runtime_signature",
				 (char *) "./installer/copy_runtime_signature", 0);
	copy_file_from_partition((char *) "network_signature",
				 (char *) "./installer/copy_network_signature", 0);
	copy_file_from_partition((char *) "bluetooth_signature",
				 (char *) "./installer/copy_bluetooth_signature", 0);
	copy_file_from_partition((char *) "linux_signature",
				 (char *) "./installer/copy_linux_signature", 0);

	printf("installer: total number of written blocks = %d\n", total_blocks);

	close_file_system();
	fclose(filep);

	return 0;
}

/* Both the OS bootloader and OS access this partition.
 * The OS PCR register will be zero when the bootloader is running and before
 * it extends the register with the hash of the OS executable.
 */
static int set_up_key_for_boot_partition(void)
{
	FILE *lfilep;
	uint8_t os_pcr[TPM_EXTEND_HASH_SIZE];
	uint8_t file_hash[TPM_EXTEND_HASH_SIZE];
	uint8_t *buffers[2];
	uint32_t buffer_sizes[2];
	uint8_t zero_pcr[TPM_EXTEND_HASH_SIZE];
	uint32_t size;

	memset(zero_pcr, 0x0, TPM_EXTEND_HASH_SIZE);

	/* create new file or delete existing file */
	lfilep = fopen("./storage/octopos_partition_0_keys", "w");
	if (!lfilep) {
		printf("Error: %s: Couldn't open the partition keys file "
		       "(w).\n", __func__);
		return -1;
	}
	fclose(lfilep);

	/* open for read and write */
	lfilep = fopen("./storage/octopos_partition_0_keys", "r+");
	if (!lfilep) {
		printf("Error: %s: Couldn't open the partition keys file "
		       "(r+).\n", __func__);
		return -1;
	}
	
	buffer_sizes[0] = TPM_EXTEND_HASH_SIZE;
	buffer_sizes[1] = TPM_EXTEND_HASH_SIZE;
	
	/* OS PCR */
	hash_file((char *) "./os/os", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, os_pcr);

	fseek(lfilep, 0, SEEK_SET);
	/* zero_pcr is for the OS bootloader. */
	size = (uint32_t) fwrite(zero_pcr, sizeof(uint8_t),
				 TPM_EXTEND_HASH_SIZE, lfilep);
	if (size != TPM_EXTEND_HASH_SIZE) {
		printf("Error: %s: couldn't write the OS bootloader PCR.\n",
		       __func__);
		fclose(lfilep);
		return -1;
	}

	fseek(lfilep, TPM_EXTEND_HASH_SIZE, SEEK_SET);
	size = (uint32_t) fwrite(os_pcr, sizeof(uint8_t), TPM_EXTEND_HASH_SIZE,
				 lfilep);
	if (size != TPM_EXTEND_HASH_SIZE) {
		printf("Error: %s: couldn't write the OS PCR.\n", __func__);
		fclose(lfilep);
		return -1;
	}

	fclose(lfilep);

	return 0;
}

static int set_up_key_for_untrusted_rootfs_partition(void)
{
	FILE *lfilep;
	uint8_t untrusted_pcr[TPM_EXTEND_HASH_SIZE];
	uint8_t file_hash[TPM_EXTEND_HASH_SIZE];
	uint8_t *buffers[2];
	uint32_t buffer_sizes[2];
	uint8_t zero_pcr[TPM_EXTEND_HASH_SIZE];
	uint32_t size;

	memset(zero_pcr, 0x0, TPM_EXTEND_HASH_SIZE);

	/* create new file or delete existing file */
	lfilep = fopen("./storage/octopos_partition_1_keys", "w");
	if (!lfilep) {
		printf("Error: %s: Couldn't open the partition keys file "
		       "(w).\n", __func__);
		return -1;
	}
	fclose(lfilep);

	/* open for read and write */
	lfilep = fopen("./storage/octopos_partition_1_keys", "r+");
	if (!lfilep) {
		printf("Error: %s: Couldn't open the partition keys file "
		       "(r+).\n", __func__);
		return -1;
	}
	
	/* generate PCR digest for OS bootloader and OS. */
	buffer_sizes[0] = TPM_EXTEND_HASH_SIZE;
	buffer_sizes[1] = TPM_EXTEND_HASH_SIZE;
	
	/* Linux PCR */
	hash_file((char *) "./installer/aligned_linux", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, untrusted_pcr);

	fseek(lfilep, 0, SEEK_SET);
	size = (uint32_t) fwrite(untrusted_pcr, sizeof(uint8_t),
				 TPM_EXTEND_HASH_SIZE, lfilep);
	if (size != TPM_EXTEND_HASH_SIZE) {
		printf("Error: %s: couldn't write the untrusted_pcr.\n",
		       __func__);
		fclose(lfilep);
		return -1;
	}

	fclose(lfilep);

	return 0;
}

static int mark_partition_as_created(char *create_filename)
{
	FILE *lfilep;
	uint32_t tag = 1;
	uint32_t size;

	/* create new file or delete existing file */
	lfilep = fopen(create_filename, "w");
	if (!lfilep) {
		printf("Error: %s: Couldn't open the partition create file "
		       "(w) (%s).\n", __func__, create_filename);
		return -1;
	}
	fclose(lfilep);

	/* open for read and write */
	lfilep = fopen(create_filename, "r+");
	if (!lfilep) {
		printf("Error: %s: Couldn't open the partition create file "
		       "(r+) (%s).\n", __func__, create_filename);
		return -1;
	}
	
	fseek(lfilep, 0, SEEK_SET);
	/* zero_pcr is for the OS bootloader. */
	size = (uint32_t) fwrite(&tag, sizeof(uint8_t), 4, lfilep);
	if (size != 4) {
		printf("Error: %s: couldn't write to the create file.\n",
		       __func__);
		fclose(lfilep);
		return -1;
	}

	fclose(lfilep);

	return 0;
}

static int mark_boot_partition_as_created(void)
{
	return mark_partition_as_created((char *)
					 "./storage/octopos_partition_0_create");
}

static int mark_untrusted_rootfs_partition_as_created(void)
{
	return mark_partition_as_created((char *)
					 "./storage/octopos_partition_1_create");
}

static int generate_signature_for_health_client_PCR(void)
{
	uint8_t app_pcr[TPM_EXTEND_HASH_SIZE];
	uint8_t file_hash[TPM_EXTEND_HASH_SIZE];
	uint8_t temp_hash[TPM_EXTEND_HASH_SIZE];
	uint8_t *buffers[2];
	uint32_t buffer_sizes[2];
	uint8_t zero_pcr[TPM_EXTEND_HASH_SIZE];
	uint8_t signature[RSA_SIGNATURE_SIZE];
	uint32_t size;
	int ret;

	memset(zero_pcr, 0x0, TPM_EXTEND_HASH_SIZE);

	buffer_sizes[0] = TPM_EXTEND_HASH_SIZE;
	buffer_sizes[1] = TPM_EXTEND_HASH_SIZE;
	
	/* App PCR: two hashes are extended to PCR in this case. */
	hash_file((char *) "./installer/aligned_runtime", file_hash);
	buffers[0] = zero_pcr;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, temp_hash);
	hash_file((char *) "applications/health_client/health_client.so",
		  file_hash);
	buffers[0] = temp_hash;
	buffers[1] = file_hash;
	hash_multiple_buffers(buffers, buffer_sizes, 2, app_pcr);

	/* generate signature */
	ret = private_encrypt((unsigned char *) app_pcr, TPM_EXTEND_HASH_SIZE,
			      admin_private_key, (unsigned char *) signature);
	if (ret != RSA_SIGNATURE_SIZE) {
		printf("Error: %s: couldn't generate the signature (%d).\n",
		       __func__, ret);
		return -1;
	}

	filep = fopen((char *) "./installer/health_client_signature", "w");
	if (!filep) {
		printf("Error: %s: Couldn't open ./installer/health_client_"
		       "signature (w).\n", __func__);
		return -1;
	}

	fseek(filep, 0, SEEK_SET);
	size = (uint32_t) fwrite(signature, sizeof(uint8_t), RSA_SIGNATURE_SIZE,
				 filep);
	if (size != RSA_SIGNATURE_SIZE) {
		printf("Error: %s: couldn't write the signature.\n", __func__);
		fclose(filep);
		return -1;
	}

	fclose(filep);

	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	ret = prepare_boot_partition();	
	if (ret) {
		printf("Error: %s: couldn't prepare the boot partition.\n",
		       __func__);
		return ret;
	}

	ret = set_up_key_for_boot_partition();
	if (ret) {
		printf("Error: %s: couldn't set up key for the boot "
		       "partition.\n", __func__);
		return ret;
	}

	ret = set_up_key_for_untrusted_rootfs_partition();
	if (ret) {
		printf("Error: %s: couldn't set up key for the untrusted "
		       "rootfs partition.\n", __func__);
		return ret;
	}

	ret = mark_boot_partition_as_created();
	if (ret) {
		printf("Error: %s: couldn't mark the boot partition as "
		       "created.\n", __func__);
		return ret;
	}

	ret = mark_untrusted_rootfs_partition_as_created();
	if (ret) {
		printf("Error: %s: couldn't mark the untrusted rootfs "
		       "partition as created.\n", __func__);
		return ret;
	}

	ret = generate_signature_for_health_client_PCR();
	if (ret) {
		printf("Error: %s: couldn't generate the signature for the "
		       "health_client measurements.\n", __func__);
		return ret;
	}

	return 0;
}	
