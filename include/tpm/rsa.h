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