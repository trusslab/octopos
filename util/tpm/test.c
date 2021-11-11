//
// Created by imcmy on 11/7/21.
//

#include <tpm/tpm.h>
#include <tpm/queue.h>
#include <tpm/hash.h>
#include <tpm/rsa.h>
#include <tpm/aes.h>


int main(int argc, char *argv[]) {

	FAPI_CONTEXT *context = NULL;
	tpm_initialize(&context);
//
////	enforce_running_process(5);
////
//////	Fapi_Delete(context, "/policy/seal_policy");
//////	Fapi_Delete(context, "/HS/SRK/sealedKey");
////
//////	tpm_reset(context, PROC_TO_PCR(5));
////
////	uint8_t pcr[32];
////	tpm_processor_read_pcr(PROC_TO_PCR(5), pcr);
////
//////	uint8_t digest[32] = {1,2,3};
//////	tpm_extend(context, PROC_TO_PCR(5), digest);
//////	tpm_processor_read_pcr(PROC_TO_PCR(5), pcr);
////
//////	tpm_seal_key(context, NULL, AES_GEN_SIZE);
////
////	uint8_t plain[362] = {1,2,3};
////	size_t plain_size = 362;
////
////	uint8_t cipher[378] = {0};
////	size_t cipher_size = 0;
////
////	uint8_t *plain2 = (uint8_t *) malloc(362);
////	size_t plain_size2 = 0;
//////
////	tpm_encrypt(plain, plain_size, cipher, &cipher_size);
////	for (size_t i=0; i<cipher_size; i++) {
////                printf("%02x ", cipher[i]);
////        }
////	printf("\n");
////	printf("%lu\n", cipher_size);
////
//////	tpm_extend(context, PROC_TO_PCR(5), digest);
//////	tpm_processor_read_pcr(PROC_TO_PCR(5), pcr);
////
////	tpm_decrypt(plain2, &plain_size2, cipher, cipher_size);
////	for (size_t i=0; i<plain_size2; i++) {
////		printf("%u ", plain2[i]);
////	}
////	printf("\n");
////	printf("%lu\n", plain_size2);
////
////	free(plain2);
////
//////	uint8_t *result = NULL;
//////	size_t result_size;
//////
//////	Fapi_Unseal(context, "/HS/SRK/sealedStorage", &result,
//////		    &result_size);
//////
	Fapi_Delete(context, "/HS/SRK/AK");
//////	Fapi_Delete(context, "/policy/seal_policy");
//////	Fapi_Delete(context, "/HS/SRK/sealedKey");
//////	Fapi_Delete(context, "/HS/SRK/sealedStorage");
//
	tpm_finalize(&context);

	tpm_boot();

	return 0;
}