#include <tpm/tpm.h>
#include <tpm/libtpm.h>
#include <tpm/hash.h>

void tpm_directly_extend(int slot, uint8_t *hash_buf)
{
	char hash_str[(2 * TPM_EXTEND_HASH_SIZE) + 1];
	ESYS_CONTEXT *context = NULL;
	TSS2_RC rc = Esys_Initialize(&context, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: %s\n", Tss2_RC_Decode(rc));
		exit(TPM_INIT_ERR);
	}

	// Esys_GetTcti(context, &tcti_context);
	// rc = Tss2_Tcti_SetLocality(tcti_context, 0);
	
	// if (rc == TSS2_TCTI_RC_BAD_REFERENCE) {
	// 	printf("TSS2_TCTI_RC_BAD_REFERENCE\n");
	// 	return;
	// }

	TPML_DIGEST_VALUES digests = {
        .count = 1,
        .digests = {
		{.hashAlg = TPM2_ALG_SHA256,
		 .digest = {
			.sha256 = { }
		 }
		},
        }
	};

	convert_hash_to_str(hash_buf, hash_str);
	/* FIXME: why do we need this? */
	hash_str[2 * TPM_EXTEND_HASH_SIZE] = 0;

	int ret = prepare_extend(hash_str, &digests);
	if (ret) {
		fprintf(stderr, "Extend preparation failed.\n");
		return;
	}

	rc = Esys_PCR_Extend(context, TPM_PCR_BANK(slot), ESYS_TR_PASSWORD, 
			ESYS_TR_NONE, ESYS_TR_NONE, &digests);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_PCR_Extend: %s\n", Tss2_RC_Decode(rc));
		exit(TPM_EXTD_ERR);
	}

	Esys_Finalize(&context);
}
