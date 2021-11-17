#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

int main(int argc, char const *argv[])
{
	TSS2_RC r;
	ESYS_CONTEXT *esys_context = NULL;
	ESYS_TR primaryHandle = ESYS_TR_NONE;
	ESYS_TR persistent_handle1 = ESYS_TR_NONE;
	TPM2B_PUBLIC *outPublic = NULL;
	TPM2B_CREATION_DATA *creationData = NULL;
	TPM2B_DIGEST *creationHash = NULL;
	TPMT_TK_CREATION *creationTicket = NULL;

//	TPM2B_AUTH authValue = {
//		.size = 0,
//		.buffer = {}
//	};

	TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
		.size = 0,
		.sensitive = {
			.userAuth = {
				.size = 0,
				.buffer = {0 },
			},
			.data = {
				.size = 0,
				.buffer = {0},
			},
		},
	};

//	inSensitivePrimary.sensitive.userAuth = authValue;

	TPM2B_PUBLIC inPublic = {
		.size = 0,
		.publicArea = {
			.type = TPM2_ALG_RSA,
			.nameAlg = TPM2_ALG_SHA256,
			.objectAttributes = (TPMA_OBJECT_RESTRICTED |
					     TPMA_OBJECT_DECRYPT |
					     TPMA_OBJECT_FIXEDTPM |
					     TPMA_OBJECT_FIXEDPARENT |
					     TPMA_OBJECT_SENSITIVEDATAORIGIN),
			.authPolicy = {
				.size = 0,
			},
			.parameters = {
				.rsaDetail = {
					.symmetric = {
						.algorithm = TPM2_ALG_AES,
						.keyBits = {
							.aes = 128,
						},
						.mode = {
							.aes = TPM2_ALG_CFB
						},
					},
					.scheme = {
						.scheme = TPM2_ALG_NULL
					},
					.keyBits = 2048,
					.exponent = 0,
				},
			},
			.unique = {
				.rsa = {
					.size = 0,
					.buffer = {},
				}
			},
		},
	};

	TPM2B_DATA outsideInfo = {
		.size = 0,
		.buffer = {},
	};

	TPML_PCR_SELECTION creationPCR = {
		.count = 0,
	};

	r = Esys_Initialize(&esys_context, NULL, NULL);
	if (r != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: %s\n", Tss2_RC_Decode(r));
		return 1;
	}

//	r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
//	if (r != TSS2_RC_SUCCESS) {
//		fprintf(stderr, "TR_SetAuth: %s\n", Tss2_RC_Decode(r));
//		return 1;
//	}

	r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
			       ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
			       &outsideInfo, &creationPCR, &primaryHandle,
			       &outPublic, &creationData, &creationHash,
			       &creationTicket);
	if (r != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_CreatePrimary: %s\n", Tss2_RC_Decode(r));
		return 1;
	}

//	r = Esys_TR_SetAuth(esys_context, primaryHandle, &authValue);
//	if (r != TSS2_RC_SUCCESS) {
//		fprintf(stderr, "TR_SetAuth: %s\n", Tss2_RC_Decode(r));
//		return 1;
//	}

	r = Esys_EvictControl(esys_context, ESYS_TR_RH_OWNER, primaryHandle,
			      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			      TPM2_PERSISTENT_FIRST + 1,
			      &persistent_handle1);
	if (r != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_EvictControl: %s\n", Tss2_RC_Decode(r));
		return 1;
	}

	Esys_Finalize(&esys_context);

	return 0;
}