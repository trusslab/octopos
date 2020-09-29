#include <tpm/tpm.h>
#include <tpm/libtpm.h>
#include <octopos/mailbox.h>
#include <arch/mailbox_tpm.h>


void pcr_print(uint8_t slot, TPML_DIGEST *pcrValues)
{
	for (uint32_t i = 0; i < pcrValues->count; i++) {
		for (size_t j = 0; j < pcrValues->digests[i].size; j++) {
			fprintf(stdout, "%02x", pcrValues->digests[i].buffer[j]);
		}
		fprintf(stdout, "\n");
	}
}

void pcr_read_single(int slot)
{
	ESYS_CONTEXT *context = NULL;
	TSS2_RC rc = Esys_Initialize(&context, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: %s\n", Tss2_RC_Decode(rc));
		exit(1);
	}

	uint32_t pcrUpdateCounter;
	TPML_PCR_SELECTION *pcrSelectionOut = NULL;
	TPML_DIGEST *pcrValues = NULL;
	
    TPML_PCR_SELECTION pcrSelectionIn = {
        .count = 1,
        .pcrSelections = {
            { .hash = TPM2_ALG_SHA256,
              .sizeofSelect = 3,
              .pcrSelect = { }
            }
        }
    };

	uint8_t selection[4] = { 
		0 | (1 << slot) % 256,
		0 | (1 << (slot - 8)) % 256,
		0 | (1 << (slot - 16)) % 256,
		0 | (1 << (slot - 24)) % 256
	};
	memcpy(pcrSelectionIn.pcrSelections[0].pcrSelect, selection, 4);

	rc = Esys_PCR_Read(context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
			&pcrSelectionIn, &pcrUpdateCounter, &pcrSelectionOut, &pcrValues);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_PCR_Read: %s\n", Tss2_RC_Decode(rc));
		exit(1);
	}

	pcr_print(slot, pcrValues);

	Esys_Free(pcrSelectionOut);
	Esys_Free(pcrValues);

	Esys_Finalize(&context);
}

void tpm_directly_extend(int slot, char *path)
{
	ESYS_CONTEXT *context = NULL;
	TSS2_RC rc = Esys_Initialize(&context, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: %s\n", Tss2_RC_Decode(rc));
		exit(TPM_INIT_ERR);
	}

	TPML_DIGEST_VALUES digests = {
        .count = 1,
        .digests = {
            {
				.hashAlg = TPM2_ALG_SHA256,
				.digest = {
					.sha256 = { }
                }
            },
        }
	};

	int ret = prepare_extend(path, &digests);
	if (ret)
		return;

	rc = Esys_PCR_Extend(context, TPM_PCR_BANK(slot), ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &digests);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_PCR_Extend: %s\n", Tss2_RC_Decode(rc));
		exit(TPM_EXTD_ERR);
	}
}

void tpm_measurement_core()
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE_LARGE];

	while (1) {
		read_ext_request_from_queue(buf);
		//tpm_directly_extend(TPM_USR_MEASUREMENT, (char *)buf);
		fprintf(stdout, "SLOT %d CHANGED TO: ", TPM_USR_MEASUREMENT);
		//pcr_read_single(TPM_USR_MEASUREMENT);
	}
}

int main(int argc, char const *argv[])
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: TPM init\n", __func__);

	int ret = init_tpm();
	if (ret)
		return ret;
	
	tpm_measurement_core();

	close_tpm();
	
	return 0;
}
