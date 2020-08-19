#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tpm/tpm.h>


void pcr_read_single(uint8_t slot)
{
	ESYS_CONTEXT *context = NULL;
	TSS2_RC rc = Esys_Initialize(&context, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS)
	{
		fprintf(stderr, "Esys_Initialize: %s\n", Tss2_RC_Decode(rc));
		exit(1);
	}

	UINT32 pcrUpdateCounter;
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

	UINT8 selection[4] = { 
		0 | (1 << slot) % 256,
		0 | (1 << (slot - 8)) % 256,
		0 | (1 << (slot - 16)) % 256,
		0 | (1 << (slot - 24)) % 256
	};
	memcpy(pcrSelectionIn.pcrSelections[0].pcrSelect, selection, 4);

	rc = Esys_PCR_Read(context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, 
			&pcrSelectionIn, &pcrUpdateCounter, &pcrSelectionOut, &pcrValues);
	if (rc != TSS2_RC_SUCCESS)
	{
		fprintf(stderr, "Esys_PCR_Read: %s\n", Tss2_RC_Decode(rc));
		exit(1);
	}

	pcr_print(slot, pcrValues);

	Esys_Free(pcrSelectionOut);
	Esys_Free(pcrValues);

	Esys_Finalize(&context);
}

void pcr_print(uint8_t slot, TPML_DIGEST *pcrValues)
{
	for(uint32_t i = 0; i < pcrValues->count; i++)
	{
		for (size_t j = 0; j < pcrValues->digests[i].size; j++)
		{
			fprintf(stdout, "%02x", pcrValues->digests[i].buffer[j]);
		}
		fprintf(stdout, "\n");
    }
}

void pcr_extend_data(uint8_t slot, char *data)
{
	ESYS_CONTEXT *context = NULL;
	TSS2_RC rc = Esys_Initialize(&context, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS)
	{
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
	memcpy((digests.digests->digest.sha256), data, strlen(data));

	rc = Esys_PCR_Extend(context, TPM_PCR_BANK(slot), ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &digests);
	if (rc != TSS2_RC_SUCCESS)
	{
		fprintf(stderr, "Esys_PCR_Extend: %s\n", Tss2_RC_Decode(rc));
		exit(TPM_EXTD_ERR);
	}
}

void pcr_extend_file(uint8_t slot, char *path)
{
	FILE *bin = fopen(path, "rb");
	if (bin)
	{
		fseek(bin, 0L, SEEK_END);
		long bin_size = ftell(bin);
		fseek(bin, 0L, SEEK_SET);
		char *buffer = (char *)malloc(bin_size * sizeof(char));
		fread(buffer, 1, bin_size, bin);
		fclose(bin);

		pcr_extend_data(slot, buffer);

		free(buffer);
	}
}