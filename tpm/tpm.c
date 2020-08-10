#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

void read_PCR(int slot, TPM2_ALG_ID tpmAlg);
void print_PCR(TPML_DIGEST *pcrValues);
void extend_PCR(int slot, char *data, TPM2_ALG_ID tpmAlg);


void read_PCR(int slot, TPM2_ALG_ID tpmAlg)
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
            { .hash = tpmAlg,
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

	print_PCR(pcrValues);

    Esys_Free(pcrSelectionOut);
	Esys_Free(pcrValues);

	Esys_Finalize(&context);
}

void print_PCR(TPML_DIGEST *pcrValues)
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

void extend_PCR(int slot, char *data, TPM2_ALG_ID tpmAlg)
{
	ESYS_CONTEXT *context = NULL;
	TSS2_RC rc = Esys_Initialize(&context, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS)
	{
		fprintf(stderr, "Esys_Initialize: %s\n", Tss2_RC_Decode(rc));
		exit(1);
	}

	ESYS_TR pcrHandle_handle = ESYS_TR_PCR0 + slot;

	TPML_DIGEST_VALUES digests = {
        .count = 1,
        .digests = {
            {
				.hashAlg = tpmAlg,
				.digest = {
					.sha1 = { }
                }
            },
        }
	};
	memcpy((digests.digests->digest.sha1), data, strlen(data));
	
	rc = Esys_PCR_Extend(context, pcrHandle_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &digests);
	if (rc != TSS2_RC_SUCCESS)
	{
		fprintf(stderr, "Esys_PCR_Extend: %s\n", Tss2_RC_Decode(rc));
		exit(1);
	}
}

/**
* PCR No.    Allocation
* ------------------------------------------------------
* 0          BIOS
* 1          BIOS configuration
* 2          Option ROMs
* 3          Option ROM configuration
* 4          MBR (master boot record)
* 5          MBR configuration
* 6          State transitions and wake events
* 7          Platform manufacturer specific measurements
* 8–15       Static operating system
* 16         Debug
* 17-20      Locality 4-1
* 21-22      Dynamic OS controlled
* 23         Application specific
*/
int main(int argc, char *argv[])
{
	TPM2_ALG_ID algs[] = { TPM2_ALG_SHA1, TPM2_ALG_HMAC, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA512 };
	
	read_PCR(16, algs[0]);
	extend_PCR(16, "HelloWorld", algs[0]);
	read_PCR(16, algs[0]);

	return 0;
}