#include <tpm/tpm.h>
#include <tpm/libtpm.h>


int quote_request(FAPI_CONTEXT *context, uint8_t *nonce, int slot,
	uint8_t **signature, size_t *signature_size,
	char** quote_info, char **pcr_event_log)
{
	uint32_t pcr_list[1] = { slot };
    char *certificate = NULL;

	TSS2_RC rc = Fapi_Quote(context, pcr_list, 1, "HS/SRK/AK", "TPM-Quote",
					nonce, TPM_AT_NONCE_LENGTH,
					quote_info,
					signature, signature_size,
					pcr_event_log, &certificate);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Fapi_Quote: %s\n", Tss2_RC_Decode(rc));
		return -1;
	}

	return 0;
}
