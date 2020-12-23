#include <octopos/tpm.h>
#include <tpm/tpm.h>
#include <tpm/libtpm.h>

int quote_request(FAPI_CONTEXT *context, uint8_t *nonce, uint8_t *pcr_slots,
		  uint8_t num_pcr_slots, uint8_t **signature,
		  size_t *signature_size, char** quote_info,
		  char **pcr_event_log)
{
	uint32_t *pcr_list = NULL;
	char *certificate = NULL;
	uint8_t i;

	pcr_list = (uint32_t *) malloc(num_pcr_slots * sizeof(uint32_t));
	if (!pcr_list) {
		printf("Error: %s: couldn't allocate memory for pcr_list\n",
		       __func__);
		return -1;
	}

	for (i = 0; i < num_pcr_slots; i++)
		pcr_list[i] = (uint32_t) pcr_slots[i];

	TSS2_RC rc = Fapi_Quote(context, pcr_list, (size_t) num_pcr_slots,
				"HS/SRK/AK", "TPM-Quote", nonce,
				TPM_AT_NONCE_LENGTH, quote_info, signature,
				signature_size, pcr_event_log, &certificate);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Fapi_Quote: %s\n", Tss2_RC_Decode(rc));
		return -1;
	}

	return 0;
}
