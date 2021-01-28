#include <tpm/tpm.h>
#include <tpm/hash.h>

void print_digest(uint8_t pcr_index, uint8_t *digest, size_t digest_size)
{
    printf("PCR %d: ", pcr_index);
	for (size_t index = 0; index < digest_size; index++)
		printf("%x", *(digest + index));
	printf("\n");
}

int hash_to_byte_structure(const char *input_string, UINT16 *byte_length, BYTE *byte_buffer)
{
	if (input_string == NULL || byte_length == NULL || byte_buffer == NULL) {
		return -1;
	}
	
	int str_length = strlen(input_string);
	if (str_length % 2 || *byte_length < str_length / 2) {
		return -1;
	}

	int i = 0;
	for (i = 0; i < str_length; i++) {
		if (!isxdigit(input_string[i])) {
			return -1;
		}
	}

	*byte_length = str_length / 2;
	for (i = 0; i < *byte_length; i++) {
		char tmp_str[4] = { 0 };
		tmp_str[0] = input_string[i * 2];
		tmp_str[1] = input_string[i * 2 + 1];
		byte_buffer[i] = strtol(tmp_str, NULL, 16);
	}

	return 0;
}

int prepare_extend(char *hash_buf, TPML_DIGEST_VALUES *digest_value)
{
	BYTE *digest_data = (BYTE *) &digest_value->digests->digest;
	UINT16 hash_size = TPM2_SHA256_DIGEST_SIZE;
	int rc = hash_to_byte_structure(hash_buf, &hash_size, digest_data);
	if (rc) {
		fprintf(stderr, "Error converting hex string as data, got: \"%s\"",
			hash_buf);
		return -1;
	}

	return 0;
}

int tpm_initialize(FAPI_CONTEXT **context, uint8_t processor)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
    
    /* Hide all error and warning logs produced by TSS lib.
	 * All errors and warnings should be handled manually.
	 * Change TSS_LOG_LVL_NONE to TSS_LOG_LVL_DEBUG enables debug logs
	 * including info and debug.
	 */
	setenv("TSS2_LOG", TSS_LOG_LVL_NONE, 1);

    rc = Fapi_Initialize(context, NULL);
	return_if_error(rc, "Fapi Initialization Error.");

	rc = Fapi_Provision(*context, NULL, NULL, NULL);
	return_if_error_exception(rc, "Fapi Provision Error.", 
							  TSS2_FAPI_RC_ALREADY_PROVISIONED);

	/* Create AK */
	rc = Fapi_CreateKey(*context, "HS/SRK/AK", "sign,noDa", "", NULL);
	return_if_error_exception(rc, "Fapi Create Initial Key Error.", 
							  TSS2_FAPI_RC_PATH_ALREADY_EXISTS);

	rc = Fapi_GetTcti(*context, &tcti_ctx);
	return_if_error(rc, "Get TCTI Error.");

    rc = Tss2_Tcti_SetLocality(tcti_ctx, PROC_LOCALITY(processor));
	return_if_error(rc, "Change Locality Error.");

	return 0;
}

int tpm_finalize(FAPI_CONTEXT **context)
{
	Fapi_Finalize(context);
	return 0;
}

int tpm_read(FAPI_CONTEXT *context, uint8_t pcr_index, uint8_t *buf, 
			 char **log, BOOL print)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	uint8_t *digest = NULL;
	size_t digest_size = 0;

	rc = Fapi_PcrRead(context, pcr_index, &digest, &digest_size, log);
	return_if_error(rc, "PCR Read Error.");

	if (digest_size != TPM_EXTEND_HASH_SIZE) {
		fprintf(stderr, "Unexpected vals (size = %ld)\n", digest_size);
		return -1;
	}

	if (print)
		print_digest(pcr_index, digest, digest_size);

	if (buf != NULL)
		memcpy(buf, digest, digest_size);

	return 0;
}

/* FAPI_PcrExtend uses TPM_EVENT extending all hashes slots.
 * So here just uses ESYS_CONTEXT.
*/
int tpm_extend(FAPI_CONTEXT *context, int pcr_index, uint8_t *hash_buf)
{
	TSS2_RC rc;
	ESYS_CONTEXT *esys_context = NULL;
	char hash_str[(2 * TPM_EXTEND_HASH_SIZE) + 1];
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

	convert_hash_to_str(hash_buf, hash_str);
	int ret = prepare_extend(hash_str, &digests);
	if (ret) {
		fprintf(stderr, "Extend preparation failed.\n");
		return -1;
	}

	rc = Fapi_GetEsys(context, &esys_context);
	return_if_error(rc, "Get Esys Error.");

	rc = Esys_PCR_Extend(esys_context, TPM_PCR_BANK(pcr_index), 
						 ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 
						 &digests);
	return_if_error(rc, "PCR Extend Error.");

	return 0;
}

int tpm_quote(FAPI_CONTEXT *context, uint8_t *nonce,
			  uint32_t *pcr_list, size_t pcr_list_size,
			  uint8_t **signature, size_t *signature_size, 
			  char** quote_info, char **pcr_event_log)
{
	char *certificate = NULL;
	TSS2_RC rc = Fapi_Quote(context, pcr_list, pcr_list_size,
				"HS/SRK/AK", "TPM-Quote", nonce,
				TPM_AT_NONCE_LENGTH, quote_info, signature,
				signature_size, pcr_event_log, &certificate);
	return_if_error(rc, "Quote Error");
	return 0;
}

int tpm_measure_service(char* path, uint8_t processor)
{
	int rc = 0;
	FAPI_CONTEXT *context = NULL;
	uint8_t hash_value[TPM_EXTEND_HASH_SIZE] = {0};

	rc = hash_file(path, hash_value);
	return_if_error_no_msg(rc);

	rc = tpm_initialize(&context, processor);
	return_if_error_no_msg(rc);
	
	rc = tpm_extend(context, PROC_TO_PCR(processor), hash_value);
	return_if_error_no_msg(rc);
	
	rc = tpm_read(context, PROC_TO_PCR(processor), NULL, NULL, 1);
	return_if_error_no_msg(rc);
	
	rc = tpm_finalize(&context);
	return rc;
}

int tpm_processor_read_pcr(uint8_t processor, uint8_t *pcr_value)
{
	int rc = 0;
	FAPI_CONTEXT *context = NULL;

	rc = tpm_initialize(&context, processor);
	return_if_error_no_msg(rc);
	
	rc = tpm_read(context, PROC_TO_PCR(processor), pcr_value, NULL, 1);
	return_if_error_no_msg(rc);
	
	rc = tpm_finalize(&context);
	return rc;
}

int tpm_attest(uint8_t processor, uint8_t *nonce, 
			   uint32_t *pcr_list, size_t pcr_list_size,
			   uint8_t **signature, size_t *signature_size, 
			   char** quote_info)
{
	int rc = 0;
	FAPI_CONTEXT *context = NULL;
	char *pcr_event_log = NULL;

	rc = tpm_initialize(&context, processor);
	return_if_error_no_msg(rc);

	rc = tpm_quote(context, nonce, pcr_list, pcr_list_size, signature, signature_size, 
				   quote_info, &pcr_event_log);
	return_if_error_no_msg(rc);
	
	rc = tpm_finalize(&context);
	return rc;
}