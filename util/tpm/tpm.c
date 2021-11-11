#include <tpm/tpm.h>
#include <tpm/hash.h>
#include <tpm/queue.h>
#include <tpm/aes.h>
#define ARCH_UMODE

static uint8_t running_processor = 0;

/* Driver support functions:
 * 	write_to_driver
 */
int write_to_driver(uint8_t *in_buf, uint8_t **out_buf, size_t *out_size)
{
	int rc = 0;
	struct queue_list *in_queues;
	struct queue_list *out_queues;
	open_queue(&in_queues, &out_queues);
	enqueue(in_queues, in_buf, running_processor);
	while (1) {
		rc = dequeue(out_queues, out_buf, out_size, running_processor);
		if (rc != E_EMPTY_QUEUE) {
			return rc;
		}
		sleep(2);
	}
}

/* Hash support functions:
 * 	print_digest
 * 	print_digest_buffer
 * 	hash_to_byte_structure
 * 	prepare_extend
 */
void print_digest(uint8_t pcr_index, uint8_t *digest, size_t digest_size)
{
	printf("PCR %d: ", pcr_index);
	for (size_t index = 0; index < digest_size; index++)
		printf("%02x", *(digest + index));
	printf("\n");
}

void print_digest_buffer(uint8_t *digest, size_t digest_size, char* buf, size_t buf_size)
{
	if (digest_size * 2 + 1 != buf_size)
		return;
	for (size_t index = 0; index < digest_size; index++)
		sprintf(buf + index * 2, "%02x", *(digest + index));
	buf[buf_size - 1] = '\0';
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

/* Wrapper of FAPI and ESAPI
 * 	tpm_set_locality
 * 	tpm_initialize
 * 	tpm_finalize
 * 	tpm_read
 * 	tpm_quote
 * 	tpm_seal
 * 	tpm_unseal
 * 	tpm_reset
 */
int tpm_set_locality(FAPI_CONTEXT *context, uint8_t processor)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

	rc = Fapi_GetTcti(context, &tcti_ctx);
	return_if_error(rc, "Get TCTI Error.");

	rc = Tss2_Tcti_SetLocality(tcti_ctx, PROC_LOCALITY(processor));
	return_if_error(rc, "Change Locality Error.");

	return 0;
}

int tpm_initialize(FAPI_CONTEXT **context)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;

	/* Hide all error and warning logs produced by TSS lib.
	 * All errors and warnings should be handled manually.
	 * Change TSS_LOG_LVL_NONE to TSS_LOG_LVL_DEBUG enables debug logs
	 * including info and debug.
	 */
	setenv("TSS2_LOG", TSS_LOG_LVL_ERROR, 1);

	rc = Fapi_Initialize(context, NULL);
	return_if_error(rc, "Fapi Initialization Error.");

	rc = Fapi_Provision(*context, NULL, NULL, NULL);
	return_if_error_exception(rc, "Fapi Provision Error.",
				  TSS2_FAPI_RC_ALREADY_PROVISIONED);

	return 0;
}

void tpm_finalize(FAPI_CONTEXT **context)
{
	Fapi_Finalize(context);
}

int tpm_read(FAPI_CONTEXT *context, uint32_t pcr_index, uint8_t *buf,
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

int tpm_extend(FAPI_CONTEXT *context, uint32_t pcr_index, uint8_t *hash_buf)
{
	TSS2_RC rc;
	ESYS_CONTEXT *esys_context = NULL;
	char hash_str[(2 * TPM_EXTEND_HASH_SIZE) + 1];
	TPML_DIGEST_VALUES digests = {
		.count = 1,
		.digests = {{
				    .hashAlg = TPM2_ALG_SHA256,
				    .digest = {.sha256 = { }}
			    }}
	};

	convert_hash_to_str(hash_buf, hash_str);
	int ret = prepare_extend(hash_str, &digests);
	if (ret) {
		fprintf(stderr, "Extend preparation failed.\n");
		return -1;
	}

	/* FAPI_PcrExtend uses TPM_EVENT extending all hashes slots.
	 * So here just uses ESYS_CONTEXT.
	 */
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
	TSS2_RC rc;
	char *certificate = NULL;

	/* Create attestation key (AK), if exists, ignore */
	rc = Fapi_CreateKey(context, "/HS/SRK/AK", "sign,noDa",
			    "", NULL);
	return_if_error_exception(rc, "Fapi Create Initial Key Error.",
				  TSS2_FAPI_RC_PATH_ALREADY_EXISTS);

	rc = Fapi_Quote(context, pcr_list, pcr_list_size,
			"/HS/SRK/AK", "TPM-Quote", nonce,
			TPM_AT_NONCE_LENGTH, quote_info, signature,
			signature_size, pcr_event_log, &certificate);
	return_if_error(rc, "Quote Error.");
	return 0;
}

int tpm_seal_key(FAPI_CONTEXT *context, uint8_t *data, size_t data_size)
{
	TSS2_RC rc;
	uint8_t pcr_buf[TPM_EXTEND_HASH_SIZE];
	char pcr_str[TPM_EXTEND_HASH_SIZE*2 + 1];
	const char* pcr_policy_template = "{"
					  "\"description\":\"PCR POLICY\","
					  "\"policy\":[{"
					  "	\"type\":\"POLICYPCR\","
					  "	\"pcrs\":[{"
					  "		\"pcr\":%u,"
					  "		\"hashAlg\":\"TPM2_ALG_SHA256\","
					  "		\"digest\":\"%s\""
					  "}]"
					  "}]}";
	char pcr_policy[strlen(pcr_policy_template) + TPM_EXTEND_HASH_SIZE * 2];
	printf("RUNNING_PROCESSOR: %u\n", running_processor);

	tpm_read(context, PROC_TO_PCR(running_processor), pcr_buf, NULL, 0);
	print_digest_buffer(pcr_buf, TPM_EXTEND_HASH_SIZE,
			    pcr_str, TPM_EXTEND_HASH_SIZE * 2 + 1);
	snprintf(pcr_policy,
		 strlen(pcr_policy_template) + TPM_EXTEND_HASH_SIZE * 2,
		 pcr_policy_template, PROC_TO_PCR(running_processor), pcr_str);

	rc = Fapi_Import(context, "/policy/seal_policy", pcr_policy);
	return_if_error(rc, "Build policy Error.");

	rc = Fapi_CreateSeal(context,
			     "/HS/SRK/sealedKey", "noDa,0x81000010",
			     data_size,
			     "/policy/seal_policy", "",  data);
	return_if_error(rc, "Seal Error.");

	return 0;
}

int tpm_unseal_key(FAPI_CONTEXT *context, uint8_t **data, size_t *data_size)
{
	TSS2_RC rc;

	/* Unseal the stored key, if the key is not set, then
	 * create the key randomly and seal it.
	 */
	rc = Fapi_Unseal(context, "/HS/SRK/sealedKey", data,
			 data_size);
	if (rc == TSS2_FAPI_RC_KEY_NOT_FOUND) {
		printf("TSS2_FAPI_RC_KEY_NOT_FOUND\n");
		rc = tpm_seal_key(context, NULL, AES_GEN_SIZE);
		return_if_error_no_msg(rc);

		printf("Sealed\n");

		rc = Fapi_Unseal(context, "/HS/SRK/sealedKey", data,
				 data_size);
	}
	return_if_error(rc, "Unseal Error.");

	return 0;
}

int tpm_encrypt_direct(FAPI_CONTEXT *context, uint8_t *plain, size_t plain_size,
		       uint8_t **cipher, size_t *cipher_size)
{
	TSS2_RC rc;
	uint8_t pcr_buf[TPM_EXTEND_HASH_SIZE];
	char pcr_str[TPM_EXTEND_HASH_SIZE*2 + 1];
	const char* pcr_policy_template = "{"
					  "\"description\":\"PCR POLICY\","
					  "\"policy\":[{"
					  "	\"type\":\"POLICYPCR\","
					  "	\"pcrs\":[{"
					  "		\"pcr\":%u,"
					  "		\"hashAlg\":\"TPM2_ALG_SHA256\","
					  "		\"digest\":\"%s\""
					  "}]"
					  "}]}";
	char pcr_policy[strlen(pcr_policy_template) + TPM_EXTEND_HASH_SIZE * 2];

	tpm_read(context, PROC_TO_PCR(running_processor), pcr_buf, NULL, 0);
	print_digest_buffer(pcr_buf, TPM_EXTEND_HASH_SIZE,
			    pcr_str, TPM_EXTEND_HASH_SIZE * 2 + 1);
	snprintf(pcr_policy,
		 strlen(pcr_policy_template) + TPM_EXTEND_HASH_SIZE * 2,
		 pcr_policy_template, PROC_TO_PCR(running_processor), pcr_str);

	rc = Fapi_Import(context, "/policy/seal_policy", pcr_policy);
	return_if_error(rc, "Build policy Error.");

	rc = Fapi_CreateKey(context, "/HS/SRK/sealedKey", "decrypt,0x81000004",
			    "/policy/seal_policy", NULL);
	return_if_error_exception(rc, "Sealed Key Creation Error.",
				  TSS2_FAPI_RC_PATH_ALREADY_EXISTS);

	rc = Fapi_Encrypt(context, "/HS/SRK/sealedKey", plain, plain_size,
			  cipher, cipher_size);
	return_if_error(rc, "Encryption Error.");

	return 0;
}

int tpm_decrypt_direct(FAPI_CONTEXT *context, uint8_t **plain, size_t *plain_size,
		       uint8_t *cipher, size_t cipher_size)
{
	TSS2_RC rc;

	rc = Fapi_Decrypt(context, "/HS/SRK/sealedKey", cipher, cipher_size,
			  plain, plain_size);
	return_if_error(rc, "Decryption Error.");

	return 0;
}

int tpm_reset(FAPI_CONTEXT *context, uint32_t pcr_selected)
{
	TSS2_RC rc;
	ESYS_CONTEXT *esys_context = NULL;

	rc = Fapi_GetEsys(context, &esys_context);
	return_if_error(rc, "Get Esys Error.");

	rc = Esys_PCR_Reset(esys_context, pcr_selected,
			    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
	return_if_error(rc, "PCR Reset Error.");

	return 0;
}

/* Top-level TPM API exposed for calling
 * 	enforce_running_process
 * 	cancel_running_process
 * 	tpm_measure_service
 * 	tpm_processor_read_pcr
 * 	tpm_attest
 * 	tpm_encrypt
 * 	tpm_decrypt
 * 	tpm_reset_pcrs
 */
int enforce_running_process(uint8_t processor)
{
	if (processor == 0 || processor >= INVALID_PROCESSOR) {
		fprintf(stderr, "Invalid processor.\n");
		return -1;
	}
	running_processor = processor;
	return 0;
}

int cancel_running_process()
{
	running_processor = 0;
	return 0;
}

int tpm_measure_service(char* path)
{
	int rc = 0;
	uint8_t hash_value[TPM_EXTEND_HASH_SIZE] = {0};

	rc = hash_file(path, hash_value);
	return_if_error_no_msg(rc);

#ifdef ARCH_UMODE
	FAPI_CONTEXT *context = NULL;

	rc = tpm_initialize(&context);
	return_if_error_no_msg(rc);

	rc = tpm_set_locality(context, running_processor);
	return_if_error_label(rc, out_measure_service);

	rc = tpm_extend(context, PROC_TO_PCR(running_processor), hash_value);
	return_if_error_label(rc, out_measure_service);

	rc = tpm_read(context, PROC_TO_PCR(running_processor), NULL, NULL, 1);
	return_if_error_label(rc, out_measure_service);

out_measure_service:
	tpm_finalize(&context);
	return rc;
#else
	uint8_t in_buf[BUFFER_SIZE] = { 0 };
	uint8_t *out_buf;
	size_t size;
	in_buf[0] = OP_MEASURE;
	memcpy(in_buf + 1, hash_value, TPM_EXTEND_HASH_SIZE);
	rc = write_to_driver(in_buf, &out_buf, &size);
	free(out_buf);
	return rc;
#endif
}

int tpm_processor_read_pcr(uint32_t pcr_index, uint8_t *pcr_value)
{
	int rc = 0;

#ifdef ARCH_UMODE
	FAPI_CONTEXT *context = NULL;

	rc = tpm_initialize(&context);
	return_if_error_no_msg(rc);

	rc = tpm_set_locality(context, running_processor);
	return_if_error_label(rc, out_processor_read_pcr);

	rc = tpm_read(context, pcr_index, pcr_value, NULL, 1);
	return_if_error_label(rc, out_processor_read_pcr);

out_processor_read_pcr:
	tpm_finalize(&context);
	return rc;
#else
	uint8_t in_buf[BUFFER_SIZE] = { 0 };
	uint8_t *out_buf;
	size_t size;
	in_buf[0] = OP_READ;
	in_buf[1] = (uint8_t) (pcr_index & 0xFF);
	rc = write_to_driver(in_buf, &out_buf, &size);
	memcpy(pcr_value, out_buf, TPM_EXTEND_HASH_SIZE);
	free(out_buf);
	return rc;
#endif
}

int tpm_attest(uint8_t *nonce, uint32_t *pcr_list,
	       size_t pcr_list_size, uint8_t **signature,
	       size_t *signature_size, char** quote_info)
{
	int rc = 0;

#ifdef ARCH_UMODE
	FAPI_CONTEXT *context = NULL;
	char *pcr_event_log = NULL;

	rc = tpm_initialize(&context);
	return_if_error_no_msg(rc);

	rc = tpm_set_locality(context, running_processor);
	return_if_error_label(rc, out_attest);

	rc = tpm_quote(context, nonce, pcr_list, pcr_list_size, signature,
		       signature_size, quote_info, &pcr_event_log);
	return_if_error_label(rc, out_attest);

out_attest:
	tpm_finalize(&context);
	return rc;
#else
	uint8_t in_buf[BUFFER_SIZE] = { 0 };
	uint8_t *out_buf;
	size_t size;
	in_buf[0] = OP_ATTEST;
	memcpy(in_buf + 1, nonce, TPM_AT_NONCE_LENGTH);
	in_buf[1 + TPM_AT_NONCE_LENGTH] = (uint8_t) (pcr_list_size & 0XFF);
	for (size_t i = 0; i < pcr_list_size; i++) {
		in_buf[2 + TPM_AT_NONCE_LENGTH + i] = (uint8_t) (pcr_list[i] & 0xFF);
	}
	rc = write_to_driver(in_buf, &out_buf, &size);
	*signature_size = (out_buf[2] << 8) + out_buf[3];
	*signature = (uint8_t *) malloc(*signature_size * sizeof(uint8_t));
	memcpy(*signature, out_buf + 4, *signature_size);

	size_t quote_info_size = (out_buf[4 + *signature_size] << 8) + out_buf[5 + *signature_size];
	*quote_info = (char *) malloc(quote_info_size * sizeof(char));
	memcpy(quote_info, out_buf + 6 + *signature_size, quote_info_size);

	free(out_buf);
	return rc;
#endif
}

int tpm_encrypt(uint8_t *plain, size_t plain_size,
		uint8_t *cipher, size_t *cipher_size)
{
	int rc = 0;

#ifdef ARCH_UMODE
	FAPI_CONTEXT *context = NULL;
	uint8_t *key_iv = NULL;
	size_t key_iv_size;

	rc = tpm_initialize(&context);
	return_if_error_no_msg(rc);

	rc = tpm_set_locality(context, running_processor);
	return_if_error_label(rc, out_encrypt);

	rc = tpm_unseal_key(context, &key_iv, &key_iv_size);
	return_if_error_label(rc, out_encrypt);
	if (key_iv_size != AES_GEN_SIZE) {
		return -1;
	}

	rc = aes_encrypt(key_iv, plain, plain_size, cipher, cipher_size);
	return_if_error_label(rc, out_encrypt);

out_encrypt:
	tpm_finalize(&context);
	return rc;
#else
	uint8_t in_buf[BUFFER_SIZE] = { 0 };
	uint8_t *out_buf;
	size_t size;
	in_buf[0] = OP_SEAL;
	rc = write_to_driver(in_buf, &out_buf, &size);
	return rc;
#endif
}

int tpm_decrypt(uint8_t *plain, size_t *plain_size,
		uint8_t *cipher, size_t cipher_size)
{
	int rc = 0;

#ifdef ARCH_UMODE
	FAPI_CONTEXT *context = NULL;
	uint8_t *key_iv = NULL;
	size_t key_iv_size;

	rc = tpm_initialize(&context);
	return_if_error_no_msg(rc);

	rc = tpm_set_locality(context, running_processor);
	return_if_error_label(rc, out_decrypt);

	rc = tpm_unseal_key(context, &key_iv, &key_iv_size);
	return_if_error_label(rc, out_decrypt);
	if (key_iv_size != AES_GEN_SIZE) {
		return -1;
	}

	rc = aes_decrypt(key_iv, plain, plain_size, cipher, cipher_size);
	return_if_error_label(rc, out_decrypt);

out_decrypt:
	tpm_finalize(&context);
	return rc;
#else
	return rc;
#endif
}

int tpm_reset_pcrs(uint32_t *pcr_list, size_t pcr_list_size)
{
	int rc = 0;

#ifdef ARCH_UMODE
	size_t pcr_index = 0;
	FAPI_CONTEXT *context = NULL;

	rc = tpm_initialize(&context);
	return_if_error_no_msg(rc);

	rc = tpm_set_locality(context, running_processor);
	return_if_error_label(rc, out_reset_pcrs);

	for (; pcr_index < pcr_list_size; pcr_index++) {
		rc = tpm_reset(context, *(pcr_list + pcr_index));
		return_if_error_label(rc, out_reset_pcrs);
	}

out_reset_pcrs:
	tpm_finalize(&context);
	return rc;
#else
	uint8_t in_buf[BUFFER_SIZE] = { 0 };
	uint8_t *out_buf;
	size_t size;
	in_buf[0] = OP_RESET;
	in_buf[1] = (uint8_t) (pcr_list_size & 0XFF);
	for (size_t i = 0; i < pcr_list_size; i++) {
		in_buf[2 + i] = (uint8_t)(pcr_list[i] & 0xFF);
	}
	rc = write_to_driver(in_buf, &out_buf, &size);
	return rc;
#endif
}
