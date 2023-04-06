/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#include <tpm/tpm.h>
#include <tpm/hash.h>
#include <tpm/aes.h>
#include <fcntl.h>           /* For O_* constants */
#include <sys/stat.h>
#include <semaphore.h>

#define ARCH_UMODE
#ifdef TPM_REMOTE
#undef ARCH_UMODE
#endif

#ifndef ARCH_UMODE
#include <tpm/queue.h>
#endif

static uint8_t running_processor = 0;
static sem_t *sem;

#ifndef ARCH_UMODE
struct queue_list *in_queues = NULL;
struct queue_list *out_queues = NULL;
#endif

/* Support functions:
 * 	write_to_driver
 * 	print_digest
 * 	print_digest_buffer
 * 	hash_to_byte_structure
 * 	prepare_extend
 */
#ifndef ARCH_UMODE
int write_to_driver(uint8_t *in_buf, size_t in_size,
		    uint8_t **out_buf, size_t *out_size)
{
	int rc = 0;
	if (in_queues == NULL)
		open_queue(&in_queues, &out_queues);


	/* Attach the size of the message.
	 * Occupy buf[1] and buf[2]
	 */
	in_buf[1] = (in_size >> 8) & 0xFF;
	in_buf[2] = in_size & 0xFF;

	enqueue(in_queues, running_processor, in_buf, in_size);
	while (1) {
		rc = dequeue(out_queues, running_processor, out_buf, out_size);
		if (rc != E_EMPTY_QUEUE)
			break;
		sleep(5);
	}

	rc = *out_buf[0];
	if (rc != RET_SUCCESS) {
		rc = (*out_buf[3] << 24)
			| (*out_buf[4] << 16)
			| (*out_buf[5] << 8)
			| *out_buf[6];
	}

	return rc;
}
#endif

void print_digest(uint8_t pcr_index, const uint8_t *digest, size_t digest_size)
{
	printf("PCR %d: ", pcr_index);
	for (size_t index = 0; index < digest_size; index++)
		printf("%02x", *(digest + index));
	printf("\n");
}

void print_digest_buffer(const uint8_t *digest, size_t digest_size,
			 char* buf, size_t buf_size)
{
	if (digest_size * 2 + 1 != buf_size)
		return;
	for (size_t index = 0; index < digest_size; index++)
		sprintf(buf + index * 2, "%02x", *(digest + index));
	buf[buf_size - 1] = '\0';
}

int hash_to_byte_structure(const char *input_string, UINT16 *byte_length,
			   BYTE *byte_buffer)
{
	if (input_string == NULL || byte_length == NULL || byte_buffer == NULL) {
		return -1;
	}

	size_t str_length = strlen(input_string);
	if (str_length % 2 || *byte_length < str_length / 2) {
		return -1;
	}

	size_t i = 0;
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

int check_processor(uint8_t processor)
{
	if (processor == 0 || processor >= INVALID_PROCESSOR) {
		fprintf(stderr, "Invalid processor.\n");
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
 * 	tpm_seal_key
 * 	tpm_unseal_key
 * 	tpm_reset
 */
int tpm_set_locality(FAPI_CONTEXT *context, uint8_t processor)
{
	TSS2_RC rc = TSS2_RC_SUCCESS;
	TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

	rc = check_processor(processor);
	return_if_error_no_msg(rc);

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
	setenv("TSS2_LOG", TSS_LOG_LVL_NONE, 1);

	sem = sem_open("/tpm_sem", O_CREAT, 0644, 1);
	if (sem == SEM_FAILED) {
		fprintf(stderr, "Error: couldn't open tpm semaphore.\n");
		return -1;
	}

	sem_wait(sem);

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

	sem_post(sem);
	sem_close(sem);
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
	rc = Fapi_CreateKey(context, "HS/SRK/AK", "sign,noDa",
			    NULL, NULL);
	return_if_error_exception(rc, "Fapi Create Attestation Key Error.",
				  TSS2_FAPI_RC_PATH_ALREADY_EXISTS);

	rc = Fapi_Quote(context, pcr_list, pcr_list_size,
			"HS/SRK/AK", "TPM-Quote", nonce,
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
	const char *policy_name_template = "/policy/sealedPolicy%d";
	const char *key_name_template = "/HS/SRK/sealedKey%d";
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
	char policy_name[strlen(policy_name_template) + 1];
	char key_name[strlen(key_name_template) + 1];
	char pcr_policy[strlen(pcr_policy_template) + TPM_EXTEND_HASH_SIZE * 2 + 1];
	unsigned int nv_handle_base = 0x81020000;
	const char *nv_type_template = "noDa,0x%x";
	char nv_type[strlen(nv_type_template) + 7];

	snprintf(policy_name, strlen(policy_name_template) + 1,
		 policy_name_template, PROC_TO_PCR(running_processor));
	snprintf(key_name, strlen(key_name_template) + 1,
		 key_name_template, PROC_TO_PCR(running_processor));
	snprintf(nv_type, strlen(nv_type_template) + 7,
		 nv_type_template, nv_handle_base + running_processor);

	tpm_read(context, PROC_TO_PCR(running_processor), pcr_buf, NULL, 0);
	print_digest_buffer(pcr_buf, TPM_EXTEND_HASH_SIZE,
			    pcr_str, TPM_EXTEND_HASH_SIZE * 2 + 1);
	snprintf(pcr_policy,
		 strlen(pcr_policy_template) + TPM_EXTEND_HASH_SIZE * 2 + 1,
		 pcr_policy_template, PROC_TO_PCR(running_processor), pcr_str);

	rc = Fapi_Import(context, policy_name, pcr_policy);
	return_if_error(rc, "Build policy Error.");

	rc = Fapi_CreateSeal(context, key_name, nv_type, data_size, policy_name,
			     "",  data);
	return_if_error(rc, "Seal Error.");

	return 0;
}

int tpm_unseal_key(FAPI_CONTEXT *context, uint8_t **data, size_t *data_size)
{
	TSS2_RC rc;
	const char *key_name_template = "/HS/SRK/sealedKey%d";
	char key_name[strlen(key_name_template) + 1];

	snprintf(key_name, strlen(key_name_template) + 1,
		 key_name_template, PROC_TO_PCR(running_processor));
	/* Unseal the stored key, if the key is not set, then
	 * create the key randomly and seal it.
	 */
	rc = Fapi_Unseal(context, key_name, data, data_size);
	if (rc == TSS2_FAPI_RC_KEY_NOT_FOUND) {
		rc = tpm_seal_key(context, NULL, AES_GEN_SIZE);
		return_if_error_no_msg(rc);

		rc = Fapi_Unseal(context, key_name, data, data_size);
	}
	return_if_error(rc, "Unseal Error.");

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
 * 	tpm_get_storage_key
 * 	tpm_reset_pcrs
 */
int enforce_running_process(uint8_t processor)
{
	if (check_processor(processor) == 0)
		running_processor = processor;
	return 0;
}

int cancel_running_process()
{
	running_processor = 0;
	return 0;
}

int tpm_measure_service(char* path, BOOL is_path)
{
	int rc = 0;
	uint8_t hash_value[TPM_EXTEND_HASH_SIZE] = {0};

	if (is_path) {
		rc = hash_file(path, hash_value);
		return_if_error_no_msg(rc);
	} else {
		memcpy(hash_value, path, TPM_EXTEND_HASH_SIZE);
	}

#ifdef ARCH_UMODE
	FAPI_CONTEXT *context = NULL;

	rc = tpm_initialize(&context);
	return_if_error_no_msg(rc);

	rc = tpm_set_locality(context, running_processor);
	return_if_error_label(rc, out_measure_service);

	rc = tpm_extend(context, PROC_TO_PCR(running_processor), hash_value);
	return_if_error_label(rc, out_measure_service);

out_measure_service:
	tpm_finalize(&context);
	return rc;
#else
	uint8_t request[TPM_EXTEND_HASH_SIZE + 3] = { 0 };
	uint8_t *response;
	size_t response_size;

	request[0] = OP_MEASURE;
	memcpy(request + 3, hash_value, TPM_EXTEND_HASH_SIZE);
	rc = write_to_driver(request, TPM_EXTEND_HASH_SIZE + 3,
			     &response, &response_size);

	free(response);
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

	rc = tpm_read(context, pcr_index, pcr_value, NULL, 0);
	return_if_error_label(rc, out_processor_read_pcr);

out_processor_read_pcr:
	tpm_finalize(&context);
	return rc;
#else
	uint8_t request[4] = { 0 };
	uint8_t *response;
	size_t response_size;

	request[0] = OP_READ;
	request[3] = (uint8_t) (pcr_index & 0xFF);
	rc = write_to_driver(request, 4, &response, &response_size);
	return_if_error_label(rc, out_processor_read_pcr);

	memcpy(pcr_value, response + 3, TPM_EXTEND_HASH_SIZE);

out_processor_read_pcr:
	free(response);
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
	uint8_t *request;
	uint8_t *response;
	size_t response_size;
	size_t quote_info_size;

	request = (uint8_t *) malloc(4 + TPM_AT_NONCE_LENGTH + pcr_list_size);
	memset(request, 0, 4 + TPM_AT_NONCE_LENGTH + pcr_list_size);
	request[0] = OP_ATTEST;
	memcpy(request + 3, nonce, TPM_AT_NONCE_LENGTH);
	request[3 + TPM_AT_NONCE_LENGTH] = pcr_list_size & 0xFF;
	for (size_t i = 0; i < pcr_list_size; i++) {
		request[4 + TPM_AT_NONCE_LENGTH + i] = pcr_list[i] & 0xFF;
	}
	rc = write_to_driver(request, 4 + TPM_AT_NONCE_LENGTH + pcr_list_size,
			     &response, &response_size);
	return_if_error_label(rc, out_attest);

	*signature_size = (response[3] << 8) + response[4];
	*signature = (uint8_t *) malloc(*signature_size);
	memcpy(*signature, response + 5, *signature_size);

	quote_info_size = (response[5 + *signature_size] << 8) + response[6 + *signature_size];
	*quote_info = (char *) malloc(quote_info_size);
	memcpy(quote_info, response + 7 + *signature_size, quote_info_size);

out_attest:
	free(request);
	free(response);
	return rc;
#endif
}

int tpm_get_storage_key(uint8_t **key_iv)
{
	int rc = 0;

#ifdef ARCH_UMODE
	FAPI_CONTEXT *context = NULL;
	size_t key_iv_size;

	rc = tpm_initialize(&context);
	return_if_error_no_msg(rc);

	rc = tpm_set_locality(context, running_processor);
	return_if_error_label(rc, out_get_storage_key);

	rc = tpm_unseal_key(context, key_iv, &key_iv_size);
	return_if_error_label(rc, out_get_storage_key);
	if (key_iv_size != AES_GEN_SIZE)
		rc = -1;

out_get_storage_key:
	tpm_finalize(&context);
	return rc;
#else
	uint8_t request[3] = { 0 };;
	uint8_t *response;
	size_t response_size;
	size_t key_iv_size;

	request[0] = OP_SEAL;
	rc = write_to_driver(request,3, &response, &response_size);
	return_if_error_label(rc, out_get_storage_key);

	key_iv_size = response[3];
	if (key_iv_size != AES_GEN_SIZE) {
		rc = -1;
		goto out_get_storage_key;
	}
	memcpy(key_iv, response + 4, key_iv_size);

out_get_storage_key:
	free(response);
	return rc;
#endif
}

int tpm_reset_pcrs(const uint32_t *pcr_list, size_t pcr_list_size)
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
	uint8_t *request;
	uint8_t *response;
	size_t response_size;

	request = (uint8_t *) malloc(3 + pcr_list_size);
	memset(request, 0, 3 + pcr_list_size);
	request[0] = OP_RESET;
	request[3] = (uint8_t) (pcr_list_size & 0XFF);
	for (size_t i = 0; i < pcr_list_size; i++) {
		request[4 + i] = pcr_list[i] & 0xFF;
	}
	rc = write_to_driver(request, 3 + pcr_list_size,
			     &response, &response_size);
	return_if_error_label(rc, out_reset_pcrs);

out_reset_pcrs:
	free(request);
	free(response);
	return rc;
#endif
}