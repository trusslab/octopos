/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#include <tpm/tpm.h>
#include <tpm/hash.h>
#include <tpm/aes.h>
#include <fcntl.h> /* For O_* constants */
#include <sys/stat.h>
#include <semaphore.h>

#define ARCH_UMODE

static uint8_t running_processor = 0;

/* Support functions:
 *      print_binary
 * 	print_digest
 * 	print_digest_buffer
 * 	hash_to_byte_structure
 * 	prepare_extend
 */
#define BIN_PRINT_LENGTH 16
void print_binary(const uint8_t *buffer, size_t length)
{
	size_t i;
	size_t line_length;
	char line[(BIN_PRINT_LENGTH * 4) + 4];
	char *ptr;

	if (!buffer) {
		printf("\tNULL");
		return;
	}

	while (length > 0) {
		line_length = length;
		if (line_length > BIN_PRINT_LENGTH)
			line_length = BIN_PRINT_LENGTH;

		ptr = line;
		ptr += sprintf(ptr, "\t");
		for (i = 0; i < BIN_PRINT_LENGTH; i++) {
			if (i < length)
				ptr += sprintf(ptr, "%02x ", buffer[i]);
			else
				ptr += sprintf(ptr, "   ");
		}
		ptr += sprintf(ptr, "| ");
		for (i = 0; i < line_length; i++) {
			if (buffer[i] > 31 && buffer[i] < 127)
				ptr += sprintf(ptr, "%c", buffer[i]);
			else
				ptr += sprintf(ptr, ".");
		}
		printf("%s\n", line);

		buffer += line_length;
		length -= line_length;
	}
}

void print_digest(uint8_t pcr_index, const uint8_t *digest, size_t digest_size)
{
	printf("PCR %d: ", pcr_index);
	for (size_t index = 0; index < digest_size; index++)
		printf("%02x", *(digest + index));
	printf("\n");
}

void print_digest_buffer(const uint8_t *digest, size_t digest_size, char *buf,
			 size_t buf_size)
{
	if (digest_size * 2 + 1 != buf_size)
		return;
	for (size_t index = 0; index < digest_size; index++)
		sprintf(buf + index * 2, "%02x", *(digest + index));
	buf[buf_size - 1] = '\0';
}

int hash_to_byte_structure(const uint8_t *input_string, UINT16 *byte_length,
			   BYTE *byte_buffer)
{
	if (input_string == NULL || byte_length == NULL ||
	    byte_buffer == NULL) {
		return -1;
	}

	size_t str_length = strlen((char *)input_string);
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

int prepare_extend(uint8_t *hash_buf, uint8_t *digest_value)
{
	UINT16 hash_size = TPM_EXTEND_HASH_SIZE;
	int rc = hash_to_byte_structure(hash_buf, &hash_size, digest_value);
	if (rc) {
		fprintf(stderr,
			"Error converting hex string as data, got: \"%s\"",
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

/* Wrapper of WOLF TPM2 functions:
 * 	tpm_initialize
 * 	tpm_finalize
 * 	tpm_read
 * 	tpm_quote
 * 	tpm_seal_key
 * 	tpm_unseal_key
 * 	tpm_reset
 */
int tpm_initialize(WOLFTPM2_DEV *dev)
{
	int rc = TPM_RC_SUCCESS;

	rc = check_processor(running_processor);
	return_if_error_no_msg(rc);

	rc = wolfTPM2_Init(dev, NULL, NULL);
	return_if_error(rc, "TPM Initialization Error.");

	dev->ctx.locality = PROC_LOCALITY(running_processor);

	return rc;
}

void tpm_finalize(WOLFTPM2_DEV *dev)
{
	wolfTPM2_Shutdown(dev, 0);
	wolfTPM2_Cleanup(dev);
}

int tpm_gen_ek(WOLFTPM2_DEV *dev)
{
	int rc = TPM_RC_SUCCESS;
	WOLFTPM2_KEY ekKey;
	TPMT_PUBLIC publicTemplate;

	rc = wolfTPM2_GetKeyTemplate_RSA_EK(&publicTemplate);
	return_if_error(rc, "Get Key Template Error.");

	rc = wolfTPM2_CreatePrimaryKey(dev, &ekKey, TPM_RH_ENDORSEMENT,
				       &publicTemplate, NULL, 0);
	return_if_error(rc, "Create Primary Key Error.");

	wolfTPM2_UnloadHandle(dev, &ekKey.handle);

	return rc;
}

int tpm_read(WOLFTPM2_DEV *dev, uint32_t pcr_index, uint8_t *buf, bool print)
{
	int rc = TPM_RC_SUCCESS;
	uint8_t digest[TPM_EXTEND_HASH_SIZE];
	int digest_size = 0;

	rc = wolfTPM2_ReadPCR(dev, pcr_index, TPM_ALG_SHA256, digest,
			      &digest_size);
	return_if_error(rc, "Read PCR Error.");

	if (digest_size != TPM_EXTEND_HASH_SIZE) {
		fprintf(stderr, "Unexpected vals (size = %d)\n", digest_size);
		return -1;
	}

	if (print)
		print_digest(pcr_index, digest, digest_size);

	if (buf != NULL)
		memcpy(buf, digest, digest_size);

	return 0;
}

int tpm_extend(WOLFTPM2_DEV *dev, uint32_t pcr_index, uint8_t *hash_buf)
{
	int rc = TPM_RC_SUCCESS;
	uint8_t hash_str[(2 * TPM_EXTEND_HASH_SIZE) + 1];
	uint8_t digests[TPM_EXTEND_HASH_SIZE];

	convert_hash_to_str(hash_buf, hash_str);

	rc = prepare_extend(hash_str, digests);
	return_if_error(rc, "Extend preparation failed.");

	rc = wolfTPM2_ExtendPCR(dev, pcr_index, TPM_ALG_SHA256, digests,
				TPM_EXTEND_HASH_SIZE);
	return_if_error(rc, "PCR Extend Error.");

	return 0;
}

int tpm_quote(WOLFTPM2_DEV *dev, uint8_t *nonce, uint32_t *pcr_list,
	      size_t pcr_list_size, uint8_t **signature, size_t *signature_size,
	      uint8_t **quote, size_t *quote_size)
{
	int rc = TPM_RC_SUCCESS;
	WOLFTPM2_KEY storageKey;
	WOLFTPM2_KEY aik;
	Quote_In quoteAsk;
	Quote_Out quoteResult;
	TPMS_ATTEST attestedData;

	rc = wolfTPM2_ReadPublicKey(dev, &storageKey, TPM2_STORAGE_KEY_HANDLE);
	if (rc) {
		rc = wolfTPM2_CreateSRK(dev, &storageKey, TPM_ALG_RSA, NULL, 0);
		return_if_error(rc, "Create SRK Error.");

		rc = wolfTPM2_NVStoreKey(dev, TPM_RH_OWNER, &storageKey,
					 TPM2_STORAGE_KEY_HANDLE);
		return_if_error(rc, "NV Store SRK Error.");
	}

	rc = wolfTPM2_ReadPublicKey(dev, &aik, TPM2_ATTEST_KEY_HANDLE);
	if (rc) {
		rc = wolfTPM2_CreateAndLoadAIK(dev, &aik, TPM_ALG_RSA,
					       &storageKey, NULL, 0);
		return_if_error(rc, "Create AIK Error.");

		rc = wolfTPM2_NVStoreKey(dev, TPM_RH_OWNER, &aik,
					 TPM2_ATTEST_KEY_HANDLE);
		return_if_error(rc, "NV Store AIK Error.");
	}

	wolfTPM2_SetAuthPassword(dev, 0, NULL);
	wolfTPM2_SetAuthHandle(dev, 0, &aik.handle);

	XMEMSET(&quoteAsk, 0, sizeof(quoteAsk));
	XMEMSET(&quoteResult, 0, sizeof(quoteResult));
	quoteAsk.signHandle = aik.handle.hndl;
	quoteAsk.inScheme.scheme = TPM_ALG_RSASSA;
	quoteAsk.inScheme.details.any.hashAlg = TPM_ALG_SHA256;
	quoteAsk.qualifyingData.size = 16;
	XMEMCPY(quoteAsk.qualifyingData.buffer, nonce, 16);
	quoteAsk.PCRselect.count = 1;

	for (size_t i = 0; i < pcr_list_size; i++) {
		quoteAsk.PCRselect.pcrSelections[0].hash = TPM_ALG_SHA256;
		quoteAsk.PCRselect.pcrSelections[0].sizeofSelect =
			PCR_SELECT_MAX;
		quoteAsk.PCRselect.pcrSelections[0].pcrSelect[pcr_list[i] >> 3] =
			(1 << (pcr_list[i] & 0x7));
	}

	rc = TPM2_Quote(&quoteAsk, &quoteResult);
	return_if_error(rc, "Quote failed");

	rc = TPM2_ParseAttest(&quoteResult.quoted, &attestedData);
	return_if_error(rc, "Parse Attest failed");
	if (attestedData.magic != TPM_GENERATED_VALUE)
		printf("\tError, attested data not generated by the TPM = 0x%X\n",
		       attestedData.magic);

	*quote_size = quoteResult.quoted.size;
	*quote = (uint8_t *)malloc(*quote_size);
	XMEMCPY(*quote, &quoteResult.quoted.attestationData, *quote_size);

	*signature_size = sizeof(TPMT_SIGNATURE);
	*signature = (uint8_t *)malloc(*signature_size);
	XMEMCPY(*signature, (uint8_t *)&quoteResult.signature, *signature_size);

	return rc;
}

int tpm_reset(uint32_t pcr_selected)
{
	int rc = TPM_RC_SUCCESS;
	PCR_Reset_In pcrReset;

	pcrReset.pcrHandle = pcr_selected;
	rc = TPM2_PCR_Reset(&pcrReset);
	return_if_error(rc, "PCR Reset failed");

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

int tpm_measure_service(char *path, BOOL is_path)
{
	int rc = 0;
	uint8_t hash_value[TPM_EXTEND_HASH_SIZE] = { 0 };

	if (is_path) {
		rc = hash_file(path, hash_value);
		return_if_error_no_msg(rc);
	} else {
		memcpy(hash_value, path, TPM_EXTEND_HASH_SIZE);
	}

	WOLFTPM2_DEV dev;

	rc = tpm_initialize(&dev);
	return_if_error_no_msg(rc);

	rc = tpm_extend(&dev, PROC_TO_PCR(running_processor), hash_value);
	return_if_error_label(rc, out_measure_service);

out_measure_service:
	tpm_finalize(&dev);
	return rc;
}

int tpm_processor_read_pcr(uint32_t pcr_index, uint8_t *pcr_value)
{
	int rc = 0;
	WOLFTPM2_DEV dev;

	rc = tpm_initialize(&dev);
	return_if_error_no_msg(rc);

	rc = tpm_read(&dev, pcr_index, pcr_value, false);
	return_if_error_label(rc, out_processor_read_pcr);

out_processor_read_pcr:
	tpm_finalize(&dev);
	return rc;
}

int tpm_attest(uint8_t *nonce, uint32_t *pcr_list, size_t pcr_list_size,
	       uint8_t **signature, size_t *signature_size,
	       uint8_t **quote_info, size_t *quote_info_size)
{
	int rc = 0;
	WOLFTPM2_DEV dev;

	rc = tpm_initialize(&dev);
	return_if_error_no_msg(rc);

	rc = tpm_quote(&dev, nonce, pcr_list, pcr_list_size, signature,
		       signature_size, quote_info, quote_info_size);
	return_if_error_label(rc, out_attest);

out_attest:
	tpm_finalize(&dev);
	return rc;
}

int tpm_reset_pcrs(const uint32_t *pcr_list, size_t pcr_list_size)
{
	int rc = 0;
	size_t pcr_index = 0;
	WOLFTPM2_DEV dev;

	rc = tpm_initialize(&dev);
	return_if_error_no_msg(rc);

	for (; pcr_index < pcr_list_size; pcr_index++) {
		rc = tpm_reset(*(pcr_list + pcr_index));
		return_if_error_label(rc, out_reset_pcrs);
	}

out_reset_pcrs:
	tpm_finalize(&dev);
	return rc;
}
