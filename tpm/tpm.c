#include <tpm/tpm.h>
#include <tpm/libtpm.h>
#include <octopos/mailbox.h>
#include <octopos/tpm.h>
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

void process_request(FAPI_CONTEXT *context, uint8_t *buf, uint8_t proc_id)
{
	int op = buf[0];
	
	if (op == TPM_OP_EXTEND) {
		fprintf(stdout, "EXTEND REQUEST\n");
		char content[MAILBOX_QUEUE_MSG_SIZE] = {0};
		memcpy(content, buf + 1, MAILBOX_QUEUE_MSG_SIZE - 1);
		
		tpm_directly_extend(PROC_PCR_SLOT(proc_id), content);
		printf("(proc %d) SLOT %d CHANGED TO: ", proc_id, PROC_PCR_SLOT(proc_id));
		pcr_read_single(PROC_PCR_SLOT(proc_id));
	} else if (op == TPM_OP_ATTEST) {
		fprintf(stdout, "ATTEST REQUEST\n");
		uint8_t nonce[TPM_AT_NONCE_LENGTH];
		memcpy(nonce, buf + 2, TPM_AT_NONCE_LENGTH);

		uint8_t *signature = NULL;
		size_t signature_size = 0;
		char *quote_info = NULL;
		char *pcr_event_log = NULL;
		quote_request(context, nonce, buf[1],
			&signature, &signature_size, &quote_info, &pcr_event_log);
		
		// Send Signature
		uint8_t sig_out[MAILBOX_QUEUE_MSG_SIZE];
		sig_out[0] = TPM_REP_ATTEST_SIG;
		sig_out[1] = signature_size;
		if (signature_size <= (MAILBOX_QUEUE_MSG_SIZE - 2) ||
		    signature_size > ((2 * MAILBOX_QUEUE_MSG_SIZE) - 2)) {
		    printf("Error: %s: unexpected signature_size (%d).\n",
			   __func__, (int) signature_size);
		    exit(-1);
		}
		memcpy(&sig_out[2], signature, MAILBOX_QUEUE_MSG_SIZE - 2);
		send_response_to_queue(sig_out);
		memcpy(sig_out, signature + (MAILBOX_QUEUE_MSG_SIZE - 2),
		       signature_size - (MAILBOX_QUEUE_MSG_SIZE - 2));
		send_response_to_queue(sig_out);

		FILE* quote_file = fopen("quote_info", "w");
		fwrite(quote_info, strlen(quote_info), 1, quote_file);
		fclose(quote_file);

		free(signature);
		free(quote_info);
		free(pcr_event_log);
	} else {
		fprintf(stderr, "Error: No identified operation %d.\n", op);
	}

	return;
}

int init_context(FAPI_CONTEXT **context)
{
	TSS2_RC rc = Fapi_Initialize(context, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Fapi_Initialize: %s\n", Tss2_RC_Decode(rc));
		return -1;
	}

	rc = Fapi_Provision(*context, NULL, NULL, NULL);
	if (rc == TSS2_FAPI_RC_ALREADY_PROVISIONED) {
		fprintf(stdout, "INFO: Profile was provisioned.\n");
	} else if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "ERROR: Fapi_Provision: %s.\n", Tss2_RC_Decode(rc));
		return -1;
	}

	/* Create AK */
	rc = Fapi_CreateKey(*context, "HS/SRK/AK", "sign,noDa", "", NULL);
	if (rc == TSS2_FAPI_RC_PATH_ALREADY_EXISTS) {
		fprintf(stdout, "INFO: Key HS/SRK/AK already exists.\n");
	} else if (rc == TSS2_RC_SUCCESS) {
		fprintf(stdout, "INFO: Key HS/SRK/AK created.\n");
	} else {
		fprintf(stderr, "ERROR: Fapi_CreateKey: %s.\n", Tss2_RC_Decode(rc));
		return -1;
	}

	return 0;
}

void tpm_measurement_core(FAPI_CONTEXT *context)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t proc_id;

	while (1) {
		proc_id = read_request_get_owner_from_queue(buf);
		if (proc_id < MIN_PROC_ID || proc_id > MAX_PROC_ID) {
			printf("Error: %s: unsupported proc_id (%d)\n",
			       __func__, proc_id);
			continue;
		}
		process_request(context, buf, proc_id);
	}
}

int main(int argc, char const *argv[])
{
	setenv("TSS2_LOG", TSS_LOG_LVL_NONE, 1);

	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: TPM init\n", __func__);

	int ret = init_tpm();
	if (ret)
		return ret;
	
	FAPI_CONTEXT *context = NULL;
	init_context(&context);
	
	tpm_measurement_core(context);

	Fapi_Finalize(&context);
	close_tpm();
	
	return 0;
}
