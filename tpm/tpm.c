#include <tpm/tpm.h>
#include <tpm/libtpm.h>
#include <octopos/mailbox.h>
#include <octopos/tpm.h>
#include <tpm/hash.h>
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
		uint8_t hash_buf[TPM_EXTEND_HASH_SIZE];
		uint8_t _proc_id;

		/* Note that we assume that two messages are needed to send the hash.
		* See include/tpm/hash.h
		*/
		memcpy(hash_buf, buf + 1, MAILBOX_QUEUE_MSG_SIZE - 1);

		_proc_id = read_request_get_owner_from_queue(buf);
		if (_proc_id != proc_id) {
			printf("Error: %s: unexpected sender proc_id (%d, %d)\n",
			       __func__, _proc_id, proc_id);
			/* FIXME: send an error? We currently don't send a
			 * response for the extend op and the clients don't
			 * check either. */
			return;
		}

		memcpy(hash_buf + MAILBOX_QUEUE_MSG_SIZE - 1, buf,
		       TPM_EXTEND_HASH_SIZE - MAILBOX_QUEUE_MSG_SIZE + 1);

		tpm_directly_extend(PROC_PCR_SLOT(proc_id), (char *) hash_buf);
		printf("(proc %d) SLOT %d CHANGED TO: ", proc_id,
		       PROC_PCR_SLOT(proc_id));
		pcr_read_single(PROC_PCR_SLOT(proc_id));
	} else if (op == TPM_OP_ATTEST) {
		fprintf(stdout, "ATTEST REQUEST\n");
		uint8_t nonce[TPM_AT_NONCE_LENGTH];
		memcpy(nonce, buf + 2, TPM_AT_NONCE_LENGTH);

		uint8_t *signature = NULL;
		size_t _signature_size = 0;
		char *quote_info = NULL;
		char *pcr_event_log = NULL;
		quote_request(context, nonce, buf[1],
			&signature, &_signature_size, &quote_info,
			&pcr_event_log);
		
		/* Send signature and quote */
		uint8_t resp_buf[MAILBOX_QUEUE_MSG_SIZE];
		resp_buf[0] = TPM_REP_ATTEST;
		uint32_t signature_size = (uint32_t) _signature_size;
		uint32_t quote_size = strlen(quote_info);
		*((uint32_t *) &resp_buf[1]) = signature_size;
		*((uint32_t *) &resp_buf[5]) = quote_size;

		send_response_to_queue(resp_buf);

		int off = 0;
		while (signature_size) {
			if (signature_size > MAILBOX_QUEUE_MSG_SIZE) {
				memcpy(resp_buf, signature + off,
				       MAILBOX_QUEUE_MSG_SIZE);
				off += MAILBOX_QUEUE_MSG_SIZE;
				signature_size -= MAILBOX_QUEUE_MSG_SIZE;
			} else {
				memcpy(resp_buf, signature + off,
				       signature_size);
				signature_size = 0;
			}
			send_response_to_queue(resp_buf);
		}

		off = 0;
		while (quote_size) {
			if (quote_size > MAILBOX_QUEUE_MSG_SIZE) {
				memcpy(resp_buf, quote_info + off,
				       MAILBOX_QUEUE_MSG_SIZE);
				off += MAILBOX_QUEUE_MSG_SIZE;
				quote_size -= MAILBOX_QUEUE_MSG_SIZE;
			} else {
				memcpy(resp_buf, quote_info + off, quote_size);
				quote_size = 0;
			}
			send_response_to_queue(resp_buf);
		}

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
