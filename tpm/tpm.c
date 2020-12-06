#include <tpm/tpm.h>
#include <tpm/libtpm.h>
#include <octopos/mailbox.h>
#include <octopos/tpm.h>
#include <tpm/hash.h>
#include <arch/mailbox_tpm.h>
#include <openssl/sha.h>

static void pcr_print(uint8_t slot, TPML_DIGEST *pcrValues)
{
	for (uint32_t i = 0; i < pcrValues->count; i++) {
		for (size_t j = 0; j < pcrValues->digests[i].size; j++) {
			fprintf(stdout, "%02x", pcrValues->digests[i].buffer[j]);
		}
		fprintf(stdout, "\n");
	}

	///* print digest of pcr val */
	//fprintf(stdout, "pcr val digest: ");
	//SHA256_CTX hash_ctx;
	//SHA256_Init(&hash_ctx);
	//unsigned char hash[SHA256_DIGEST_LENGTH];
	////hash_buffer(pcrValues->digests[i].buffer, pcrValues->digests[i].size, hash);

	//for (uint8_t i = 0; i < pcrValues->count; i++) {
	//	SHA256_Update(&hash_ctx, pcrValues->digests[i].buffer,
	//		      pcrValues->digests[i].size);
	//}
	//SHA256_Final(hash, &hash_ctx);

	//print_hash_buf(hash);
}

/*
 * Return values:
 * 0: no,
 * 1: yes.
 */
static int is_proc_queue_owner(uint8_t proc_id, uint8_t queue_id)
{
	uint8_t owner = get_queue_owner(queue_id);

	int ret = (proc_id == owner);

	if (!ret)
		printf("Error: %s: proc %d is not the owner for queue %d\n",
		       __func__, proc_id, queue_id);

	return ret;
}

/*
 * Return values:
 * 0: not allowed,
 * 1: allowed.
 */
static int is_pcr_slot_attest_allowed(uint8_t pcr_slot, uint8_t requester)
{
	/* Every proc can ask for all PCR slots involved in the boot of the
	 * shared parts of the system.
	 */ 
	if (BOOT_PCR_SLOT(pcr_slot))
		return 1;

	uint8_t proc_id = PCR_SLOT_PROC(pcr_slot);

	/* Every proc can obviously ask for its own PCR slot */
	if (requester == proc_id)
		return 1;

	/* If the requester is the owner of one of the queues for which proc_id
	 * is the fixed_proc, then permission is granted.
	 */
	switch (proc_id) {
	case P_KEYBOARD:
		return is_proc_queue_owner(requester, Q_KEYBOARD);

	case P_SERIAL_OUT:
		return is_proc_queue_owner(requester, Q_SERIAL_OUT);

	case P_STORAGE:
		/* Even access to one of the queues should be enough, but
		 * there's no harm in being stricter here.
		 */
		return (is_proc_queue_owner(requester, Q_STORAGE_CMD_IN) &&
			is_proc_queue_owner(requester, Q_STORAGE_CMD_OUT) &&
			is_proc_queue_owner(requester, Q_STORAGE_DATA_IN) &&
			is_proc_queue_owner(requester, Q_STORAGE_DATA_OUT));

	case P_NETWORK:
		/* Even access to one of the queues should be enough, but
		 * there's no harm in being stricter here.
		 */
		return (is_proc_queue_owner(requester, Q_NETWORK_DATA_IN) &&
			is_proc_queue_owner(requester, Q_NETWORK_DATA_OUT));

	case P_RUNTIME1:
		return is_proc_queue_owner(requester, Q_RUNTIME1);

	case P_RUNTIME2:
		return is_proc_queue_owner(requester, Q_RUNTIME2);

	default:
		printf("Error: %s: unexpected proc_id (%d)\n", __func__,
		       proc_id);
		return 0;
	}
}

static void pcr_read_single(int slot)
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

/* FIXME: this function shares a lot of code with pcr_read_single(). */
static void pcr_read_to_buf(int slot, uint8_t *buf)
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

	//pcr_print(slot, pcrValues);
	if ((pcrValues->count != 1) ||
	    (pcrValues->digests[0].size != TPM_EXTEND_HASH_SIZE)) {
		fprintf(stderr, "Unexpected vals (count = %d, size = %d)\n",
			pcrValues->count, pcrValues->digests[0].size);
		/* FIXME: return error instead? */
		exit(1);
	}

	memcpy(buf, pcrValues->digests[0].buffer, TPM_EXTEND_HASH_SIZE);

	Esys_Free(pcrSelectionOut);
	Esys_Free(pcrValues);

	Esys_Finalize(&context);
}

static void process_request(FAPI_CONTEXT *context, uint8_t *buf, uint8_t proc_id)
{
	int op = buf[0];
	
	if (op == TPM_OP_EXTEND) {
		uint8_t hash_buf[TPM_EXTEND_HASH_SIZE];
		//uint8_t _proc_id;

		/* Note that we assume that two messages are needed to send the hash.
		* See include/tpm/hash.h
		*/
		memcpy(hash_buf, buf + 1, MAILBOX_QUEUE_MSG_SIZE - 1);
		///* test start */
		//printf("%s [1]: received hash: \n", __func__);
		//print_hash_buf(hash_buf);

		//printf("(proc %d) SLOT %d CURRENT VALUE: ", proc_id,
		//       PROC_PCR_SLOT(proc_id));
		//pcr_read_single(PROC_PCR_SLOT(proc_id));
		///* test end */
		tpm_directly_extend(PROC_PCR_SLOT(proc_id), hash_buf);
		printf("(proc %d) SLOT %d CHANGED TO: ", proc_id,
		       PROC_PCR_SLOT(proc_id));
		pcr_read_single(PROC_PCR_SLOT(proc_id));
	} else if (op == TPM_OP_ATTEST) {
		fprintf(stdout, "ATTEST REQUEST\n");
		//uint8_t nonce[TPM_AT_NONCE_LENGTH];
		uint8_t resp_buf[MAILBOX_QUEUE_MSG_SIZE];
		uint8_t *signature = NULL;
		size_t _signature_size = 0;
		char *quote_info = NULL;
		char *pcr_event_log = NULL;
		uint8_t num_pcr_slots = buf[1];
		uint32_t signature_size, quote_size;
		uint8_t i;
		int ret, off;

		if (num_pcr_slots > 24) {
			printf("Error: %s: invalid num_pcr_slots (%d)",
			       __func__, num_pcr_slots);
			goto attest_error;
		}

		/* Note that the checks here are not vulnerable to TOCTOU attacks.
		 * This is because the TPM service is single threaded.
		 * While we're processing the current command, no new values
		 * can be extended to PCRs. The PCRs might get reset, but that
		 * does not pose a confidentiality risk.
		 */
		for (i = 0; i < num_pcr_slots; i++) {
			ret = is_pcr_slot_attest_allowed(buf[2 + i], proc_id);
			if (!ret) {
				printf("Error: %s: attesting pcr slot %d for "
				       "proc %d not allowed)", __func__,
				       buf[2 + i], proc_id);
				goto attest_error;
			}
		}

		//memcpy(nonce, buf + 2, TPM_AT_NONCE_LENGTH);

		ret = quote_request(context, &buf[2 + num_pcr_slots], &buf[2],
				    num_pcr_slots, &signature, &_signature_size,
				    &quote_info, &pcr_event_log);
		if (ret) {
			printf("Error: %s: quote request failed\n", __func__);
			goto attest_error;
		}
		
		/* Send signature and quote */
		resp_buf[0] = TPM_REP_ATTEST;
		signature_size = (uint32_t) _signature_size;
		quote_size = strlen(quote_info);
		*((uint32_t *) &resp_buf[1]) = signature_size;
		*((uint32_t *) &resp_buf[5]) = quote_size;

		send_response_to_queue(resp_buf);

		off = 0;
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

		return;
attest_error:
		resp_buf[0] = TPM_REP_ERROR;
		send_response_to_queue(resp_buf);
	} else if (op == TPM_OP_READ_PCR) {
		uint8_t resp_buf[MAILBOX_QUEUE_MSG_SIZE];
		uint8_t pcr_slot = buf[1];
		int ret;

		/* Note that the check here is not vulnerable to TOCTOU attacks.
		 * This is because the TPM service is single threaded.
		 * While we're processing the current command, no new values
		 * can be extended to PCRs. The PCRs might get reset, but that
		 * does not pose a confidentiality risk.
		 */
		ret = is_pcr_slot_attest_allowed(pcr_slot, proc_id);
		if (!ret) {
			printf("Error: %s: reading pcr slot %d for proc %d not "
			       "allowed)", __func__, pcr_slot, proc_id);
			resp_buf[0] = TPM_REP_ERROR;
			send_response_to_queue(resp_buf);
			return;
		}
		
		resp_buf[0] = TPM_REP_READ_PCR;
		pcr_read_to_buf(pcr_slot, &resp_buf[1]);
		send_response_to_queue(resp_buf);
	} else {
		fprintf(stderr, "Error: No identified operation %d.\n", op);
	}

	return;
}

static int init_context(FAPI_CONTEXT **context)
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

static void tpm_measurement_core(FAPI_CONTEXT *context)
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
