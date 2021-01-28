#ifndef TPM_H_
#define TPM_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

#define TSS_LOG_LVL_NONE    "ALL+none"
#define TSS_LOG_LVL_ERROR   "ALL+error"
#define TSS_LOG_LVL_DEBUG   "ALL+debug"

/**
* PCR No.    Allocation
* ------------------------------------------------------
* 0-24       Origin PCR, preserved
* 25         OS PCR
* 26         KEYBOARD PCR
* 27         SERIAL_OUT PCR
* 28         STORAGE PCR
* 29         NETWORK PCR
* 30         BLUETOOTH PCR
* 31         RUNTIME1 PCR
* 32         RUNTIME2 PCR
* 33         UNTRUSTED PCR
* 34         PMU PCR
* 35-40      Placeholder
*/
#define TPM_PCR_BANK(pcr)   (ESYS_TR_PCR0 + pcr)
#define TPM_PCR_BASE        TPM_PCR_BANK(24)
#define PCR_TO_PROC(pcr)    (pcr - TPM_PCR_BASE)
#define PROC_TO_PCR(proc)   (proc + TPM_PCR_BASE)

#define LOCALITY_BASE       0x80
#define LOCALITY_OS         (LOCALITY_BASE)
#define LOCALITY_KEYBOARD   (LOCALITY_BASE + 0x01)
#define LOCALITY_SERIAL_OUT (LOCALITY_BASE + 0x02)
#define LOCALITY_STORAGE    (LOCALITY_BASE + 0x03)
#define LOCALITY_NETWORK    (LOCALITY_BASE + 0x04)
#define LOCALITY_BLUETOOTH  (LOCALITY_BASE + 0x05)
#define LOCALITY_RUNTIME1   (LOCALITY_BASE + 0x06)
#define LOCALITY_RUNTIME2   (LOCALITY_BASE + 0x07)
#define LOCALITY_UNTRUSTED  (LOCALITY_BASE + 0x08)
#define LOCALITY_PMU        (LOCALITY_BASE + 0x09)
#define PROC_LOCALITY(proc) (LOCALITY_BASE + (proc - 1))

// #define BOOT_PCR_SLOT(pcr_slot) (pcr_slot <= 7)

#define SAFE_FREE(S) if((S) != NULL) {free((void*) (S)); (S)=NULL;}

#define TPM2_ERROR_FORMAT "%s%s (0x%08x)"
#define TPM2_ERROR_TEXT(r) "Error", "Code", r

#define return_if_error_no_msg(r) \
    if (r != 0) { \
        return r;  \
    }

#define return_if_error(r,msg) \
    if (r != TSS2_RC_SUCCESS) { \
        fprintf(stderr, "%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;  \
    }

#define return_if_error_exception(r,msg,except) \
    if (r != TSS2_RC_SUCCESS && r != except) { \
        fprintf(stderr, "%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;  \
    }

/* Top-level TPM API for extending / reading / attestation */
int tpm_measure_service(char* path, uint8_t processor);
int tpm_processor_read_pcr(uint8_t processor, uint8_t *pcr_value);
int tpm_attest(uint8_t processor, uint8_t *nonce, 
			   uint32_t *pcr_list, size_t pcr_list_size,
			   uint8_t **signature, size_t *signature_size, 
			   char** quote_info);

/* Wrapper of FAPI and ESAPI */
int tpm_initialize(FAPI_CONTEXT **context, uint8_t processor);
int tpm_finalize(FAPI_CONTEXT **context);
int tpm_read(FAPI_CONTEXT* context, uint8_t index, uint8_t* buf, 
			 char** log, BOOL print);
int tpm_extend(FAPI_CONTEXT* context, int selected, uint8_t *hash_buf);
int tpm_quote(FAPI_CONTEXT *context, uint8_t *nonce,
			  uint32_t *pcr_list, size_t pcr_list_size,
			  uint8_t **signature, size_t *signature_size, 
			  char** quote_info, char **pcr_event_log);

/* Support function */
void print_digest(uint8_t pcr_index, uint8_t *digest, size_t digest_size);
int prepare_extend(char *hash_buf, TPML_DIGEST_VALUES *digest_value);

// int is_pcr_slot_attest_allowed(uint8_t pcr_slot, uint8_t requester);

#endif