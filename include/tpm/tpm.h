#ifndef ARCH_SEC_HW

#ifndef TPM_H_
#define TPM_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <time.h>

/* FIX: duplicate define */
#define INVALID_PROCESSOR 11

#define TSS_LOG_LVL_NONE "ALL+none"
#define TSS_LOG_LVL_ERROR "ALL+error"
#define TSS_LOG_LVL_WARNING "ALL+warning"
#define TSS_LOG_LVL_DEBUG "ALL+debug"
#define TSS_LOG_LVL_TRACE "ALL+trace"

/**
 * PCR No.    Allocation
 * ------------------------------------------------------
 * 0-24       Origin PCRs, preserved
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
#define TPM_PCR_BANK(pcr) (ESYS_TR_PCR0 + pcr)
#define TPM_PCR_BASE TPM_PCR_BANK(24)
#define PCR_TO_PROC(pcr) (pcr - TPM_PCR_BASE)
#define PROC_TO_PCR(proc) (proc + TPM_PCR_BASE)

#define LOCALITY_BASE 0x80
#define PROC_LOCALITY(proc) (LOCALITY_BASE + (proc - 1))

#define OP_MEASURE 0x01
#define OP_READ 0x02
#define OP_ATTEST 0x03
#define OP_SEAL 0x04
#define OP_RESET 0x06
/* Deprecated OP */
#define OP_UNSEAL 0x05

/* Macros copied from TPM2-TSS */
#define SAFE_FREE(S)       \
    if ((S) != NULL)       \
    {                      \
        free((void *)(S)); \
        (S) = NULL;        \
    }

#define TPM2_ERROR_FORMAT "(0x%08x), %s"
#define TPM2_ERROR_TEXT(r) r, Tss2_RC_Decode(r)

#define return_if_error(r, msg)                                            \
    if (r != TSS2_RC_SUCCESS)                                              \
    {                                                                      \
        fprintf(stderr, "%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;                                                          \
    }

#define return_if_error_no_msg(r) \
    if (r != 0)                   \
    {                             \
        return r;                 \
    }

#define return_if_error_label(r, label) \
    if (r != 0)                         \
    {                                   \
        goto label;                     \
    }

#define return_if_error_exception(r, msg, except)                          \
    if (r != TSS2_RC_SUCCESS && r != except)                               \
    {                                                                      \
        fprintf(stderr, "%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;                                                          \
    }

/* Support functions */
void print_digest(uint8_t pcr_index, const uint8_t *digest, size_t digest_size);
void print_digest_buffer(const uint8_t *digest, size_t digest_size,
                         char *buf, size_t buf_size);
int hash_to_byte_structure(const char *input_string, UINT16 *byte_length,
                           BYTE *byte_buffer);
int prepare_extend(char *hash_buf, TPML_DIGEST_VALUES *digest_value);
int check_processor(uint8_t processor);

/* Wrapper of FAPI and ESAPI */
int tpm_set_locality(FAPI_CONTEXT *context, uint8_t processor);
int tpm_initialize(FAPI_CONTEXT **context);
void tpm_finalize(FAPI_CONTEXT **context);
int tpm_read(FAPI_CONTEXT *context, uint32_t pcr_index, uint8_t *buf,
             char **log, BOOL print);
int tpm_extend(FAPI_CONTEXT *context, uint32_t pcr_index, uint8_t *hash_buf);
int tpm_quote(FAPI_CONTEXT *context, uint8_t *nonce,
              uint32_t *pcr_list, size_t pcr_list_size,
              uint8_t **signature, size_t *signature_size,
              char **quote_info, char **pcr_event_log);
int tpm_seal_key(FAPI_CONTEXT *context, uint8_t *data, size_t data_size);
int tpm_unseal_key(FAPI_CONTEXT *context, uint8_t **data, size_t *data_size);
int tpm_reset(FAPI_CONTEXT *context, uint32_t pcr_selected);

/* Top-level TPM API exposed for calling */
int enforce_running_process(uint8_t processor);
int cancel_running_process();
int tpm_measure_service(char *path, BOOL is_path);
int tpm_processor_read_pcr(uint32_t pcr_index, uint8_t *pcr_value);
int tpm_attest(uint8_t *nonce, uint32_t *pcr_list,
               size_t pcr_list_size, uint8_t **signature,
               size_t *signature_size, char **quote_info);
int tpm_get_storage_key(uint8_t **key_iv);
int tpm_reset_pcrs(const uint32_t *pcr_list, size_t pcr_list_size);
#endif

#endif