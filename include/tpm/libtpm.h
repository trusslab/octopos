#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <stdint.h>

/* FIXME: is this the right file for all of these? */
int prepare_extend(char *hash_buf, TPML_DIGEST_VALUES *digest_value);
void tpm_directly_extend(int slot, uint8_t *hash_buf);
int is_pcr_slot_attest_allowed(uint8_t pcr_slot, uint8_t proc_id);
int quote_request(FAPI_CONTEXT *context, uint8_t *nonce, uint8_t *pcr_slots,
		  uint8_t num_pcr_slots, uint8_t **signature,
		  size_t *signature_size, char** quote_info,
		  char **pcr_event_log);
