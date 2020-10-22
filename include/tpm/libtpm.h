#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <stdint.h>

int prepare_extend(char *path, TPML_DIGEST_VALUES *digest_value);
int quote_request(FAPI_CONTEXT *context, uint8_t *nonce, int slot,
	uint8_t **signature, size_t *signature_size,
	char** quote_info, char **pcr_event_log);
void tpm_directly_extend(int slot, char *path);