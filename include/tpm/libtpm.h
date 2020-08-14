#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <stdint.h>

int prepare_extend(char *path, TPML_DIGEST_VALUES *digest_value);