#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

int main(int argc, char const *argv[])
{
	ESYS_CONTEXT *context = NULL;
	TSS2_RC rc = Esys_Initialize(&context, NULL, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Initialize: %s\n", Tss2_RC_Decode(rc));
		return -1;
	}

	rc = Esys_Shutdown(context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_SU_STATE);
	if (rc != TPM2_RC_SUCCESS) {
		fprintf(stderr, "Esys_Shutdown: %s\n", Tss2_RC_Decode(rc));
		return -1;
	}

	Esys_Finalize(&context);
	return 0;
}
