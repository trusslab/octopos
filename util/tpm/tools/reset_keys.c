#include <stdio.h>
#include <string.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_rc.h>

int main(int argc, char const *argv[])
{
	FAPI_CONTEXT *context = NULL;
	Fapi_Initialize(&context, NULL);
	Fapi_Provision(context, NULL, NULL, NULL);
	Fapi_Delete(context, "/HS/SRK/AK");
	Fapi_Finalize(&context);
	return 0;
}