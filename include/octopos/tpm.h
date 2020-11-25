#define TPM_OP_EXTEND		1
#define TPM_OP_ATTEST		2

#define TPM_REP_EXTEND		0x11
#define TPM_REP_ATTEST		0x12
#define TPM_REP_ERROR		0x13

#define PROC_PCR_SLOT(proc_id) (7 + proc_id)

#define TPM_AT_ID_LENGTH 16
#define TPM_AT_NONCE_LENGTH 16
