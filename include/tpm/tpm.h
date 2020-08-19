#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

/**
* PCR No.    Allocation
* ------------------------------------------------------
* 0          BIOS
* 1          BIOS configuration
* 2          Option ROMs
* 3          Option ROM configuration
* 4          MBR (master boot record)
* 5          MBR configuration
* 6          State transitions and wake events
* 7          Platform manufacturer specific measurements
* 8–15       Static operating system
* 16         Debug
* 17-20      Locality 4-1
* 21-22      Dynamic OS controlled
* 23         Application specific
*/
#define TPM_PCR_BANK(slot) (ESYS_TR_PCR0 + slot)
#define TPM_PCR_DEFAULT_SLOT 15

#define TPM_INIT_ERR 0x01
#define TPM_EXTD_ERR 0x02

void pcr_read_single(uint8_t slot);
void pcr_print(uint8_t slot, TPML_DIGEST *pcrValues);
void pcr_extend_data(uint8_t slot, char *data);
void pcr_extend_file(uint8_t slot, char *path);

void tpm_monitor_core(void);
