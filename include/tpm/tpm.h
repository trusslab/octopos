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
//#define TPM_KNL_MEASUREMENT 8
//#define TPM_USR_MEASUREMENT 9
#define PROC_PCR_SLOT(proc_id) (7 + proc_id)
#define MIN_PROC_ID	1
#define MAX_PROC_ID	8

#define TPM_INIT_ERR 0x01
#define TPM_EXTD_ERR 0x02
