#ifndef __ARCH_OCTOPOS_MBOX_H_
#define __ARCH_OCTOPOS_MBOX_H_

#define OWNER_MASK (u32) 0x00FFFFFF
#define QUOTA_MASK (u32) 0xFF000FFF
#define TIME_MASK  (u32) 0xFFFFF000

#define MAX_OCTOPOS_MAILBOX_QUOTE 4094

#define OCTOPOS_MAILBOX_MAX_TIME_DRIFT 10

/* mailbox ctrl register addresses mapped to OS */
#define OCTOPOS_MAILBOX_OS_1WRI_0_BASEADDR 0xA0000000

#define OCTOPOS_MAILBOX_OS_3WRI_0_BASEADDR 0xA0001000

#define OCTOPOS_MAILBOX_OS_3WRI_1_BASEADDR 0xA0033000

#define OCTOPOS_MAILBOX_OS_3WRI_2_BASEADDR 0xA0035000

#define OCTOPOS_OS_Q_STORAGE_DATA_IN_BASEADDR 0xA0055000

#define OCTOPOS_OS_Q_STORAGE_DATA_OUT_BASEADDR 0xA0053000

#define OCTOPOS_OS_Q_STORAGE_IN_2_BASEADDR 0xA0059000

#define OCTOPOS_OS_Q_STORAGE_OUT_2_BASEADDR 0xA0057000

/* mailbox ctrl register addresses mapped to Microblaze 0 and 1 */
#define OCTOPOS_SERIAL_MAILBOX_1WRI_0_BASEADDR 0x44A00000

/* mailbox ctrl register addresses mapped to Microblaze 2 and 3 */
#define OCTOPOS_ENCLAVE_MAILBOX_1WRI_0_BASEADDR 0x44A00000

#define OCTOPOS_ENCLAVE_MAILBOX_3WRI_0_BASEADDR 0x44A10000

#define OCTOPOS_ENCLAVE_MAILBOX_3WRI_1_BASEADDR 0x44A20000

#define OCTOPOS_ENCLAVE_MAILBOX_3WRI_2_BASEADDR 0x44A30000

#define OCTOPOS_ENCLAVE_Q_STORAGE_DATA_IN_BASEADDR 0x44A34000

#define OCTOPOS_ENCLAVE_Q_STORAGE_DATA_OUT_BASEADDR 0x44A32000

#define OCTOPOS_ENCLAVE_Q_STORAGE_IN_2_BASEADDR 0x44A38000

#define OCTOPOS_ENCLAVE_Q_STORAGE_OUT_2_BASEADDR 0x44A36000

/* mailbox ctrl register addresses mapped to Microblaze 4 */
#define OCTOPOS_STORAGE_Q_STORAGE_DATA_IN_BASEADDR 0x43605000

#define OCTOPOS_STORAGE_Q_STORAGE_DATA_OUT_BASEADDR 0x43603000

#define OCTOPOS_STORAGE_Q_STORAGE_IN_2_BASEADDR 0x43609000

#define OCTOPOS_STORAGE_Q_STORAGE_OUT_2_BASEADDR 0x43607000


u32 octopos_mailbox_get_status_reg(UINTPTR base);

void octopos_mailbox_set_status_reg(UINTPTR base, u32 value);

u8 octopos_mailbox_get_owner(UINTPTR base);

void octopos_mailbox_set_owner(UINTPTR base, u8 owner);

u16 octopos_mailbox_get_quota_limit(UINTPTR base);

void octopos_mailbox_set_quota_limit(UINTPTR base, u16 limit);

u16 octopos_mailbox_get_time_limit(UINTPTR base);

void octopos_mailbox_set_time_limit(UINTPTR base, u16 limit);

u32 octopos_mailbox_calc_owner(u32 reg, u8 owner);

u32 octopos_mailbox_calc_quota_limit(u32 reg, u16 limit);

u32 octopos_mailbox_calc_time_limit(u32 reg, u16 limit);

_Bool octopos_mailbox_attest_owner(UINTPTR base, u8 owner);

_Bool octopos_mailbox_attest_owner_fast(UINTPTR base);

_Bool octopos_mailbox_attest_quota_limit(UINTPTR base, u16 limit);

_Bool octopos_mailbox_attest_time_limit(UINTPTR base, u16 limit);

_Bool octopos_mailbox_attest_time_limit_lower_bound(UINTPTR base, u16 limit);

void octopos_mailbox_clear_interrupt(UINTPTR base);

void octopos_mailbox_deduct_and_set_owner(UINTPTR base, u8 owner);

#endif /* __ARCH_OCTOPOS_MBOX_H_ */
