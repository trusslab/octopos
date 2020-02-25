#ifndef __ARCH_OCTOPOS_MBOX_H_
#define __ARCH_OCTOPOS_MBOX_H_

#define OWNER_MASK (u32) 0x00FFFFFF
#define QUOTA_MASK (u32) 0xFF000FFF
#define TIME_MASK  (u32) 0xFFFFF000

#define MAX_OCTOPOS_MAILBOX_QUOTE 4094

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

_Bool octopos_mailbox_attest_quota_limit(UINTPTR base, u16 limit);

_Bool octopos_mailbox_attest_time_limit(UINTPTR base, u16 limit);

#endif /* __ARCH_OCTOPOS_MBOX_H_ */
