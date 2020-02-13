#ifndef __ARCH_OCTOPOS_MBOX_H_
#define __ARCH_OCTOPOS_MBOX_H_

u32 OWNER_MASK 	= 0x00FFFFFF;
u32 QUOTA_MASK 	= 0xFF000FFF;
u32 TIME_MASK 	= 0xFFFFF000;

u32 octopos_mailbox_get_status_reg(UINTPTR base);

void octopos_mailbox_set_status_reg(UINTPTR base, u32 value);

u8 octopos_mailbox_get_owner(UINTPTR base);

void octopos_mailbox_set_owner(UINTPTR base, u8 owner);

u8 octopos_mailbox_get_quota_limit(UINTPTR base);

void octopos_mailbox_set_quota_limit(UINTPTR base, u16 limit);

u8 octopos_mailbox_get_time_limit(UINTPTR base);

void octopos_mailbox_set_time_limit(UINTPTR base, u16 limit);

#endif /* __ARCH_OCTOPOS_MBOX_H_ */
