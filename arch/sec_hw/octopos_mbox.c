#include <string.h>

#include "xstatus.h"
#include "xil_io.h"

#include "arch/sec_hw.h"
#include "arch/octopos_mbox.h"

u32 octopos_mailbox_get_status_reg(UINTPTR base)
{
	Xil_AssertNonvoid(base != 0);

	return Xil_In32(base);
}

void octopos_mailbox_set_status_reg(UINTPTR base, u32 value)
{
	Xil_AssertVoid(base != 0);

	Xil_Out32(base, value);
}

u8 octopos_mailbox_get_owner(UINTPTR base)
{
	Xil_AssertNonvoid(base != 0);

	return (u8) (octopos_mailbox_get_status_reg(base) >> 24 & 0xff);
}

void octopos_mailbox_set_owner(UINTPTR base, u8 owner)
{
	Xil_AssertVoid(base != 0);

	u32 reg = octopos_mailbox_get_status_reg(base);
	reg = (OWNER_MASK & reg) | owner << 24;

	octopos_mailbox_set_status_reg(base, reg);
}

u8 octopos_mailbox_get_quota_limit(UINTPTR base)
{
	Xil_AssertNonvoid(base != 0);

	return (u8) (octopos_mailbox_get_status_reg(base) >> 12 & 0xfff);
}

void octopos_mailbox_set_quota_limit(UINTPTR base, u16 limit)
{
	Xil_AssertVoid(base != 0);

	u32 reg = octopos_mailbox_get_status_reg(base);
	reg = (QUOTA_MASK & reg) | limit << 12;

	octopos_mailbox_set_status_reg(base, reg);
}

u8 octopos_mailbox_get_time_limit(UINTPTR base)
{
	Xil_AssertNonvoid(base != 0);

	return (u8) (octopos_mailbox_get_status_reg(base) & 0xfff);
}

void octopos_mailbox_set_time_limit(UINTPTR base, u16 limit)
{
	Xil_AssertVoid(base != 0);

	u32 reg = octopos_mailbox_get_status_reg(base);
	reg = (TIME_MASK & reg) | limit;

	octopos_mailbox_set_status_reg(base, reg);
}

