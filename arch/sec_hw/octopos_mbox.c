#include <string.h>

#include "xstatus.h"
#include "xil_io.h"

#include "arch/sec_hw.h"
#include "arch/octopos_mbox.h"

#define OCTOPOS_MAILBOX_INTR_OFFSET 4

/* "unitsleep: rsub %1, r11, %1" <- 1 clk cycle */
/* "nop                        " <- 1 clk cycle */
/* "bnei %1, unitsleep         " <- 3 clk cycle */	
void octopos_usleep(u32 usecs)
{
    asm(
		"addik r11, r0, 1             \n\t"
		"nextsleep: rsub %0, r11, %0  \n\t"
		"unitsleep: rsub %1, r11, %1  \n\t"
		"nop                          \n\t"
		"bnei %1, unitsleep           \n\t"
		"add %1, r0, %2               \n\t"
		"bnei %0, nextsleep           \n\t"
		: 
		: "r"(usecs), 
		"r"(CPU_SPEED_IN_MHZ / 5), 
		"r"(CPU_SPEED_IN_MHZ / 5)
		: "r11"
    );
}

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

void octopos_mailbox_deduct_and_set_owner(UINTPTR base, u8 owner)
{
	Xil_AssertVoid(base != 0);

/* Old mailbox hardware code
 * 	
 * Temporary owner of the mailbox cannot delegate full quota to another
 * owner (or switch back to the OS). So we must take one off from the
 * read limit and time limit quotas.
 */

/*
	u32 reg = octopos_mailbox_get_status_reg(base) - 0x1001;
	reg = (OWNER_MASK & reg) | owner << 24;
*/
	
	u32 reg = 0xFF000000;
	
	octopos_mailbox_set_status_reg(base, reg);
}

u16 octopos_mailbox_get_quota_limit(UINTPTR base)
{
	Xil_AssertNonvoid(base != 0);

	return (u16) (octopos_mailbox_get_status_reg(base) >> 12 & 0xfff);
}

void octopos_mailbox_set_quota_limit(UINTPTR base, u16 limit)
{
	Xil_AssertVoid(base != 0);

	u32 reg = octopos_mailbox_get_status_reg(base);
	reg = (QUOTA_MASK & reg) | limit << 12;

	octopos_mailbox_set_status_reg(base, reg);
}

u16 octopos_mailbox_get_time_limit(UINTPTR base)
{
	Xil_AssertNonvoid(base != 0);

	return (u16) (octopos_mailbox_get_status_reg(base) & 0xfff);
}

void octopos_mailbox_set_time_limit(UINTPTR base, u16 limit)
{
	Xil_AssertVoid(base != 0);

	u32 reg = octopos_mailbox_get_status_reg(base);
	reg = (TIME_MASK & reg) | limit;

	octopos_mailbox_set_status_reg(base, reg);
}

_Bool octopos_mailbox_attest_owner(UINTPTR base, u8 owner)
{
	Xil_AssertNonvoid(base != 0);

	_SEC_HW_DEBUG("%08x: %08x", base, octopos_mailbox_get_status_reg(base));
	return owner == (u8) (octopos_mailbox_get_status_reg(base) >> 24 & 0xff);
}

_Bool octopos_mailbox_attest_owner_fast(UINTPTR base)
{
	Xil_AssertNonvoid(base != 0);

	_SEC_HW_DEBUG("%08x: %08x", base, octopos_mailbox_get_status_reg(base));
	return 0xDEAFBEEF != octopos_mailbox_get_status_reg(base);
}

_Bool octopos_mailbox_attest_quota_limit(UINTPTR base, u16 limit)
{
	Xil_AssertNonvoid(base != 0);

	_SEC_HW_DEBUG("%08x: %08x", base, octopos_mailbox_get_status_reg(base));
	return limit == (u16) (octopos_mailbox_get_status_reg(base) >> 12 & 0xfff);
}

_Bool octopos_mailbox_attest_time_limit(UINTPTR base, u16 limit)
{
	Xil_AssertNonvoid(base != 0);

	_SEC_HW_DEBUG("%08x: %08x", base, octopos_mailbox_get_status_reg(base));
	return limit == (u16) (octopos_mailbox_get_status_reg(base) & 0xfff);
}

_Bool octopos_mailbox_attest_time_limit_lower_bound(UINTPTR base, u16 limit)
{
	Xil_AssertNonvoid(base != 0);

	_SEC_HW_DEBUG("%08x: %08x", base, octopos_mailbox_get_status_reg(base));
	return limit <= (u16) (octopos_mailbox_get_status_reg(base) & 0xfff);
}

void octopos_mailbox_clear_interrupt(UINTPTR base)
{
	Xil_AssertVoid(base != 0);

	Xil_Out32(base + OCTOPOS_MAILBOX_INTR_OFFSET, 1);
}
