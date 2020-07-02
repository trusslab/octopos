#ifdef ARCH_SEC_HW_PMU

/*
 * Based on https://xilinx-wiki.atlassian.net/wiki/spaces/A/pages/18841941/Zynq+UltraScale+MPSoC+-+IPI+Messaging+Example
 */

/******************************************************************************
 * Copyright (C) 2017 Xilinx, Inc.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * Use of the Software is limited solely to applications:
 * (a) running on a Xilinx device, or
 * (b) that interact with a Xilinx device through a bus or interconnect.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * XILINX  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
 * OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Except as contained in this notice, the name of the Xilinx shall not be used
 * in advertising or otherwise to promote the sale, use or other dealings in
 * this Software without prior written authorization from Xilinx.
 ******************************************************************************/
#include <unistd.h>

#include "octopos_ipi.h"
#include "octopos_pmu_common.h"

#include "../xpfw_default.h"
#include "../xpfw_config.h"
#include "../xpfw_core.h"
#include "../xpfw_events.h"
#include "../xpfw_module.h"
#include "../xpfw_ipi_manager.h"

#define RESP_AND_MSG_NUM_OFFSET		0x1U
#define GPIO_DATA_5_OFFSET          0XFF0A0054

const XPfw_Module_t *IpiExampleModPtr;

static void PSU_Mask_Write(unsigned long offset, unsigned long mask, unsigned long val)
{
	unsigned long RegVal = 0x0;

	RegVal = Xil_In32(offset);
	RegVal &= ~(mask);
	RegVal |= (val & mask);
	Xil_Out32(offset, RegVal);
}

/* Reset through GPIO only available through PMU.
 * APUs do not have permission to reset according to our isolation setup
 **/
static void IpiExampleHandler(const XPfw_Module_t *ModPtr, u32 IpiNum, u32 SrcMask, const u32* Payload, u8 Len)
{
	if (IpiNum > 0) {
		_SEC_HW_ERROR("PMU: IPI Example Handler: It handles"
				" only IPI on PMU-0");
	} else {
		_SEC_HW_DEBUG("PMU: Payload received:");
		_SEC_HW_DEBUG("PMU: IPI Message number from payload: 0x%x",
				Payload[RESP_AND_MSG_NUM_OFFSET]);

		/* This delay is to avoid interrupting any last-minute prints from runtime */
		usleep(10);

		switch(Payload[RESP_AND_MSG_NUM_OFFSET]) {
		case OCTOPOS_PMU_RUNTIME_1:
			_SEC_HW_DEBUG("PMU: Reset request on runtime 1");
			// FIXME change to bit mask, sometimes need to reset more than one runtimes
			PSU_Mask_Write(GPIO_DATA_5_OFFSET, 0xC0000000U, 0xC0000000U);
			usleep(1);
			PSU_Mask_Write(GPIO_DATA_5_OFFSET, 0xC0000000U, 0x00000000U);
			usleep(1);
			PSU_Mask_Write(GPIO_DATA_5_OFFSET, 0xC0000000U, 0xC0000000U);
			_SEC_HW_DEBUG("PMU: Reset done");
			break;
		case OCTOPOS_PMU_RUNTIME_2:
			_SEC_HW_DEBUG("PMU: Reset request on runtime 2");
			PSU_Mask_Write(GPIO_DATA_5_OFFSET, 0x40000000U, 0x40000000U);
			usleep(1);
			PSU_Mask_Write(GPIO_DATA_5_OFFSET, 0x40000000U, 0x00000000U);
			usleep(1);
			PSU_Mask_Write(GPIO_DATA_5_OFFSET, 0x40000000U, 0x40000000U);
			_SEC_HW_DEBUG("PMU: Reset done");
			break;
		default:
			_SEC_HW_ERROR("PMU: Invalid reset target");
			break;
		}
	}
}

void octopos_ipi_init(void) {
	_SEC_HW_DEBUG("PMU: IPI initialize begin");
	IpiExampleModPtr = XPfw_CoreCreateMod();

	(void)XPfw_CoreSetIpiHandler(IpiExampleModPtr, IpiExampleHandler, 0x1EU);
	_SEC_HW_DEBUG("PMU: IPI initialize end");
}

#endif
