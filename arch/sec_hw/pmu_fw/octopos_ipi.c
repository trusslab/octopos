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
#include "octopos_ipi.h"

#include <unistd.h>

#include "../xpfw_default.h"
#include "../xpfw_config.h"
#include "../xpfw_core.h"
#include "../xpfw_events.h"
#include "../xpfw_module.h"

#include "../xpfw_ipi_manager.h"

#define RESP_AND_MSG_NUM_OFFSET		0x1U

#define GPIO_DATA_5_OFFSET                  0XFF0A0054

const XPfw_Module_t *IpiExampleModPtr;

static void PSU_Mask_Write(unsigned long offset, unsigned long mask, unsigned long val)
{
	unsigned long RegVal = 0x0;

	RegVal = Xil_In32(offset);
	RegVal &= ~(mask);
	RegVal |= (val & mask);
	Xil_Out32(offset, RegVal);
}

static void IpiExampleHandler(const XPfw_Module_t *ModPtr, u32 IpiNum, u32 SrcMask, const u32* Payload, u8 Len)
{
	if (IpiNum > 0) {
		xil_printf("PMU: IPI Example Handler: It handles"
				" only IPI on PMU-0\r\n");
	} else {
		xil_printf("PMU: Payload received:\r\n");
		xil_printf("PMU: IPI Message number from payload: 0x%x\r\n",
				Payload[RESP_AND_MSG_NUM_OFFSET]);

		/* Reset through GPIO only available through PMU.
		 * APUs do not have permission to reset according to our isolation setup
		 **/
		PSU_Mask_Write(GPIO_DATA_5_OFFSET, 0x40000000U, 0x40000000U);
		usleep(1);
		PSU_Mask_Write(GPIO_DATA_5_OFFSET, 0x40000000U, 0x00000000U);
		usleep(1);
		PSU_Mask_Write(GPIO_DATA_5_OFFSET, 0x40000000U, 0x40000000U);
		xil_printf("PMU: Reset done");
	}
}

void octopos_ipi_init(void) {
	xil_printf("PMU: IPI INIT BEGIN\r\n");
	IpiExampleModPtr = XPfw_CoreCreateMod();

	(void)XPfw_CoreSetIpiHandler(IpiExampleModPtr, IpiExampleHandler, 0x1EU);
	xil_printf("PMU: IPI INIT DONE\r\n");
}

#endif
