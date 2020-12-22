/******************************************************************************
*
* Copyright (C) 2007 - 2017 Xilinx, Inc.  All rights reserved.
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
*
******************************************************************************/

#ifndef OCTOPOS_XMBOX_H			/* prevent circular inclusions */
#define OCTOPOS_XMBOX_H			/* by using protection macros */

#ifdef __cplusplus
extern "C" {
#endif

/***************************** Include Files *********************************/

#include "xstatus.h"
#include "octopos_xmbox_hw.h"

/************************** Constant Definitions *****************************/

/**************************** Type Definitions *******************************/

/**
 * This typedef contains configuration information for the device.
 */
typedef struct {
	u16 DeviceId;		/**< Unique ID of device */
	UINTPTR BaseAddress;	/**< Register base address */
	u8 UseFSL;		/**< use the FSL for the interface. */
	u8 SendID;		/**< FSL link for the write i/f mailbox. */
	u8 RecvID;		/**< FSL link for the read i/f mailbox. */

} OCTOPOS_XMbox_Config;

/**
 * The XMbox driver instance data. The user is required to allocate a
 * variable of this type for every mbox device in the system. A
 * pointer to a variable of this type is then passed to the driver API
 * functions.
 */
typedef struct {
	OCTOPOS_XMbox_Config Config;	/**< Configuration data, includes base address
				  */
	u32 IsReady;		/**< Device is initialized and ready */
} OCTOPOS_XMbox;

/***************** Macros (Inline Functions) Definitions *********************/

/************************** Function Prototypes ******************************/

/*
 * Required functions, in file xmbox.c
 */
int OCTOPOS_XMbox_CfgInitialize(OCTOPOS_XMbox *InstancePtr, OCTOPOS_XMbox_Config *ConfigPtr,
			UINTPTR EffectiveAddress);
int OCTOPOS_XMbox_Read(OCTOPOS_XMbox *InstancePtr, u32 *BufferPtr, u32 RequestedBytes,
			u32 *BytesRecvdPtr);
void OCTOPOS_XMbox_ReadBlocking(OCTOPOS_XMbox *InstancePtr, u32 *BufferPtr,
			u32 RequestedBytes);
int OCTOPOS_XMbox_Write(OCTOPOS_XMbox *InstancePtr, u32 *BufferPtr, u32 RequestedBytes,
		u32 *BytesSentPtr);
void OCTOPOS_XMbox_WriteBlocking(OCTOPOS_XMbox *InstancePtr, u32 *BufferPtr,
			 u32 RequestedBytes);
u32 OCTOPOS_XMbox_IsEmpty(OCTOPOS_XMbox *InstancePtr);
u32 OCTOPOS_XMbox_IsFull(OCTOPOS_XMbox *InstancePtr);
int OCTOPOS_XMbox_Flush(OCTOPOS_XMbox *InstancePtr);
void OCTOPOS_XMbox_ResetFifos(OCTOPOS_XMbox *InstancePtr);
void OCTOPOS_XMbox_SetInterruptEnable(OCTOPOS_XMbox *InstancePtr, u32 Mask);
u32 OCTOPOS_XMbox_GetInterruptEnable(OCTOPOS_XMbox *InstancePtr);
u32 OCTOPOS_XMbox_GetInterruptStatus(OCTOPOS_XMbox *InstancePtr);
void OCTOPOS_XMbox_ClearInterrupt(OCTOPOS_XMbox *InstancePtr, u32 Mask);
u32 OCTOPOS_XMbox_GetStatus(OCTOPOS_XMbox *InstancePtr);
void OCTOPOS_XMbox_SetSendThreshold(OCTOPOS_XMbox *InstancePtr, u32 Value);
void OCTOPOS_XMbox_SetReceiveThreshold(OCTOPOS_XMbox *InstancePtr, u32 Value);

/*
 * Static initialization function, in file xmbox_sinit.c
 */
OCTOPOS_XMbox_Config *OCTOPOS_XMbox_LookupConfig(u16 DeviceId);

#ifdef __cplusplus
}
#endif

#endif /* end of protection macro */
/** @} */
