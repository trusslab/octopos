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

/***************************** Include Files *********************************/

#include <string.h>
#include "arch/octopos_xmbox.h"
#include "xil_assert.h"

/************************** Constant Definitions *****************************/

/**************************** Type Definitions *******************************/

/***************** Macros (Inline Functions) Definitions *********************/

/************************** Function Prototypes ******************************/

/************************** Variable Definitions *****************************/

/*****************************************************************************/
/**
*
* Initializes a specific mailbox.
*
* @param	InstancePtr is a pointer to the OCTOPOS_XMbox instance to be worked on.
* @param	CfgPtr is the device configuration structure containing
*		required HW build data.
* @param	EffectiveAddr is the Physical address of the hardware in a
*		Virtual Memory operating system environment. It is the Base
*		Address in a stand alone environment.
*
* @return
*		- XST_SUCCESS if initialization was successful
*
* @note		None.
*
******************************************************************************/
int OCTOPOS_XMbox_CfgInitialize(OCTOPOS_XMbox *InstancePtr, OCTOPOS_XMbox_Config *ConfigPtr,
			UINTPTR EffectiveAddress)
{

	Xil_AssertNonvoid(InstancePtr != NULL);
	Xil_AssertNonvoid(ConfigPtr != NULL);

	/*
	 * Clear instance memory and make copy of configuration
	 */
	memset(InstancePtr, 0, sizeof(OCTOPOS_XMbox));
	memcpy(&InstancePtr->Config, ConfigPtr, sizeof(OCTOPOS_XMbox_Config));

	InstancePtr->Config.BaseAddress = EffectiveAddress;
	InstancePtr->IsReady = XIL_COMPONENT_IS_READY;

	return XST_SUCCESS;
}

/*****************************************************************************/
/**
*
* Reads requested bytes from the mailbox referenced by InstancePtr,into the
* buffer pointed to by the provided pointer. The number of bytes must be a
* multiple of 4 (bytes). If not, the call will fail in an assert.
*
* This function is non blocking.
*
* @param	InstancePtr is a pointer to the OCTOPOS_XMbox instance to be worked on.
* @param	BufferPtr is the buffer to read the mailbox contents into,
*		aligned to a word boundary.
* @param	RequestedBytes is the number of bytes of data requested.
* @param	BytesRecvdPtr is the memory that is updated with the number of
*		bytes of data actually read.
*
* @return
*		- XST_SUCCESS on success.
*		- XST_NO_DATA ifthere was no data in the mailbox.
*
* On success, the number of bytes read is returned through the pointer.  The
* call may return with fewer bytes placed in the buffer than requested  (not
* including zero). This is not necessarily an error condition and indicates
* the amount of data that was currently available in the mailbox.
*
* @note		None.
*
******************************************************************************/
int OCTOPOS_XMbox_Read(OCTOPOS_XMbox *InstancePtr, u32 *BufferPtr, u32 RequestedBytes,
			u32 *BytesRecvdPtr)
{
	u32 NumBytes;

	Xil_AssertNonvoid(InstancePtr != NULL);
	Xil_AssertNonvoid(!((u32) BufferPtr & 0x3));
	Xil_AssertNonvoid(RequestedBytes != 0);
	Xil_AssertNonvoid((RequestedBytes %4) == 0);
	Xil_AssertNonvoid(BytesRecvdPtr != NULL);

	NumBytes = 0;

	if (InstancePtr->Config.UseFSL == 0) {
		/* For memory mapped IO */
		if (OCTOPOS_XMbox_IsEmptyHw(InstancePtr->Config.BaseAddress))
			return XST_NO_DATA;

		/*
		 * Read the Mailbox until empty or the length requested is
		 * satisfied
		 */
		do {
			*BufferPtr++ =
				OCTOPOS_XMbox_ReadMBox(InstancePtr->Config.BaseAddress);
			NumBytes += 4;
		} while ((NumBytes != RequestedBytes) &&
			 !(OCTOPOS_XMbox_IsEmptyHw(InstancePtr->Config.BaseAddress)));

		*BytesRecvdPtr = NumBytes;
	} else {

		/* FSL based Access */
		if (OCTOPOS_XMbox_FSLIsEmpty(InstancePtr->Config.RecvID))
			return XST_NO_DATA;

		/*
		 * Read the Mailbox until empty or the length requested is
		 * satisfied
		 */
		do {
			*BufferPtr++ =
				OCTOPOS_XMbox_FSLReadMBox(InstancePtr->Config.RecvID);
			NumBytes += 4;
		} while ((NumBytes != RequestedBytes) &&
			 !(OCTOPOS_XMbox_FSLIsEmpty(InstancePtr->Config.RecvID)));

		*BytesRecvdPtr = NumBytes;
	}

	return XST_SUCCESS;
}

/*****************************************************************************/
/**
*
* Reads requested bytes from the mailbox referenced by InstancePtr,into the
* buffer pointed to by the provided pointer. The number of bytes must be a
* multiple of 4 (bytes). If not, the call will fail in an assert.
*
* @param	InstancePtr is a pointer to the OCTOPOS_XMbox instance to be worked on.
* @param	BufferPtr is the buffer to read the mailbox contents into,
*		aligned to a word boundary.
* @param	RequestedBytes is the number of bytes of data requested.
*
* @return	None.
*
* @note		The call blocks until the number of bytes requested are
*		available.
*
******************************************************************************/
void OCTOPOS_XMbox_ReadBlocking(OCTOPOS_XMbox *InstancePtr, u32 *BufferPtr,
			u32 RequestedBytes)
{
	u32 NumBytes;

	Xil_AssertVoid(InstancePtr != NULL);
	Xil_AssertVoid(!((u32) BufferPtr & 0x3));
	Xil_AssertVoid(RequestedBytes != 0);
	Xil_AssertVoid((RequestedBytes % 4) == 0);

	NumBytes = 0;

	if (InstancePtr->Config.UseFSL == 0) {
		/* For memory mapped IO */
		/* Block while the mailbox FIFO has at-least some data */

		do {
			while(OCTOPOS_XMbox_IsEmptyHw(InstancePtr->Config.BaseAddress));

			/*
			 * Read the Mailbox until empty or the length
			 * requested is satisfied
			 */
			*BufferPtr++ =
				OCTOPOS_XMbox_ReadMBox(InstancePtr->Config.BaseAddress);
			NumBytes += 4;
		} while (NumBytes != RequestedBytes);
	} else {

		/* FSL based Access */
		/* Block while the mailbox FIFO has at-least some data */

		do {
			while (OCTOPOS_XMbox_FSLIsEmpty(InstancePtr->Config.RecvID));

			/*
			 * Read the Mailbox until empty or the length requested
			 * is satisfied
			 */

			*BufferPtr++ =
				OCTOPOS_XMbox_FSLReadMBox(InstancePtr->Config.RecvID);
			NumBytes += 4;
		} while (NumBytes != RequestedBytes);
	}
}

/*****************************************************************************/
/**
* Writes the requested bytes from the buffer pointed to by the provided
* pointer into the mailbox referenced by InstancePtr.The number of bytes must
* be a multiple of 4 (bytes). If not, the call will fail in an assert.
*
* This function is non blocking.
*
* @param	InstancePtr is a pointer to the OCTOPOS_XMbox instance to be worked on.
* @param	BufferPtr is the source data buffer, aligned to a word
*		boundary.
* @param	RequestedBytes is the number of bytes requested to be written.
* @param	BytesRecvdPtr points to memory which is updated with the actual
*		number of bytes written, return value.
* @return
*
*		- XST_SUCCESS on success.
*		- XST_FIFO_NO_ROOM if the fifo was full.

* On success, the number of bytes successfully written into the destination
* mailbox is returned in the provided pointer. The call may  return with
* zero. This is not necessarily an error condition and indicates that the
* mailbox is currently full.
*
* @note		The provided buffer pointed to by BufferPtr must be aligned to a
*		word boundary.
*
******************************************************************************/
int OCTOPOS_XMbox_Write(OCTOPOS_XMbox *InstancePtr, u32 *BufferPtr, u32 RequestedBytes,
		u32 *BytesSentPtr)
{
	u32 NumBytes;

	Xil_AssertNonvoid(InstancePtr != NULL);
	Xil_AssertNonvoid(!((u32) BufferPtr & 0x3));
	Xil_AssertNonvoid(RequestedBytes != 0);
	Xil_AssertNonvoid((RequestedBytes %4) == 0);
	Xil_AssertNonvoid(BytesSentPtr != NULL);

	NumBytes = 0;

	if (InstancePtr->Config.UseFSL == 0) {
		/* For memory mapped IO */

		if (OCTOPOS_XMbox_IsFullHw(InstancePtr->Config.BaseAddress)) {
			return XST_FIFO_NO_ROOM;
		}

		/*
		 * Write to the Mailbox until full or the length requested is
		 * satisfied.
		 */

		do {
			OCTOPOS_XMbox_WriteMBox(InstancePtr->Config.BaseAddress,
					*BufferPtr++);
			NumBytes += 4;
		} while ((NumBytes != RequestedBytes) &&
			 !(OCTOPOS_XMbox_IsFullHw(InstancePtr->Config.BaseAddress)));

		*BytesSentPtr = NumBytes;
	} else {

		/* FSL based Access */
		if (OCTOPOS_XMbox_FSLIsFull(InstancePtr->Config.SendID)) {
			return XST_FIFO_NO_ROOM;
		}

		/*
		 * Write to the Mailbox until full or the length requested is
		 * satisfied.
		 */
		do {
			OCTOPOS_XMbox_FSLWriteMBox(InstancePtr->Config.SendID,
					    *BufferPtr++);
			NumBytes += 4;
		} while ((NumBytes != RequestedBytes) &&
			 !(OCTOPOS_XMbox_FSLIsFull(InstancePtr->Config.SendID)));

		*BytesSentPtr = NumBytes;
	}

	return XST_SUCCESS;
}

/*****************************************************************************/
/**
* Writes the requested bytes from the buffer pointed to by the provided
* pointer into the mailbox referenced by InstancePtr. The number of bytes must
* be a multiple of 4 (bytes). If not, the call will fail in an assert.
*
* @param	InstancePtr is a pointer to the OCTOPOS_XMbox instance to be worked on.
* @param	BufferPtr is the source data buffer, aligned to a word boundary.
* @param	RequestedBytes is the number of bytes requested to be written.
*
* @return	None.
*
* @note		The call blocks until the number of bytes requested are written.
*		The provided buffer pointed to by BufferPtr must be aligned to a
*		word boundary.
*
******************************************************************************/
void OCTOPOS_XMbox_WriteBlocking(OCTOPOS_XMbox *InstancePtr, u32 *BufferPtr, u32 RequestedBytes)
{
	u32 NumBytes;

	Xil_AssertVoid(InstancePtr != NULL);
	Xil_AssertVoid(!((u32) BufferPtr & 0x3));
	Xil_AssertVoid(RequestedBytes != 0);
	Xil_AssertVoid((RequestedBytes %4) == 0);

	NumBytes = 0;

	if (InstancePtr->Config.UseFSL == 0) {
		/* For memory mapped IO */
		/* Block while the mailbox FIFO becomes free to transfer
		 * at-least one word
		 */
		do {
			while (OCTOPOS_XMbox_IsFullHw(InstancePtr->Config.BaseAddress));

			OCTOPOS_XMbox_WriteMBox(InstancePtr->Config.BaseAddress,
					 *BufferPtr++);
			NumBytes += 4;
		} while (NumBytes != RequestedBytes);
	} else {

		/* FSL based Access */
		/* Block while the mailbox FIFO becomes free to transfer
		 * at-least one word
		 */
		do {
			while (OCTOPOS_XMbox_FSLIsFull(InstancePtr->Config.SendID));

			OCTOPOS_XMbox_FSLWriteMBox(InstancePtr->Config.SendID,
					    *BufferPtr++);
			NumBytes += 4;
		} while (NumBytes != RequestedBytes);
	}
}

/*****************************************************************************/
/**
*
* Checks to see if there is data available to be read.
*
* @param	InstancePtr is a pointer to the OCTOPOS_XMbox instance to be worked on.
*
* @return
*		- FALSE if there is data to be read.
*		- TRUE is there no data to be read.
*
* @note		None.
*
******************************************************************************/
u32 OCTOPOS_XMbox_IsEmpty(OCTOPOS_XMbox *InstancePtr)
{
	Xil_AssertNonvoid(InstancePtr != NULL);

	if (InstancePtr->Config.UseFSL == 0) {
		/* For memory mapped IO */
		return (OCTOPOS_XMbox_IsEmptyHw(InstancePtr->Config.BaseAddress));
	} else {
		/* FSL based Access */
		return (OCTOPOS_XMbox_FSLIsEmpty(InstancePtr->Config.RecvID));
	}
}

/*****************************************************************************/
/**
*
* Checks to see if there is room in the write FIFO.
*
* @param	InstancePtr is a pointer to the OCTOPOS_XMbox instance to be worked on.
*
* @return
*		- FALSE if there is room in write FIFO.
*		- TRUE if there is room in write FIFO.
*
* @note		None.
*
******************************************************************************/
u32 OCTOPOS_XMbox_IsFull(OCTOPOS_XMbox *InstancePtr)
{
	Xil_AssertNonvoid(InstancePtr != NULL);

	if (InstancePtr->Config.UseFSL == 0) {
		/* For memory mapped IO */
		return (OCTOPOS_XMbox_IsFullHw(InstancePtr->Config.BaseAddress));
	} else {
		/* FSL based Access */
		return (OCTOPOS_XMbox_FSLIsFull(InstancePtr->Config.SendID));
	}
}

/*****************************************************************************/
/**
*
* Resets the mailbox FIFOs by emptying the READ FIFO and making sure the
* Error Status is zero.
*
* @param	InstancePtr is a pointer to the OCTOPOS_XMbox instance to be worked on.
*
* @return
*		- XST_SUCCESS on success.
*		- XST_FAILURE if there are any outstanding errors.
*
* @note		Data from read FIFO is thrown away.
*
******************************************************************************/
int OCTOPOS_XMbox_Flush(OCTOPOS_XMbox *InstancePtr)
{
	Xil_AssertNonvoid(InstancePtr != NULL);

	if (InstancePtr->Config.UseFSL == 0) {
		/* For memory mapped IO */
		do {
			(void)OCTOPOS_XMbox_ReadMBox(InstancePtr->Config.BaseAddress);
		} while (!(OCTOPOS_XMbox_IsEmptyHw(InstancePtr->Config.BaseAddress)));

	} else {
		/* FSL based Access */
		do {
			(void) OCTOPOS_XMbox_FSLReadMBox(InstancePtr->Config.RecvID);
		} while (!(OCTOPOS_XMbox_FSLIsEmpty(InstancePtr->Config.RecvID)));
	}

	return XST_SUCCESS;
}

/*****************************************************************************/
/**
*
* Resets the mailbox FIFOs by clearing the READ and WRITE FIFOs using the
* hardware control register for memory mapped IO.
*
* @param	InstancePtr is a pointer to the OCTOPOS_XMbox instance to be worked on.
*
* @return	None.
*
* @note		Use OCTOPOS_XMbox_Flush instead for FSL based access.
*
******************************************************************************/
void OCTOPOS_XMbox_ResetFifos(OCTOPOS_XMbox *InstancePtr)
{
	Xil_AssertVoid(InstancePtr != NULL);
	Xil_AssertVoid(InstancePtr->Config.UseFSL == 0);

	/* For memory mapped IO:
	 *
	 * Write to the control register to reset both send and
	 * receive FIFOs, these bits are self-clearing such that
	 * there's no need to clear them.
	 */
	OCTOPOS_XMbox_WriteReg(InstancePtr->Config.BaseAddress,
		       OCTOPOS_XMB_CTRL_REG_OFFSET,
			   OCTOPOS_XMB_CTRL_RESET_SEND_FIFO |
			   OCTOPOS_XMB_CTRL_RESET_RECV_FIFO);
}

/*****************************************************************************/
/**
* Sets the interrupt enable register for this mailbox. This function can only
* be used for Non-FSL interface. If not, the function will fail in an assert.
*
* @param	InstancePtr is a pointer to the instance to be worked on.
* @param	Mask is a logical OR of XMB_IX_* constants found in xmbox_hw.h.
*
* @return	None.
*
* @note		None.
*
******************************************************************************/
void OCTOPOS_XMbox_SetInterruptEnable(OCTOPOS_XMbox *InstancePtr, u32 Mask)
{
	Xil_AssertVoid(InstancePtr != NULL);
	Xil_AssertVoid(InstancePtr->Config.UseFSL == 0);

	if (InstancePtr->Config.UseFSL == 0)
		OCTOPOS_XMbox_WriteReg(InstancePtr->Config.BaseAddress,
				OCTOPOS_XMB_IE_REG_OFFSET,
			       Mask);
}

/*****************************************************************************/
/**
* Retrieves the interrupt enable for the mailbox. AND the result of this
* function with XMB_IX_* to determine which interrupts of this mailbox
* are enabled. This function can only be used for Non-FSL interface. If not,
* the function will fail in an assert.
*
* @param	InstancePtr is a pointer to the instance to be worked on.
*
* @return	Mask of interrupt bits made up of XMB_IX_* constants found
*		in xmbox_hw.h.
*
* @note		None.
*
*
******************************************************************************/
u32 OCTOPOS_XMbox_GetInterruptEnable(OCTOPOS_XMbox *InstancePtr)
{
	Xil_AssertNonvoid(InstancePtr != NULL);
	Xil_AssertNonvoid(InstancePtr->Config.UseFSL == 0);

	return OCTOPOS_XMbox_ReadReg(InstancePtr->Config.BaseAddress,
			OCTOPOS_XMB_IE_REG_OFFSET);
}

/*****************************************************************************/
/**
* Retrieve the interrupt status for the mailbox. AND the results of this
* function with XMB_IX_* to determine which interrupts are currently pending
* to the processor. This function can only be used for Non-FSL interface.
* If not, the function will fail in an assert.
*
* @param	InstancePtr is a pointer to the instance to be worked on.
*
* @return	Mask of interrupt bits made up of XMB_IX_* constants found
*		in xmbox_hw.h.
*
******************************************************************************/
u32 OCTOPOS_XMbox_GetInterruptStatus(OCTOPOS_XMbox *InstancePtr)
{
	Xil_AssertNonvoid(InstancePtr != NULL);
	Xil_AssertNonvoid(InstancePtr->Config.UseFSL == 0);

	return OCTOPOS_XMbox_ReadReg(InstancePtr->Config.BaseAddress,
			OCTOPOS_XMB_IS_REG_OFFSET);
}

/*****************************************************************************/
/**
* Clears pending interrupts with the provided mask. This function should be
* called after the software has serviced the interrupts that are pending.
* This function clears the corresponding bits of the Interrupt Status
* Register. This function can only be used for Non-FSL interface. If not, the
* function will fail in an assert.
*
* @param	InstancePtr is a pointer to the instance to be worked on.
* @param	Mask is a logical OR of XMB_IX_* constants found in
*		xmbox_hw.h.
*
* @note		None.
*
******************************************************************************/
void OCTOPOS_XMbox_ClearInterrupt(OCTOPOS_XMbox *InstancePtr, u32 Mask)
{
	Xil_AssertVoid(InstancePtr != NULL);
	Xil_AssertVoid(InstancePtr->Config.UseFSL == 0);

	if (InstancePtr->Config.UseFSL == 0) {
		OCTOPOS_XMbox_WriteReg(InstancePtr->Config.BaseAddress,
				OCTOPOS_XMB_IS_REG_OFFSET,
				Mask);
	}
}

/*****************************************************************************/
/**
* Sets the Send Interrupt Threshold. This function can only be used for
* Non-FSL interface. If not, the function will fail in an assert.
*
* @param	InstancePtr is a pointer to the instance to be worked on.
* @param	Value is a value to set for the SIT. Only lower
*		Log2(FIFO Depth) bits are used.
*
* @return	None.
*
* @note		None.
*
******************************************************************************/
void OCTOPOS_XMbox_SetSendThreshold(OCTOPOS_XMbox *InstancePtr, u32 Value)
{
	Xil_AssertVoid(InstancePtr != NULL);
	Xil_AssertVoid(InstancePtr->Config.UseFSL == 0);

	if (InstancePtr->Config.UseFSL == 0) {
		OCTOPOS_XMbox_WriteReg(InstancePtr->Config.BaseAddress,
				OCTOPOS_XMB_SIT_REG_OFFSET,
				Value);
	}
}

/*****************************************************************************/
/**
* Set the Receive Interrupt Threshold. This function can only be used for
* Non-FSL interface. If not, the function will fail in an assert.
* @param	InstancePtr is a pointer to the instance to be worked on.
* @param	Value is a value to set for the RIT. Only lower
*		Log2(FIFO Depth) bits are used.
*
* @return	None.
*
* @note		None.
*
******************************************************************************/
void OCTOPOS_XMbox_SetReceiveThreshold(OCTOPOS_XMbox *InstancePtr, u32 Value)
{
	Xil_AssertVoid(InstancePtr != NULL);
	Xil_AssertVoid(InstancePtr->Config.UseFSL == 0);

	if (InstancePtr->Config.UseFSL == 0) {
		OCTOPOS_XMbox_WriteReg(InstancePtr->Config.BaseAddress,
				OCTOPOS_XMB_RIT_REG_OFFSET,
				Value);
	}
}

/*****************************************************************************/
/**
* Returns Status register contents. This function can only be used for
* Non-FSL interface. If not, the function will fail in an assert.
* @param	InstancePtr is a pointer to the instance to be worked on.
*
* @return	Value returns Status Register contents.
*
* @note		None.
*
******************************************************************************/
u32 OCTOPOS_XMbox_GetStatus(OCTOPOS_XMbox *InstancePtr)
{
	u32 Value;
	Xil_AssertNonvoid(InstancePtr != NULL);
	Xil_AssertNonvoid(InstancePtr->Config.UseFSL == 0);


	Value = OCTOPOS_XMbox_ReadReg(InstancePtr->Config.BaseAddress,
			OCTOPOS_XMB_STATUS_REG_OFFSET);
	return Value;

}
/** @} */
