/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifdef ARCH_SEC_HW_NETWORK

/*******************************************************************
*
* CAUTION: This file is automatically generated by HSI.
* Version: 2020.1
* DO NOT EDIT.
*
* Copyright (C) 2010-2021 Xilinx, Inc. All Rights Reserved.
* SPDX-License-Identifier: MIT 

* 
* Description: Driver configuration
*
*******************************************************************/

#include "xparameters.h"
#include "xllfifo.h"

/*
* The configuration table for devices
*/

XLlFifo_Config XLlFifo_ConfigTable[] =
{
	{
		XPAR_AXI_FIFO_0_DEVICE_ID,
		XPAR_AXI_FIFO_0_BASEADDR,
		XPAR_AXI_FIFO_0_AXI4_BASEADDR,
		XPAR_AXI_FIFO_0_DATA_INTERFACE_TYPE
	}
};

#endif /* ARCH_SEC_HW_NETWORK */
