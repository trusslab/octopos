/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef SRC_ARCH_OCTOPOS_PMU_COMMON_H_
#define SRC_ARCH_OCTOPOS_PMU_COMMON_H_

#define _SEC_HW_ERROR(fmt, ...)										\
	do {xil_printf("--ERROR: %-20.20s: " fmt "\r\n", __FUNCTION__,	\
			##__VA_ARGS__);} while (0)

#define _SEC_HW_WARNING(fmt, ...)									\
	do {xil_printf("--WARNING: %-20.20s: " fmt "\r\n", __FUNCTION__,\
			##__VA_ARGS__);} while (0)

#define _SEC_HW_INFO(fmt, ...)										\
	do {xil_printf("--INFO: %-20.20s: " fmt "\r\n", __FUNCTION__,	\
			##__VA_ARGS__);} while (0)

//#define _SEC_HW_DEBUG(fmt, ...)                                     \
//    do {xil_printf("--DEBUG: %-20.20s %-20.20s #%-5i: " fmt "\r\n", \
//            __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);} while (0)

#define _SEC_HW_DEBUG(fmt, ...)

#define OCTOPOS_PMU_RUNTIME_1 0x01
#define OCTOPOS_PMU_RUNTIME_2 0x02

#endif /* SRC_ARCH_OCTOPOS_PMU_COMMON_H_ */
