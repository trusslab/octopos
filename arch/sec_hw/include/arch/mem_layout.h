/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __SEC_HW_RAM_LAYOUT_H
#define __SEC_HW_RAM_LAYOUT_H

/* memory layout must be known by bootloaders, so
 * that they can erase the DDR memory before loading
 * binary onto the memory.
 */
#define ROM_FUSE1 0xFF800000
#define ROM_FUSE2 0xFF810000
#define FUSE_BURN_VALUE 0xDEADDEAD

#define RESET_MODULE_ENCLAVE0 0xF1900000
#define RESET_MODULE_ENCLAVE1 0xF1910000
#define RESET_MODULE_ETHERNET 0xF1920000
#define RESET_MODULE_KEYBOARD 0xF1930000
#define RESET_MODULE_SERIALOUT 0xF1940000
#define RESET_MODULE_STORAGE 0xF1950000

#define RESET_BURN_VALUE_1 0xDEADBEEF
#define RESET_BURN_VALUE_2 0xDEADDEAD
#define RESET_WAIT_CYCLE 100
#define RESET_STATUS_SUCCESS 0xAAAA
#define RESET_STATUS_FAILED 0xFFFF

/* RAM_RANGE = total RAM size - common stack/heap size */
#ifdef ARCH_SEC_HW_BOOT_STORAGE
#define RAM_BASE_ADDRESS 0x40000
#define RAM_TOTAL_SIZE 0x3c000
#define BOOT_STACK_HEAP_SIZE 0x3fb0
#define BOOT_STATUS_REG 0x7FFE0
#define BOOT_RESET_REG 0x7FFB0
#define BOOT_COUNTER_REG 0x7FFE4

#elif defined(ARCH_SEC_HW_BOOT_KEYBOARD)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_TOTAL_SIZE 0x1c000
#define BOOT_STACK_HEAP_SIZE 0x3fb0
#define BOOT_STATUS_REG 0x13FFE0
#define BOOT_RESET_REG 0x13FFB0

#elif defined(ARCH_SEC_HW_BOOT_SERIAL_OUT)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_TOTAL_SIZE 0x1c000
#define BOOT_STACK_HEAP_SIZE 0x3fb0
#define BOOT_STATUS_REG 0x13FFE0
#define BOOT_RESET_REG 0x13FFB0

#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_1)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_TOTAL_SIZE 0x3c000
#define BOOT_STACK_HEAP_SIZE 0x3fb0
#define BOOT_STATUS_REG 0x15FFE0
#define BOOT_RESET_REG 0x15FFB0

#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_2)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_TOTAL_SIZE 0x3c000
#define BOOT_STACK_HEAP_SIZE 0x3fb0
#define BOOT_STATUS_REG 0x15FFE0
#define BOOT_RESET_REG 0x15FFB0

#elif defined(ARCH_SEC_HW_BOOT_OS)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_TOTAL_SIZE 0x3c000
#define BOOT_STACK_HEAP_SIZE 0x3fb0
#define BOOT_STATUS_REG 0x15FFE0
#define BOOT_RESET_REG 0x15FFB0

#elif defined(ARCH_SEC_HW_BOOT_NETWORK)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_TOTAL_SIZE 0x3c000
#define BOOT_STACK_HEAP_SIZE 0x3fb0
#define BOOT_STATUS_REG 0x15FFE0
#define BOOT_RESET_REG 0x15FFB0

#endif /* ARCH_SEC_HW_BOOT_STORAGE */

#endif /* __SEC_HW_RAM_LAYOUT_H */
