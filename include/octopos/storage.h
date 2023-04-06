/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
#ifndef __STORAGE_OCTOPOS_CORE_H_
#define __STORAGE_OCTOPOS_CORE_H_

#if defined(ARCH_SEC_HW) && !defined(PROJ_CPP) && !defined(ROLE_INSTALLER)
#define bool _Bool
#define true 1
#define false 0
#endif

#define STORAGE_BLOCK_SIZE	512  /* bytes */

#ifndef ARCH_SEC_HW
#define STORAGE_BOOT_PARTITION_SIZE			200000
#define STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE	4000000
#else
#define STORAGE_BOOT_PARTITION_SIZE			100000
#define STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE	300000
#define RAM_ROOT_PARTITION_BASE 0x30000000
#define RAM_UNTRUSTED_PARTITION_BASE (RAM_ROOT_PARTITION_BASE + STORAGE_BOOT_PARTITION_SIZE * STORAGE_BLOCK_SIZE)
#define RAM_ENCLAVE_PARTITION_1_BASE (RAM_UNTRUSTED_PARTITION_BASE + STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE * STORAGE_BLOCK_SIZE)
#define RAM_ENCLAVE_PARTITION_2_BASE (RAM_ENCLAVE_PARTITION_1_BASE + 100 * STORAGE_BLOCK_SIZE)
#define RAM_ENCLAVE_PARTITION_3_BASE (RAM_ENCLAVE_PARTITION_2_BASE + 100 * STORAGE_BLOCK_SIZE)
#define RAM_ENCLAVE_PARTITION_4_BASE (RAM_ENCLAVE_PARTITION_3_BASE + 100 * STORAGE_BLOCK_SIZE)
#define STORAGE_METADATA_SIZE			64
#define RAM_ROOT_PARTITION_METADATA_BASE 0x25000000
#endif

#endif /* __STORAGE_OCTOPOS_CORE_H_ */
