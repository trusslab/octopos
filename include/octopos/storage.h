#ifndef __STORAGE_OCTOPOS_CORE_H_
#define __STORAGE_OCTOPOS_CORE_H_

#if defined(ARCH_SEC_HW) && !defined(PROJ_CPP)
#define bool _Bool
#define true 1
#define false 0
#endif

#ifdef ARCH_SEC_HW
#define STORAGE_BLOCK_SIZE	64  /* bytes */
#else
#define STORAGE_BLOCK_SIZE	512  /* bytes */
#endif

#define STORAGE_BOOT_PARTITION_SIZE			200000
#define STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE	4000000

#endif /* __STORAGE_OCTOPOS_CORE_H_ */
