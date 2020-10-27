#ifndef __STORAGE_OCTOPOS_CORE_H_
#define __STORAGE_OCTOPOS_CORE_H_

#ifdef ARCH_SEC_HW
#define bool _Bool
#define true 1
#define false 0
#endif

#define STORAGE_KEY_SIZE	32  /* bytes */

#define STORAGE_OP_WRITE			0
#define STORAGE_OP_READ				1
#define STORAGE_OP_SET_KEY			2
#define STORAGE_OP_UNLOCK			3
#define STORAGE_OP_LOCK				4
#define STORAGE_OP_WIPE				5
#define STORAGE_OP_CREATE_SECURE_PARTITION	6
#define STORAGE_OP_DELETE_SECURE_PARTITION	7
#define STORAGE_OP_SET_CONFIG_KEY		8
#define STORAGE_OP_UNLOCK_CONFIG		9
#define STORAGE_OP_LOCK_CONFIG			10

#ifdef ARCH_SEC_HW
#define STORAGE_BLOCK_SIZE	64  /* bytes */
#else
#define STORAGE_BLOCK_SIZE	512  /* bytes */
#endif

#define STORAGE_BOOT_PARTITION_SIZE	200000

#endif /* __STORAGE_OCTOPOS_CORE_H_ */
