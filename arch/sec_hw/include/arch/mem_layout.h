#ifndef __SEC_HW_RAM_LAYOUT_H
#define __SEC_HW_RAM_LAYOUT_H

/* memory layout must be known by bootloaders, so
 * that they can erase the DDR memory before loading
 * binary onto the memory.
 */

#define ROM_FUSE1 0xFF800000
#define ROM_FUSE2 0xFF810000
#define FUSE_BURN_VALUE 0xDEADDEAD

/* RAM_RANGE = total RAM size - common stack/heap size */
#ifdef ARCH_SEC_HW_BOOT_STORAGE
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_RANGE 0x3ffff - 0x4000

#elif defined(ARCH_SEC_HW_BOOT_KEYBOARD)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_RANGE 0x1ffff - 0x4000

#elif defined(ARCH_SEC_HW_BOOT_SERIAL_OUT)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_RANGE 0x1ffff - 0x4000

#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_1)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_RANGE 0x1ffff - 0x4000

#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_2)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_RANGE 0x1ffff - 0x4000

#elif defined(ARCH_SEC_HW_BOOT_OS)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_RANGE 0x1ffff - 0x4000

#elif defined(ARCH_SEC_HW_BOOT_NETWORK)
#define RAM_BASE_ADDRESS 0x00120000
#define RAM_RANGE 0x1ffff - 0x4000

#endif /* ARCH_SEC_HW_BOOT_STORAGE */








#endif /* __SEC_HW_RAM_LAYOUT_H */
