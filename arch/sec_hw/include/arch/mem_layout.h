#ifndef __SEC_HW_DDR_LAYOUT_H
#define __SEC_HW_DDR_LAYOUT_H

/* memory layout must be known by bootloaders, so
 * that they can erase the DDR memory before loading
 * binary onto the memory.
 */

#ifdef ARCH_SEC_HW_BOOT_STORAGE
#define DDR_BASE_ADDRESS 0x61000000
#define DDR_RANGE 0xffffff

#elif defined(ARCH_SEC_HW_BOOT_KEYBOARD)
#define DDR_BASE_ADDRESS 0x63000000
#define DDR_RANGE 0xffffff

#elif defined(ARCH_SEC_HW_BOOT_SERIAL_OUT)
#define DDR_BASE_ADDRESS 0x62000000
#define DDR_RANGE 0xffffff

#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_1)
#define DDR_BASE_ADDRESS 0x64000000
#define DDR_RANGE 0xffffff

#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_2)
#define DDR_BASE_ADDRESS 0x65000000
#define DDR_RANGE 0xffffff

#elif defined(ARCH_SEC_HW_BOOT_OS)
#define DDR_BASE_ADDRESS 0x66000000
#define DDR_RANGE 0x1ffffff

#elif defined(ARCH_SEC_HW_BOOT_NETWORK)
#define DDR_BASE_ADDRESS 0
#define DDR_RANGE 0

#endif /* ARCH_SEC_HW_BOOT_STORAGE */








#endif /* __SEC_HW_DDR_LAYOUT_H */
