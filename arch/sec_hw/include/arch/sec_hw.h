#ifndef __SEC_HW_H
#define __SEC_HW_H

#include <stdio.h>

#include "xil_printf.h"
#include "xil_exception.h"
#include "xil_assert.h"

#ifdef ARCH_SEC_HW_RUNTIME
#include <octopos/syscall.h>
#include <octopos/mailbox.h>

#include "arch/semaphore.h"

#include "arch/octopos_xmbox.h"

extern int q_os;
extern OCTOPOS_XMbox* Mbox_regs[NUM_QUEUES + 1];
extern sem_t interrupts[NUM_QUEUES + 1];
#endif

void init_platform();
void cleanup_platform();

#define printf 	xil_printf
#define true    1
#define false   0
#define bool    _Bool

/* image size measured in bytes. it must be a multiple of 512. 
 * its okay to be bigger than actual size (ceiling to the next multiple of 512).
 */
#define MAX_ALLOWED_IMAGE_SIZE_IN_SECTOR 4
#define STORAGE_IMAGE_SIZE 263168
#define OS_IMAGE_SIZE 421888

/* line number is for data transfer over mailbox.
 * each line has up to 255B (SREC_MAX_BYTES), padded with 0 to be 256B
 * FIXME: large queue: each 512 message should fit 2 lines
 */
#define OS_IMAGE_LINE_NUMBER 9169

/* special op code for boot image request */
#define STORAGE_OP_BOOT_REQ 0xf

/* This symbol is for debug only. It forces all mailbox to
 * wait on the queue until all expected bytes are delivered.
 */
// #define HW_MAILBOX_BLOCKING

/* Defines the maximum length of a single command line */
#define MAILBOX_MAX_COMMAND_SIZE                  64
#define MAILBOX_MAX_COMMAND_SIZE_NO_PADDING       \
	(MAILBOX_MAX_COMMAND_SIZE-MAILBOX_QUEUE_MSG_SIZE+1)

#define MAILBOX_MAX_COMMAND_SIZE_LARGE            64
#define MAILBOX_MAX_COMMAND_SIZE_NO_PADDING_LARGE \
	(MAILBOX_MAX_COMMAND_SIZE-MAILBOX_QUEUE_MSG_SIZE+1)

/* Defines the value written to the mailbox receive
 * threshold register. The MAILBOX_DEFAULT_RX_THRESHOLDth
 * writes (of 4 bytes messages) will trigger the raising edge
 * of the receive interrupt.
 */
#define MAILBOX_DEFAULT_RX_THRESHOLD			MAILBOX_MAX_COMMAND_SIZE/4 - 1
#define MAILBOX_DEFAULT_RX_THRESHOLD_LARGE		MAILBOX_MAX_COMMAND_SIZE_LARGE/4 - 1

#define TO_BIG_ENDIAN_16(i)						\
	 ((((u16) i>>8) & 0x00FF) |					\
	 (((u16) i<<8) & 0xFF00))

#define TO_BIG_ENDIAN_32(i)						\
	 ((((u32) i>>24) & 0x000000FF) |			\
	 (((u32) i>>8) & 0x0000FF00) |				\
	 (((u32) i<<8) & 0x00FF0000) |				\
	 (((u32) i<<24) & 0xFF000000))

#define SEC_HW_PS_LOCAL_DISABLE_INTERRUPT()		\
	do {Xil_ExceptionDisable();} while (0)

#define SEC_HW_PS_LOCAL_ENABLE_INTERRUPT()		\
	do {Xil_ExceptionEnable();} while (0)

#define SEC_HW_DEBUG_HANG()						\
	do {while(1) sleep(1);} while (0)

#ifdef ARCH_SEC_HW_RUNTIME

char host_printf_buf[64];

#define _SEC_HW_ERROR(fmt, ...)										\
	do {memset(host_printf_buf, 0x0, 64);							\
	*((uint16_t *) &host_printf_buf[0]) = SYSCALL_DEBUG_OUTPUTS;	\
	host_printf_buf[2] = 61;										\
	snprintf(&host_printf_buf[3], 61,								\
		"ERR: " fmt "\r\n", ##__VA_ARGS__);							\
	sem_wait_impatient_send(&interrupts[q_os],						\
		Mbox_regs[q_os], (u32*) host_printf_buf);} while(0)

//#define _SEC_HW_WARNING(fmt, ...)											\
//	do {memset(host_printf_buf, 0x0, 64);									\
//	*((uint16_t *) &host_printf_buf[0]) = SYSCALL_DEBUG_OUTPUTS;			\
//	host_printf_buf[2] = 61;												\
//	snprintf(&host_printf_buf[3], 61,										\
//		"WRN: " fmt "\r\n", ##__VA_ARGS__);									\
//    sem_wait_impatient_send(&interrupts[q_os],							\
//		Mbox_regs[q_os], (u32*) host_printf_buf);} while(0)

#define _SEC_HW_WARNING(fmt, ...)

//#define _SEC_HW_INFO(fmt, ...)											\
//	do {memset(host_printf_buf, 0x0, 64);  									\
//	*((uint16_t *) &host_printf_buf[0]) = SYSCALL_DEBUG_OUTPUTS;			\
//	host_printf_buf[2] = 61;												\
//	snprintf(&host_printf_buf[3], 61,										\
//		"INF: " fmt "\r\n", ##__VA_ARGS__);									\
//    sem_wait_impatient_send(&interrupts[q_os],							\
//		Mbox_regs[q_os], (u32*) host_printf_buf);} while(0)

#define _SEC_HW_INFO(fmt, ...)

//#define _SEC_HW_DEBUG(fmt, ...)											\
//	do {memset(host_printf_buf, 0x0, 64);  									\
//	*((uint16_t *) &host_printf_buf[0]) = SYSCALL_DEBUG_OUTPUTS;			\
//	host_printf_buf[2] = 61;												\
//	snprintf(&host_printf_buf[3], 61,										\
//		"DBG: " fmt "\r\n", ##__VA_ARGS__);									\
//    sem_wait_impatient_send(&interrupts[q_os],							\
//		Mbox_regs[q_os], (u32*) host_printf_buf);} while(0)

#define _SEC_HW_DEBUG(fmt, ...)

#else

#define _SEC_HW_ERROR(fmt, ...)										\
	do {xil_printf("--ERROR: %-20.20s: " fmt "\r\n", __FUNCTION__,	\
			##__VA_ARGS__);} while (0)

#define _SEC_HW_WARNING(fmt, ...)									\
	do {xil_printf("--WARNING: %-20.20s: " fmt "\r\n", __FUNCTION__,\
			##__VA_ARGS__);} while (0)

#define _SEC_HW_INFO(fmt, ...)										\
	do {xil_printf("--INFO: %-20.20s: " fmt "\r\n", __FUNCTION__,	\
			##__VA_ARGS__);} while (0)

// #define _SEC_HW_DEBUG1(fmt, ...)										\
// 	do {xil_printf("--DEBUG: %-20.20s %-20.20s #%-5i: " fmt "\r\n",		\
// 		__FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);} while (0)

// #define _SEC_HW_DEBUG(fmt, ...)										\
// 	do {xil_printf("--DEBUG: %-20.20s %-20.20s #%-5i: " fmt "\r\n", 	\
// 		__FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);} while (0)

#define _SEC_HW_DEBUG(fmt, ...)
#define _SEC_HW_DEBUG1(fmt, ...)
#endif

/* This assertion macro must be used within functions that do
 * not return anything (void). It does some clean up than just
 * calling Xil_AssertVoid.
 */
#define _SEC_HW_ASSERT_VOID(expr)							\
	{														\
	if (expr)												\
		{													\
		Xil_AssertStatus = XIL_ASSERT_NONE;					\
		}													\
	else													\
		{													\
		_SEC_HW_ERROR("ASSERT %s\r\n", #expr);				\
		Xil_Assert(__FILE__, __LINE__);						\
		Xil_AssertStatus = XIL_ASSERT_OCCURRED;				\
		return;												\
		}													\
	}

/* This assertion macro must be used within functions that do
 * return something. It does some clean up than just calling
 * Xil_AssertNonVoid.
 */
#define _SEC_HW_ASSERT_NON_VOID(expr)						\
	{														\
	if (expr)												\
		{													\
		Xil_AssertStatus = XIL_ASSERT_NONE;					\
		}													\
	else													\
		{													\
		_SEC_HW_ERROR("ASSERT %s\r\n", #expr);				\
		Xil_Assert(__FILE__, __LINE__);						\
		Xil_AssertStatus = XIL_ASSERT_OCCURRED;				\
		return 0;											\
		}													\
	}

#endif /* __SEC_HW_H */
