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

#include "xmbox.h"

extern int q_os;
extern XMbox* Mbox_regs[NUM_QUEUES + 1];
extern sem_t interrupts[NUM_QUEUES + 1];
#endif

void init_platform();
void cleanup_platform();

#define printf 	xil_printf
#define true    1
#define false   0
#define bool    _Bool

/* Defines the maximum length of a single command line */
#define MAILBOX_MAX_COMMAND_SIZE                64
#define MAILBOX_MAX_COMMAND_SIZE_NO_PADDING     \
    (MAILBOX_MAX_COMMAND_SIZE-MAILBOX_QUEUE_MSG_SIZE+1)

#define SEC_HW_PS_LOCAL_DISABLE_INTERRUPT()                 \
    do {Xil_ExceptionDisable();} while (0)

#define SEC_HW_PS_LOCAL_ENABLE_INTERRUPT()                  \
    do {Xil_ExceptionEnable();} while (0)

#ifdef ARCH_SEC_HW_RUNTIME

int write_to_shell(char *data, int size);
char host_printf_buf[64];

#define _SEC_HW_ERROR(fmt, ...)                                      		\
	do {memset(host_printf_buf, 0x0, 64);  						 		 	\
	*((uint16_t *) &host_printf_buf[0]) = SYSCALL_DEBUG_OUTPUTS;			\
	host_printf_buf[2] = 61;												\
	snprintf(&host_printf_buf[3], 61,								 		\
		"ERR: " fmt "\r\n", ##__VA_ARGS__);									\
    sem_wait_impatient_send(&interrupts[q_os],								\
		Mbox_regs[q_os], (u32*) host_printf_buf);} while(0)

#define _SEC_HW_WARNING(fmt, ...)                                      		\
	do {memset(host_printf_buf, 0x0, 64);  						 		 	\
	*((uint16_t *) &host_printf_buf[0]) = SYSCALL_DEBUG_OUTPUTS;			\
	host_printf_buf[2] = 61;												\
	snprintf(&host_printf_buf[3], 61,								 		\
		"WRN: " fmt "\r\n", ##__VA_ARGS__);									\
    sem_wait_impatient_send(&interrupts[q_os],								\
		Mbox_regs[q_os], (u32*) host_printf_buf);} while(0)

#define _SEC_HW_INFO(fmt, ...)                                      		\
	do {memset(host_printf_buf, 0x0, 64);  						 		 	\
	*((uint16_t *) &host_printf_buf[0]) = SYSCALL_DEBUG_OUTPUTS;			\
	host_printf_buf[2] = 61;												\
	snprintf(&host_printf_buf[3], 61,								 		\
		"INF: " fmt "\r\n", ##__VA_ARGS__);									\
    sem_wait_impatient_send(&interrupts[q_os],								\
		Mbox_regs[q_os], (u32*) host_printf_buf);} while(0)

#define _SEC_HW_DEBUG(fmt, ...)                                      		\
	do {memset(host_printf_buf, 0x0, 64);  						 		 	\
	*((uint16_t *) &host_printf_buf[0]) = SYSCALL_DEBUG_OUTPUTS;			\
	host_printf_buf[2] = 61;												\
	snprintf(&host_printf_buf[3], 61,								 		\
		"DBG: " fmt "\r\n", ##__VA_ARGS__);									\
    sem_wait_impatient_send(&interrupts[q_os],								\
		Mbox_regs[q_os], (u32*) host_printf_buf);} while(0)

#else

#define _SEC_HW_ERROR(fmt, ...)                                     \
    do {xil_printf("--ERROR: %-20.20s: " fmt "\r\n", __FUNCTION__,  \
            ##__VA_ARGS__);} while (0)

#define _SEC_HW_WARNING(fmt, ...)                                   \
    do {xil_printf("--WARNING: %-20.20s: " fmt "\r\n", __FUNCTION__,\
            ##__VA_ARGS__);} while (0)

#define _SEC_HW_INFO(fmt, ...)                                      \
    do {xil_printf("--INFO: %-20.20s: " fmt "\r\n", __FUNCTION__,   \
            ##__VA_ARGS__);} while (0)

#define _SEC_HW_DEBUG(fmt, ...)                                     \
    do {xil_printf("--DEBUG: %-20.20s %-20.20s #%-5i: " fmt "\r\n", \
            __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);} while (0)

#endif

//#define _SEC_HW_DEBUG(fmt, ...)

/* This assertion macro must be used within functions that do
 * not return anything (void). It does some clean up than just
 * calling Xil_AssertVoid.
 */
#define _SEC_HW_ASSERT_VOID(expr)                           \
    {                                                       \
    if (expr)                                               \
        {                                                   \
        Xil_AssertStatus = XIL_ASSERT_NONE;                 \
        }                                                   \
    else                                                    \
        {                                                   \
        _SEC_HW_ERROR("ASSERTION EPITAPH: %s\r\n", #expr);  \
        Xil_Assert(__FILE__, __LINE__);                     \
        Xil_AssertStatus = XIL_ASSERT_OCCURRED;             \
        return;                                             \
        }                                                   \
    }

/* This assertion macro must be used within functions that do
 * return something. It does some clean up than just calling
 * Xil_AssertNonVoid.
 */
#define _SEC_HW_ASSERT_NON_VOID(expr)                       \
    {                                                       \
    if (expr)                                               \
        {                                                   \
        Xil_AssertStatus = XIL_ASSERT_NONE;                 \
        }                                                   \
    else                                                    \
        {                                                   \
        _SEC_HW_ERROR("ASSERTION EPITAPH: %s\r\n", #expr);  \
        Xil_Assert(__FILE__, __LINE__);                     \
        Xil_AssertStatus = XIL_ASSERT_OCCURRED;             \
        return 0;                                           \
        }                                                   \
    }

#endif /* __SEC_HW_H */
