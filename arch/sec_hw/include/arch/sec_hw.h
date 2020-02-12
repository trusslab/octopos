#ifndef __SEC_HW_H
#define __SEC_HW_H

#include "xil_printf.h"
#include "xil_exception.h"
#include "xil_assert.h"

void init_platform();
void cleanup_platform();

#define printf  xil_printf
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

#define _SEC_HW_ERROR(fmt, ...)                                     \
    do {xil_printf("--ERROR: %-20.20s: " fmt "\r\n", __FUNCTION__,  \
            ##__VA_ARGS__);} while (0)

#define _SEC_HW_WARNING(fmt, ...)                                   \
    do {xil_printf("--WARNING: %-20.20s: " fmt "\r\n", __FUNCTION__,\
            ##__VA_ARGS__);} while (0)

#define _SEC_HW_INFO(fmt, ...)                                      \
    do {xil_printf("--INFO: %-20.20s: " fmt "\r\n", __FUNCTION__,   \
            ##__VA_ARGS__);} while (0)

//#define _SEC_HW_DEBUG(fmt, ...)                                     \
//    do {xil_printf("--DEBUG: %-20.20s %-20.20s #%-5i: " fmt "\r\n", \
//            __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);} while (0)

#define _SEC_HW_DEBUG(fmt, ...)

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
        cleanup_platform();                                 \
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
        cleanup_platform();                                 \
        Xil_Assert(__FILE__, __LINE__);                     \
        Xil_AssertStatus = XIL_ASSERT_OCCURRED;             \
        return 0;                                           \
        }                                                   \
    }

#endif /* __SEC_HW_H */
