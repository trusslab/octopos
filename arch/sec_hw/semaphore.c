#include "sleep.h"
#include "stdlib.h"

#include "arch/semaphore.h"
#include "arch/sec_hw.h"
#include "arch/ring_buffer.h"

#include "octopos/mailbox.h"

#include "xil_assert.h"
#include "xmbox.h"

int sem_init(sem_t *sem, int pshared, int value) 
{
    sem->count = value;
    return 0;
}

int sem_post(sem_t *sem) 
{
    _SEC_HW_ASSERT_NON_VOID(sem->count < 2147483647);
    sem->count += 1;
    return 0;
}

int sem_wait(sem_t *sem) 
{
    if (sem->count <= 0) {
        while(1) {
            if (sem->count > 0) {
                sem -> count -= 1;
                break;
            }
            usleep(1);
        }
    } else {
        sem -> count -= 1;
    }
    return 0;
}

int _sem_retrieve_mailbox_message_blocking(XMbox *InstancePtr, cbuf_handle_t cbuf)
{
    int         status;
    uint8_t     *message_buffer;

    message_buffer = (uint8_t*) calloc(MAILBOX_QUEUE_MSG_SIZE, sizeof(uint8_t));
    XMbox_ReadBlocking(InstancePtr, (u32*)(message_buffer), MAILBOX_QUEUE_MSG_SIZE);

    status = circular_buf_put(cbuf, (uint32_t) message_buffer);

    if (status != XST_SUCCESS) {
        /* since the cpu pulls io, this should never happen */
        _SEC_HW_ERROR("Ring buffer is full. The system may be out of sync.");
        _SEC_HW_ASSERT_NON_VOID(FALSE);
    }

    return 0;
}

int _sem_deliver_mailbox_message_blocking(XMbox *InstancePtr, u32* buf)
{
    XMbox_WriteBlocking(InstancePtr, buf, MAILBOX_QUEUE_MSG_SIZE);

    return 0;
}

int sem_wait_impatient_send(sem_t *sem, XMbox *InstancePtr, u32* buf)
{
    if (sem->count <= 0) {
        _sem_deliver_mailbox_message_blocking(InstancePtr, buf);

        if (sem->count > 0) {
            sem->count -= 1;
        }
    } else {
        sem->count -= 1;
        _sem_deliver_mailbox_message_blocking(InstancePtr, buf);
    }
    return 0;
}

int sem_wait_impatient_receive(sem_t *sem, XMbox *InstancePtr, cbuf_handle_t cbuf)
{
    if (sem->count <= 0) {
        _sem_retrieve_mailbox_message_blocking(InstancePtr, cbuf);
        /* There are two conditions:
        * 1. The mailbox really has nothing, someone writes to it
        *    will trigger an interrupt. We need to eat it here.
        * 2. The mailbox is stuck on a stale message. The blocking
        *    read acts like a plumber. Since interrupt has ever been
        *    triggered for this message, no need to -1. */
        if (sem->count > 0) {
            sem->count -= 1;
        }
    } else {
        sem->count -= 1;
        _sem_retrieve_mailbox_message_blocking(InstancePtr, cbuf);
    }
    return 0;
}

XMbox* sem_wait_impatient_receive_multiple(sem_t *sem, int mb_count, ...)
{
    XMbox*      InstancePtr = NULL;
    _Bool       has_new = FALSE;
    uint32_t    args_ptrs[mb_count];

    if (sem->count <= 0) {

        va_list args;
        va_start(args, mb_count);

        for (int i = 0; i < mb_count; ++i) {
            InstancePtr = va_arg(args, XMbox*);
            _SEC_HW_ASSERT_NON_VOID(InstancePtr);

            _SEC_HW_DEBUG("argument index: %d, mailbox: %p", i, InstancePtr);
            args_ptrs[i] = (uint32_t) InstancePtr;
        }

        va_end(args);

        while (!has_new) {
            for (int i = 0; i < mb_count; ++i) {
                if (!XMbox_IsEmpty((XMbox*) args_ptrs[i])) {
                    has_new = TRUE;
                    _SEC_HW_DEBUG("mailbox %p has new message", InstancePtr);
                    InstancePtr = (XMbox*) args_ptrs[i];
                    break;
                }
            }
        }

        if (sem->count > 0) {
            sem->count -= 1;
        }

        return InstancePtr;
    } else {
        sem->count -= 1;
        return NULL;
    }

    return NULL;
}

int sem_getvalue(sem_t *sem, int *value)
{
    *value = sem->count;
    return 0;
}
