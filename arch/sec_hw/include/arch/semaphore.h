#ifndef __SEC_HW_SEMAPHORE_H
#define __SEC_HW_SEMAPHORE_H

#include "arch/ring_buffer.h"

#include "xmbox.h"

typedef struct {
    int     count;
} sem_t;

int sem_init(sem_t *sem, int pshared, int value);

int sem_post(sem_t *sem);

int sem_wait(sem_t *sem);

int sem_wait_one_time_receive_cbuf(sem_t *sem, XMbox *InstancePtr, cbuf_handle_t cbuf);

int sem_wait_one_time_receive_buf(sem_t *sem, XMbox *InstancePtr, uint8_t* buf);

int sem_wait_impatient_receive_cbuf(sem_t *sem, XMbox *InstancePtr, cbuf_handle_t cbuf);

int sem_wait_impatient_receive_buf(sem_t *sem, XMbox *InstancePtr, uint8_t* buf);

int sem_wait_impatient_send(sem_t *sem, XMbox *InstancePtr, u32* buf);

XMbox* sem_wait_impatient_receive_multiple(sem_t *sem, int mb_count, ...);

int sem_getvalue(sem_t *sem, int *value);

#endif /* __SEC_HW_SEMAPHORE_H */
