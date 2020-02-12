#ifndef __SEC_HW_MAILBOX_OS_H
#define __SEC_HW_MAILBOX_OS_H

int is_queue_available(uint8_t queue_id);
void wait_for_queue_availability(uint8_t queue_id);
void mark_queue_unavailable(uint8_t queue_id);

int send_output(uint8_t *buf);
int recv_input(uint8_t *buf, uint8_t *queue_id);

int init_os_mailbox(void);
void close_os_mailbox(void);

#endif /* __SEC_HW_MAILBOX_OS_H */
