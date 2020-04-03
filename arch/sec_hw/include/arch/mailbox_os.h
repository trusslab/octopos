#ifndef __SEC_HW_MAILBOX_OS_H
#define __SEC_HW_MAILBOX_OS_H

void _mailbox_print_queue_status(uint8_t queue_id);

int is_queue_available(uint8_t queue_id);
void wait_for_queue_availability(uint8_t queue_id);
void mark_queue_unavailable(uint8_t queue_id);

int send_output(uint8_t *buf);
int recv_input(uint8_t *buf, uint8_t *queue_id);

int check_avail_and_send_msg_to_runtime(uint8_t runtime_proc_id, uint8_t *buf);
void wait_until_empty(uint8_t queue_id, int queue_size);
void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint16_t count);

int init_os_mailbox(void);
void close_os_mailbox(void);

#endif /* __SEC_HW_MAILBOX_OS_H */
