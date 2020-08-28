#ifndef __UMODE_MAILBOX_STORAGE_H
#define __UMODE_MAILBOX_STORAGE_H

void storage_event_loop(void);
int init_storage(void);
void close_storage(void);
void send_response(uint8_t *buf, uint8_t queue_id);
void read_data_from_queue(uint8_t *buf, uint8_t queue_id);
void write_data_to_queue(uint8_t *buf, uint8_t queue_id);

#endif /* __UMODE_MAILBOX_STORAGE_H */

