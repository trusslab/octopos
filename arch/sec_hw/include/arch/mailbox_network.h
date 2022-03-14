#ifndef __SEC_HW_MAILBOX_NETWORK_H
#define __SEC_HW_MAILBOX_NETWORK_H

void network_event_loop(void);
int init_network(void);
void close_network(void);
void read_data_from_queue(uint8_t *buf, uint8_t queue_id);
void write_data_to_queue(uint8_t *buf, uint8_t queue_id);
void send_received_packet(uint8_t *buf, uint8_t queue_id);

#endif /* __SEC_HW_MAILBOX_STORAGE_H */

