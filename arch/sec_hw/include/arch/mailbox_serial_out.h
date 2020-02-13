#ifndef __SEC_HW_MAILBOX_SERIAL_OUT_H
#define __SEC_HW_MAILBOX_SERIAL_OUT_H

void get_chars_from_serial_out_queue(uint8_t *buf);
void write_chars_to_serial_out(uint8_t *buf);
int init_serial_out(void);
void close_serial_out(void);
void runtime_core(void);

#endif /* __SEC_HW_MAILBOX_SERIAL_OUT_H */
