#ifndef __SEC_HW_MAILBOX_KEYBOARD_H
#define __SEC_HW_MAILBOX_KEYBOARD_H

uint8_t read_char_from_keyboard(void);
void put_char_on_keyboard_queue(uint8_t kchar);
int init_keyboard(void);
void close_keyboard(void);

#endif /* __SEC_HW_MAILBOX_KEYBOARD_H */
