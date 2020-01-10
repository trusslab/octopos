int send_output(uint8_t *buf);
int send_msg_to_runtime(uint8_t runtime_proc_id, uint8_t *buf);
void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint8_t count);
int send_msg_to_storage(uint8_t *buf);
