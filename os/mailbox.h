int send_output(uint8_t *buf);
int send_msg_to_runtime(uint8_t runtime_proc_id, uint8_t *buf);
void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id, uint8_t count);
int send_msg_to_storage_no_response(uint8_t *buf);
int get_response_from_storage(uint8_t *buf);
void read_from_storage_data_queue(uint8_t *buf);
void write_to_storage_data_queue(uint8_t *buf);
