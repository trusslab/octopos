uint8_t read_request_get_owner_from_queue(uint8_t *buf);
uint8_t get_queue_owner(uint8_t queue_id);
void send_response_to_queue(uint8_t *buf);
int init_tpm(void);
void close_tpm(void);
