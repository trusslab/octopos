void send_measurement_to_queue(uint8_t *buf);
void read_measurement_from_queue(uint8_t *buf);
int init_tpm(void);
void close_tpm(void);