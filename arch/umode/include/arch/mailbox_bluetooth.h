uint8_t read_from_bluetooth_cmd_queue_get_owner(uint8_t *buf);
void write_to_bluetooth_cmd_queue(uint8_t *buf);
void read_from_bluetooth_data_queue(uint8_t *buf);
void write_to_bluetooth_data_queue(uint8_t *buf);
int init_bluetooth(void);
void close_bluetooth(void);
