bool is_secure_storage_key_set(void);
int set_up_secure_storage_key(uint8_t *key);
int yield_secure_storage_access(void);
int request_secure_storage_access(int count);
int delete_and_yield_secure_storage(void);
uint32_t write_to_secure_storage(uint8_t *data, uint32_t block_num,
				 uint32_t block_offset, uint32_t write_size);
uint32_t read_from_secure_storage(uint8_t *data, uint32_t block_num,
				  uint32_t block_offset, uint32_t read_size);
