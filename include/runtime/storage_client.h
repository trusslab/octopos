bool is_secure_storage_key_set(void);
int set_up_secure_storage_key(uint8_t *key);
int yield_secure_storage_access(void);
int request_secure_storage_access(int count, uint32_t partition_size);
int delete_and_yield_secure_storage(void);
int write_secure_storage_blocks(uint8_t *data, uint32_t start_block,
				uint32_t num_blocks);
int read_secure_storage_blocks(uint8_t *data, uint32_t start_block,
			       uint32_t num_blocks);
int read_from_secure_storage_block(uint8_t *data, uint32_t block_num,
				   uint32_t block_offset, uint32_t read_size);
int write_to_secure_storage_block(uint8_t *data, uint32_t block_num,
				  uint32_t block_offset, uint32_t write_size);