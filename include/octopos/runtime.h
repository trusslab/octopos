struct runtime_api {
	/* secure keyboard/serial_out */
	int (*request_secure_keyboard)(int access_mode, int count);
	int (*yield_secure_keyboard)(void);
	int (*request_secure_serial_out)(int access_mode, int count);
	int (*yield_secure_serial_out)(void);
	void (*write_to_secure_serial_out)(char *buf);
	void (*read_char_from_secure_keyboard)(char *buf);

	/* shell input/output */
	int (*write_to_shell)(char *data, int size);
	int (*read_from_shell)(char *data, int *data_size);

	/* file system */
	uint32_t (*open_file)(char *filename);
	int (*write_to_file)(uint32_t fd, uint8_t *data, int size, int offset);
	int (*read_from_file)(uint32_t fd, uint8_t *data, int size, int offset);
	int (*close_file)(uint32_t fd);

	/* secure storage */
	int (*request_secure_storage)(int access_mode, int count, uint8_t *key);
	int (*yield_secure_storage)(void);
	int (*write_to_secure_storage)(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t write_size);
	int (*read_from_secure_storage)(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t read_size);
};
