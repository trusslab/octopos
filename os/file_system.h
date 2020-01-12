uint32_t file_system_open_file(char *filename, uint32_t mode);
int file_system_write_to_file(uint32_t fd, uint8_t *data, int size, int offset);
int file_system_read_from_file(uint32_t fd, uint8_t *data, int size, int offset);
int file_system_close_file(uint32_t fd);
int file_system_remove_file(char *filename);
void initialize_file_system(void);
