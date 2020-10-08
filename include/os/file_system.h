#ifndef _FILE_SYSTEM_H_
#define _FILE_SYSTEM_H_

/* file open modes */
#define FILE_OPEN_MODE		0
#define FILE_OPEN_CREATE_MODE	1

/* FIXME: too small */
#define DIR_DATA_NUM_BLOCKS	2 //16
#define DIR_DATA_SIZE		DIR_DATA_NUM_BLOCKS * STORAGE_BLOCK_SIZE

uint32_t file_system_open_file(char *filename, uint32_t mode);
uint32_t file_system_write_to_file(uint32_t fd, uint8_t *data, uint32_t size, uint32_t offset);
uint32_t file_system_read_from_file(uint32_t fd, uint8_t *data, uint32_t size, uint32_t offset);
uint8_t file_system_write_file_blocks(uint32_t fd, uint32_t start_block, uint32_t num_blocks, uint8_t runtime_proc_id);
void file_system_write_file_blocks_late(void);
uint8_t file_system_read_file_blocks(uint32_t fd, uint32_t start_block, uint32_t num_blocks, uint8_t runtime_proc_id);
void file_system_read_file_blocks_late(void);
int file_system_close_file(uint32_t fd);
int file_system_remove_file(char *filename);
void initialize_file_system(uint32_t _partition_num_blocks);
void close_file_system(void);

#endif
