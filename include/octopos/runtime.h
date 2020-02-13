struct runtime_api {
	/* secure keyboard/serial_out */
	int (*request_secure_keyboard)(int count);
	int (*yield_secure_keyboard)(void);
	int (*request_secure_serial_out)(int count);
	int (*yield_secure_serial_out)(void);
	void (*write_to_secure_serial_out)(char *buf);
	void (*read_char_from_secure_keyboard)(char *buf);

	/* shell input/output */
	int (*write_to_shell)(char *data, int size);
	int (*read_from_shell)(char *data, int *data_size);

#ifndef ARCH_SEC_HW
	/* file system */
	uint32_t (*open_file)(char *filename, uint32_t mode);
	int (*write_to_file)(uint32_t fd, uint8_t *data, int size, int offset);
	int (*read_from_file)(uint32_t fd, uint8_t *data, int size, int offset);
	int (*write_file_blocks)(uint32_t fd, uint8_t *data, int start_block, int num_blocks);
	int (*read_file_blocks)(uint32_t fd, uint8_t *data, int start_block, int num_blocks);
	int (*close_file)(uint32_t fd);
	int (*remove_file)(char *filename);

	/* secure storage */
	int (*set_up_secure_storage_key)(uint8_t *key);
	int (*request_secure_storage_access)(int count);
	int (*yield_secure_storage_access)(void);
	int (*delete_and_yield_secure_storage)(void);
	uint32_t (*write_to_secure_storage)(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t write_size);
	uint32_t (*read_from_secure_storage)(uint8_t *data, uint32_t block_num, uint32_t block_offset, uint32_t read_size);

	/* storing context in secure storage */
	int (*set_up_context)(void *addr, uint32_t size);
#endif

	/* secure IPC */
	int (*request_secure_ipc)(uint8_t target_runtime_queue_id, int count);
	int (*yield_secure_ipc)(void);
	int (*send_msg_on_secure_ipc)(char *msg, int size);
	int (*recv_msg_on_secure_ipc)(char *msg, int *size);

	/* Local API */
	uint8_t (*get_runtime_proc_id)(void);
	uint8_t (*get_runtime_queue_id)(void);

#ifndef ARCH_SEC_HW
	/* socket and network */
	struct socket *(*create_socket)(int family, int type, int protocol,
					struct sock_addr *skaddr);
	//int (*listen_on_socket)(struct socket *sock, int backlog);
	void (*close_socket)(struct socket *sock);
	//int (*bind_socket)(struct socket *sock, struct sock_addr *skaddr);
	//struct socket *(*accept_connection)(struct socket *sock, struct sock_addr *skaddr);
	int (*connect_socket)(struct socket *sock, struct sock_addr *skaddr);
	int (*read_from_socket)(struct socket *sock, void *buf, int len);
	int (*write_to_socket)(struct socket *sock, void *buf, int len);
	int (*request_network_access)(int count);
	int (*yield_network_access)(void);
#endif
};

/* file open modes */
#define FILE_OPEN_MODE		0
#define FILE_OPEN_CREATE_MODE	1

#define RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG	0
#define RUNTIME_QUEUE_CONTEXT_SWITCH_TAG	1
#define RUNTIME_QUEUE_EXEC_APP_TAG		2
