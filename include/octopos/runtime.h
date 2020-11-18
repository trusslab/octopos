#ifndef _OCTOPOS_RUNTIME_H_
#define _OCTOPOS_RUNTIME_H_

#ifndef UNTRUSTED_DOMAIN
#include <network/sock.h>
#endif

/* FIXME: include mailbox.h and remove the repeated defines. */
//#include <octopos/mailbox.h>
typedef uint32_t limit_t;
typedef uint32_t timeout_t;
#define MAILBOX_MAX_LIMIT_VAL	0xFFE
#define MAILBOX_MAX_TIMEOUT_VAL	0xFFE

typedef void (*queue_update_callback_t)(uint8_t, limit_t, timeout_t);

#ifndef UNTRUSTED_DOMAIN
struct runtime_api {
	/* secure keyboard/serial_out */
	int (*request_secure_keyboard)(limit_t limit, timeout_t timeout,
				       queue_update_callback_t callback);
	int (*yield_secure_keyboard)(void);
	int (*request_secure_serial_out)(limit_t limit, timeout_t timeout,
					 queue_update_callback_t callback);
	int (*yield_secure_serial_out)(void);
	int (*write_to_secure_serial_out)(char *buf);
	int (*read_char_from_secure_keyboard)(char *buf);

	/* shell input/output */
	int (*write_to_shell)(char *data, int size);
	int (*read_from_shell)(char *data, int *data_size);

	/* file system */
	uint32_t (*open_file)(char *filename, uint32_t mode);
	int (*write_to_file)(uint32_t fd, uint8_t *data, int size, int offset);
	int (*read_from_file)(uint32_t fd, uint8_t *data, int size, int offset);
	int (*write_file_blocks)(uint32_t fd, uint8_t *data, int start_block,
				 int num_blocks);
	int (*read_file_blocks)(uint32_t fd, uint8_t *data, int start_block,
				int num_blocks);
	int (*close_file)(uint32_t fd);
	int (*remove_file)(char *filename);

	/* secure storage */
	int (*set_up_secure_storage_key)(uint8_t *key);
	int (*request_secure_storage_access)(uint32_t partition_size,
					     limit_t limit, timeout_t timeout,
					     queue_update_callback_t callback);
	int (*yield_secure_storage_access)(void);
	int (*delete_and_yield_secure_storage)(void);
	int (*write_secure_storage_blocks)(uint8_t *data, uint32_t start_block,
					   uint32_t num_blocks);
	int (*read_secure_storage_blocks)(uint8_t *data, uint32_t start_block,
					  uint32_t num_blocks);
	int (*read_from_secure_storage_block)(uint8_t *data, uint32_t block_num,
					      uint32_t block_offset,
					      uint32_t read_size);
	int (*write_to_secure_storage_block)(uint8_t *data, uint32_t block_num,
					     uint32_t block_offset,
					     uint32_t write_size);

	/* storing context in secure storage */
	int (*set_up_context)(void *addr, uint32_t size);

	/* secure IPC */
	int (*request_secure_ipc)(uint8_t target_runtime_queue_id,
				  limit_t limit, timeout_t timeout,
				  queue_update_callback_t callback);
	int (*yield_secure_ipc)(void);
	int (*send_msg_on_secure_ipc)(char *msg, int size);
	int (*recv_msg_on_secure_ipc)(char *msg, int *size);

	/* tpm attestation */
	int (*tpm_remote_attest_requst)(int slot, char* nonce, int size);
	int (*recv_msg_on_tpm)(uint8_t *buf);

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
	int (*request_network_access)(limit_t limit, timeout_t timeout,
				      queue_update_callback_t callback);
	int (*yield_network_access)(void);
#endif
};
#endif /* UNTRUSTED_DOMAIN */

/* file open modes */
#define FILE_OPEN_MODE		0
#define FILE_OPEN_CREATE_MODE	1

#define RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG	0
#define RUNTIME_QUEUE_CONTEXT_SWITCH_TAG	1
#define RUNTIME_QUEUE_EXEC_APP_TAG		2

#endif /* _OCTPOS_RUNTIME_H_ */
