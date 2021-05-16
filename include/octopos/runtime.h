#ifndef _OCTOPOS_RUNTIME_H_
#define _OCTOPOS_RUNTIME_H_

#if !defined(UNTRUSTED_DOMAIN) && !defined(ARCH_SEC_HW)
#include <network/sock.h>
#endif

/* FIXME: include mailbox.h and remove the repeated defines. */
//#include <octopos/mailbox.h>
typedef uint32_t limit_t;
typedef uint32_t timeout_t;
#define MAILBOX_MAX_LIMIT_VAL	0xFFE
#define MAILBOX_MAX_TIMEOUT_VAL	0xFFE

typedef void (*queue_update_callback_t)(uint8_t, limit_t, timeout_t, uint8_t);
#define LIMIT_UPDATE		0
#define TIMEOUT_UPDATE		1

#ifndef UNTRUSTED_DOMAIN
struct runtime_api {
	/* secure keyboard/serial_out */
	int (*request_secure_keyboard)(limit_t limit, timeout_t timeout,
				       queue_update_callback_t callback,
				       uint8_t *expected_pcr);
	int (*yield_secure_keyboard)(void);
	int (*request_secure_serial_out)(limit_t limit, timeout_t timeout,
					 queue_update_callback_t callback,
					 uint8_t *expected_pcr);
	int (*yield_secure_serial_out)(void);
	int (*write_to_secure_serial_out)(char *buf);
	int (*read_char_from_secure_keyboard)(char *buf);

	/* shell input/output */
	int (*write_to_shell)(char *data, int size);
	int (*read_from_shell)(char *data, int *data_size);

	/* file system */
	/* FIXME: what's the real use of the FS API for apps? */
	uint32_t (*open_file)(char *filename, uint32_t mode);
	int (*write_to_file)(uint32_t fd, uint8_t *data, int size, int offset);
	int (*read_from_file)(uint32_t fd, uint8_t *data, int size, int offset);
	int (*write_file_blocks)(uint32_t fd, uint8_t *data, int start_block,
				 int num_blocks);
	int (*read_file_blocks)(uint32_t fd, uint8_t *data, int start_block,
				int num_blocks);
	uint32_t (*get_file_size)(uint32_t fd);
	int (*close_file)(uint32_t fd);
	int (*remove_file)(char *filename);

	/* secure storage */
	int (*request_secure_storage_access)(uint32_t partition_size,
					     limit_t limit, timeout_t timeout,
					     queue_update_callback_t callback,
					     uint8_t *expected_pcr,
					     uint8_t *return_pcr);
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
	int (*set_up_context)(void *addr, uint32_t size, int do_yield,
			      int *context_found, uint32_t partition_size,
			      limit_t limit, timeout_t timeout,
			      queue_update_callback_t callback,
			      uint8_t *expected_pcr, uint8_t *return_pcr);
	int (*write_context_to_storage)(int do_yield);

	/* secure IPC */
	int (*request_secure_ipc)(uint8_t target_runtime_queue_id,
				  limit_t limit, timeout_t timeout,
				  queue_update_callback_t callback);
	int (*yield_secure_ipc)(void);
	int (*send_msg_on_secure_ipc)(char *msg, int size);
	int (*recv_msg_on_secure_ipc)(char *msg, int *size);

	/* tpm attestation */
	int (*request_tpm_attestation_report)(uint32_t *pcr_list,
					      size_t pcr_list_size, char* nonce,
					      uint8_t **signature, size_t *sig_size,
					      uint8_t **quote, size_t *quote_size);

	/* Local API */
	uint8_t (*get_runtime_proc_id)(void);
	uint8_t (*get_runtime_queue_id)(void);
	void (*terminate_app)(void);
	int (*schedule_func_execution)(void *(*func)(void *), void *data);
	uint32_t (*get_random_uint)(void);
	uint64_t (*get_time)(void);

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
	/* FIXME: rename to request_secure_network_access */
	int (*request_network_access)(limit_t limit, timeout_t timeout,
				      queue_update_callback_t callback,
				      uint8_t *expected_pcr, uint8_t *return_pcr);
	int (*yield_network_access)(void);

	/* bluetooth */
	int (*request_secure_bluetooth_access)(uint8_t *device_names,
					       uint32_t num_devices,
					       limit_t limit, timeout_t timeout,
					       uint8_t *am_addrs,
					       queue_update_callback_t callback,
					       uint8_t *expected_pcr,
					       uint8_t *return_pcr);
	int (*authenticate_with_bluetooth_service)(uint8_t *app_signature);
	int (*yield_secure_bluetooth_access)(void);
	int (*bluetooth_send_data)(uint8_t am_addr, uint8_t *data, uint32_t len);
	int (*bluetooth_recv_data)(uint8_t am_addr, uint8_t *data, uint32_t len);
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
