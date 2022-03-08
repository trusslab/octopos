
#define NETWORK_SET_FOUR_ARGS(arg0, arg1, arg2, arg3)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];				\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);			\
	*((uint32_t *) &buf[0]) = arg0;					\
	*((uint32_t *) &buf[4]) = arg1;					\
	*((uint32_t *) &buf[8]) = arg2;					\
	*((uint32_t *) &buf[12]) = arg3;				\

#define NETWORK_GET_ONE_RET		\
	uint32_t ret0;			\
	ret0 = *((uint32_t *) &buf[0]); \


#define NETWORK_SET_ONE_ARG(arg0)				\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];			\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	SERIALIZE_32(arg0, &buf[1])				\



void handle_allocate_socket_syscall(uint8_t runtime_proc_id,
				    uint8_t *buf);
void handle_request_network_access_syscall(uint8_t runtime_proc_id,
					   uint8_t *buf);
void handle_close_socket_syscall(uint8_t runtime_proc_id,
				 uint8_t *buf);
