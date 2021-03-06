/* FIXME: there are a lot of repetition in these macros (also see include/os/storage.h) */
/* FIXME: the first check on max size is always false */
#define NETWORK_SET_ZERO_ARGS_DATA(data, size)					\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE_LARGE];				\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE);				\
	uint16_t max_size = MAILBOX_QUEUE_MSG_SIZE_LARGE - 2;			\
	if (max_size >= 65536) {						\
		printf("Error (%s): max_size not supported\n", __func__);	\
		return;								\
	}									\
	if (size > max_size) {							\
		printf("Error (%s): size not supported\n", __func__);		\
		return;								\
	}									\
	*((uint16_t *) &buf[0]) = size;						\
	memcpy(&buf[2], (uint8_t *) data, size);				\

#define NETWORK_GET_ZERO_ARGS_DATA							\
	uint8_t *data;									\
	uint16_t data_size;								\
	uint16_t max_size = MAILBOX_QUEUE_MSG_SIZE_LARGE - 2;				\
	if (max_size >= 65536) {							\
		printf("Error (%s): max_size not supported\n", __func__);		\
		return NULL;								\
	}										\
	data_size = *((uint16_t *) &buf[0]);						\
	if (data_size > max_size) {							\
		printf("Error (%s): size not supported (%d)\n", __func__, data_size);	\
		return NULL;								\
	}										\
	data = &buf[2];


#define MY_NETWORK_GET_ZERO_ARGS_DATA							\
	uint8_t *data;									\
	uint16_t data_size;								\
	uint16_t max_size = MAILBOX_QUEUE_MSG_SIZE_LARGE - 2;				\
	if (max_size >= 65536) {							\
		printf("Error (%s): max_size not supported\n", __func__);		\
		return NULL;								\
	}										\
	data_size = *((uint16_t *) &net_buf[0]);						\
	if (data_size > max_size) {							\
		printf("Error (%s): size not supported (%d)\n", __func__, data_size);	\
		return NULL;								\
	}										\
	data = &net_buf[2];

#ifdef CONFIG_UML
/* FIXME: copied from include/network/list.h */
/* list head */
struct list_head_new {
	struct list_head_new *prev, *next;
};

/* FIXME: copied from include/network/netif.h */
/* packet buf */
struct pkbuf {
	struct list_head_new pk_list;	/* for ip fragment or arp waiting list */
	unsigned short pk_pro;		/* ethernet packet type ID */
	unsigned short pk_type;		/* packet hardware address type */
	int pk_len;
	int pk_refcnt;
	struct netdev *pk_indev;
	struct rtentry *pk_rtdst;
	struct sock *pk_sk;
	unsigned char pk_data[0];
} __attribute__((packed));
#endif

void ip_send_out(struct pkbuf *pkb);
uint8_t *ip_receive(uint8_t *buf, uint16_t *size);
int syscall_allocate_tcp_socket(unsigned int *saddr, unsigned short *sport,
		unsigned int daddr, unsigned short dport);
int yield_network_access(void);
int request_network_access(int count);
void syscall_close_socket(void);

int net_start_receive(void);
void net_stop_receive(void);
