#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define PAGE_SIZE 		4096
#define ALL_PROCESSORS		10

#define SHORT_BUFFER		0
#define LARGE_BUFFER		1
#define BUFFER_SIZE		65
#define QUEUE_SIZE		64
#define MAX_BUFFER_SIZE		(QUEUE_SIZE * BUFFER_SIZE)

#define RET_SUCCESS		0
#define RET_FAILURE		1

#define E_FULL_QUEUE		0x01
#define E_EMPTY_QUEUE		0x02
#define E_ERROR_TPM		0x03

struct queue_entry {
	uint8_t proc_id;
	uint8_t buffer_tag;
	uint8_t buf[BUFFER_SIZE];
};

struct queue_list {
	struct queue_entry queue[ALL_PROCESSORS][QUEUE_SIZE];
	uint8_t size[ALL_PROCESSORS];
	uint8_t head[ALL_PROCESSORS];
	uint8_t rear[ALL_PROCESSORS];
};

void open_queue(struct queue_list **in_queues, struct queue_list **out_queues);
int is_full(struct queue_list *queues, uint8_t proc_id);
int is_empty(struct queue_list *queues, uint8_t proc_id);
uint8_t get_queue_size(struct queue_list *queues, uint8_t proc_id);
int send_entry(struct queue_list *queues, uint8_t proc_id,
	       struct queue_entry *entry);
int retrieve_entry(struct queue_list *queues, uint8_t proc_id,
		   struct queue_entry *entry);
int enqueue(struct queue_list *queues, uint8_t proc_id,
	    uint8_t *buf, size_t buf_size);
int dequeue(struct queue_list *queues, uint8_t proc_id,
	    uint8_t **buf, size_t *buf_size);
void close_queue(struct queue_list *in_queues, struct queue_list *out_queues);