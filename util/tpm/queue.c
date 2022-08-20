#include <tpm/tpm.h>
#include <tpm/queue.h>
#include <time.h>

/*
 * Simple queue implementation for communication with kernel module.
 * The queue is implemented in the shared memory and
 * works with TPM module and octopos-tpm kernel module.
 *
 * Each processor has its own queue. Each queue can keep at most
 * QUEUE_SIZE's queue entries. When enqueue, the message to be sent
 * is split into multiple small chunks. And each chunk will be wrapped into
 * a queue_entry structure. The structure is then sent to the queue.
 *
 * The messages usually follows following pattern:
 * -----------------------------------------------
 * |A| B|                                       C|
 * -----------------------------------------------
 * A: 1 byte operator or return result
 * B: 2 byte message size
 * C: message body
 */

void open_queue(struct queue_list **in_queues, struct queue_list **out_queues)
{
	int fd = shm_open("/ivshmem", O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		perror("Shared memory not found");
		return;
	}

	*in_queues = (struct queue_list *) mmap(NULL,
						sizeof(struct queue_list),
						PROT_READ | PROT_WRITE,
						MAP_SHARED, fd, 0);
	/* We initialize the queue per page. */
	*out_queues = (struct queue_list *) mmap(NULL,
						 sizeof(struct queue_list),
						 PROT_READ | PROT_WRITE,
						 MAP_SHARED, fd,
						 ((sizeof(struct queue_list) - 1) / PAGE_SIZE + 1) * PAGE_SIZE);
	close(fd);
	if (in_queues == MAP_FAILED || out_queues == MAP_FAILED) {
		perror("Allocation error");
		return;
	}
}

int is_full(struct queue_list *queues, uint8_t proc_id)
{
	if (proc_id == 0 || proc_id > ALL_PROCESSORS)
		return -1;
	return queues->size[proc_id - 1] >= QUEUE_SIZE;
}

int is_empty(struct queue_list *queues, uint8_t proc_id)
{
	if (proc_id == 0 || proc_id > ALL_PROCESSORS)
		return -1;
	return queues->size[proc_id - 1] == 0;
}

uint8_t get_queue_size(struct queue_list *queues, uint8_t proc_id)
{
	return queues->size[proc_id - 1];
}

int send_entry(struct queue_list *queues, uint8_t proc_id,
	       struct queue_entry *entry)
{
	if (is_full(queues, proc_id))
		return E_FULL_QUEUE;
	
	(queues->size[proc_id - 1]) += 1;
	queues->rear[proc_id - 1] = (queues->rear[proc_id - 1] + 1) % QUEUE_SIZE;
	memcpy(&(queues->queue[proc_id - 1][queues->rear[proc_id - 1]]),
	       entry, sizeof(struct queue_entry));

	return 0;
}

int retrieve_entry(struct queue_list *queues, uint8_t proc_id,
		   struct queue_entry *entry)
{
	if (is_empty(queues, proc_id))
		return E_EMPTY_QUEUE;

	(queues->size[proc_id - 1]) -= 1;
	*entry = queues->queue[proc_id - 1][queues->head[proc_id - 1]];
	queues->head[proc_id - 1] = (queues->head[proc_id - 1] + 1) % QUEUE_SIZE;

	return 0;
}

int enqueue(struct queue_list *queues, uint8_t proc_id,
	    uint8_t *buf, size_t buf_size)
{
	size_t transferred_size = 0;
	size_t trunk_size = 0;

	while (transferred_size != buf_size) {
		struct queue_entry entry;
		entry.proc_id = proc_id;
		/* If it's a small message, directly copy the size of the message,
		 * or copy the BUFFER_SIZE.
		 */
		if (buf_size > transferred_size + BUFFER_SIZE) {
			entry.buffer_tag = LARGE_BUFFER;
			trunk_size = BUFFER_SIZE;
		} else {
			entry.buffer_tag = SHORT_BUFFER;
			trunk_size = buf_size - transferred_size;
		}
		memset(entry.buf, 0, BUFFER_SIZE);
		memcpy(entry.buf, buf + transferred_size, trunk_size);

		/* If queue is full, wait to re-enqueue.
		 * Temporary no count mechanisms to prevent stuck.
		 */
		if (send_entry(queues, proc_id, &entry) == E_FULL_QUEUE) {
			sleep(5);
			continue;
		}

		transferred_size += trunk_size;
	}

	return 0;
}

int dequeue(struct queue_list *queues, uint8_t proc_id,
	    uint8_t **buf, size_t *buf_size)
{
	struct queue_entry entry;
	size_t retrieved_size = 0;
	size_t trunk_size = 0;

	/* Allocate buf dynamically from the size in the first chunk.
	 * The caller should free the space.
	 */
	memset(entry.buf, 0, BUFFER_SIZE);
	if (retrieve_entry(queues, proc_id, &entry) == E_EMPTY_QUEUE)
		return E_EMPTY_QUEUE;

	*buf_size = (entry.buf[1] << 8) | entry.buf[2];
	*buf = (uint8_t *) malloc(*buf_size * sizeof(uint8_t));

	/* If it's a small message, directly copy the size of the message,
	 * or copy the BUFFER_SIZE.
	 */
	trunk_size = (*buf_size > BUFFER_SIZE) ? BUFFER_SIZE : *buf_size;
	memcpy(*buf, entry.buf, trunk_size);
	retrieved_size += trunk_size;

	while (retrieved_size != *buf_size) {
		memset(entry.buf, 0, BUFFER_SIZE);
		/* If queue is empty, wait to re-enqueue.
		 * Temporary no count mechanisms to prevent stuck.
		 */
		if (retrieve_entry(queues, proc_id, &entry) == E_EMPTY_QUEUE) {
			sleep(5);
			continue;
		}

		if (*buf_size > retrieved_size + BUFFER_SIZE) {
			trunk_size = BUFFER_SIZE;
		} else {
			trunk_size = *buf_size - retrieved_size;
		}
		memcpy(*buf + retrieved_size, entry.buf, trunk_size);

		retrieved_size += trunk_size;
	}

	return 0;
}

void close_queue(struct queue_list *in_queues, struct queue_list *out_queues)
{
	if (munmap(in_queues, sizeof(struct queue_list)) == -1) {
		perror("Unmapping in_queues failed\n");
	}
	if (munmap(out_queues, sizeof(struct queue_list)) == -1) {
		perror("Unmapping out_queues failed\n");
	}
	if (shm_unlink("/ivshmem") == -1) {
		perror("Unlink failed\n");
	}
}