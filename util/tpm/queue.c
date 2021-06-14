#include <tpm/tpm.h>
#include <tpm/queue.h>

void open_queue(struct queue_list **in_queues, struct queue_list **out_queues)
{
	int fd = shm_open("/ivshmem", O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		perror("Shared memory not found");
		return;
	}

	*in_queues = (struct queue_list *) mmap(NULL, sizeof(struct queue_list), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	*out_queues = (struct queue_list *) mmap(NULL, sizeof(struct queue_list), PROT_READ | PROT_WRITE, MAP_SHARED, fd, ((sizeof(struct queue_list) - 1) / PAGE_SIZE + 1) * PAGE_SIZE);
	close(fd);
	if (in_queues == MAP_FAILED || out_queues == MAP_FAILED) {
		perror("mmap allocation error");
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

int enqueue(struct queue_list *queues, uint8_t *buf, uint8_t proc_id)
{
	if (is_full(queues, proc_id))
		return E_FULL_QUEUE;

	struct queue_entry q;
	q.proc_id = proc_id;
	q.buffer_tag = SHORT_BUFFER;
	memcpy(q.buf, buf, BUFFER_SIZE);
	
	(queues->size[proc_id - 1]) += 1;
	queues->rear[proc_id - 1] = (queues->rear[proc_id - 1] + 1) % QUEUE_SIZE;
	memcpy(&(queues->queue[proc_id - 1][queues->rear[proc_id - 1]]), &q, sizeof(struct queue_entry));

	return 0;
}

int dequeue(struct queue_list *queues, uint8_t **buf, size_t *size, uint8_t proc_id)
{
	size_t buffer_off = 0;
	struct queue_entry q;

	if (is_empty(queues, proc_id))
		return E_EMPTY_QUEUE;

	(queues->size[proc_id - 1]) -= 1;
	q = queues->queue[proc_id - 1][queues->head[proc_id - 1]];
	queues->head[proc_id - 1] = (queues->head[proc_id - 1] + 1) % QUEUE_SIZE;
	if (q.buf[0]) 
		return E_ERROR_TPM;
	
	if (q.buffer_tag == SHORT_BUFFER) {
		*size = BUFFER_SIZE - 1;
	} else {
		*size = (q.buf[1] << 8) + q.buf[2];
	}
	*buf = (uint8_t *) malloc(*size * sizeof(uint8_t));
	memcpy(*buf, q.buf + 1, BUFFER_SIZE - 1);
	buffer_off += BUFFER_SIZE - 1;

	while (q.buffer_tag == LARGE_BUFFER) {
		(queues->size[proc_id - 1]) -= 1;
		q = queues->queue[proc_id - 1][queues->head[proc_id - 1]];
		memcpy(*buf + buffer_off, q.buf + 1, BUFFER_SIZE - 1);
		queues->head[proc_id - 1] = (queues->head[proc_id - 1] + 1) % QUEUE_SIZE;
		buffer_off += (BUFFER_SIZE - 1);
	}

	return 0;
}

uint8_t get_queue_size(struct queue_list *queues, uint8_t proc_id)
{
	return queues->size[proc_id - 1];
}