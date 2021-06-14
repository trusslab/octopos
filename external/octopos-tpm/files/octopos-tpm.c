/* OctopOS driver for creating a TPM node
 * Copyright (C) 2020 Ardalan Amiri Sani <arrdalan@gmail.com> */

/* Template based on octopos/untrusted/octopos_mailbox.c,
 * 		     arch/um/drivers/random.c
 */
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <linux/kernel.h>
#include <linux/pci.h>

#define OM_MODULE_NAME "octopos_tpm"
/* check include/linux/miscdevice.h to make sure this is not taken. */
#define OM_MINOR		244

/* Red Hat, Inc. Inter-VM shared memory PCIe device */
#define VENDOR_ID		0x1af4
#define DEVICE_ID		0x1110
#define BAR_NUMBER		2
#define PAGE_SIZE		4096

#define MAILBOX_QUEUE_MSG_SIZE	64

#define ALL_PROCESSORS	10

/* TPM ops */
#define OP_MEASURE		0x01
#define OP_READ			0x02
#define OP_ATTEST		0x03
#define OP_RESET		0x04

#define SHORT_BUFFER	0
#define LARGE_BUFFER	1
#define BUFFER_SIZE		65
#define QUEUE_SIZE		64

#define E_FULL_QUEUE	0x01
#define E_EMPTY_QUEUE	0x02

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

void open_queue(void __iomem **in, void __iomem **out);
int is_full(void __iomem *queues, uint8_t proc_id);
int is_empty(void __iomem *queues, uint8_t proc_id);
int enqueue(void __iomem *queues, uint8_t *buf, uint8_t proc_id);
int dequeue(void __iomem *queues, uint8_t *buf, uint8_t proc_id);
uint8_t get_queue_size(void __iomem *queues, uint8_t proc_id);

size_t queue_list_size = sizeof(struct queue_list);

size_t queue_offset = offsetof(struct queue_list, queue);
size_t size_offset = offsetof(struct queue_list, size);
size_t head_offset = offsetof(struct queue_list, head);
size_t rear_offset = offsetof(struct queue_list, rear);

size_t proc_id_offset = offsetof(struct queue_entry, proc_id);
size_t buffer_tag_offset = offsetof(struct queue_entry, buffer_tag);
size_t buf_offset = offsetof(struct queue_entry, buf);

void __iomem *in_queues;
void __iomem *out_queues;

void open_queue(void __iomem **in, void __iomem **out)
{
	struct pci_dev *dev = NULL;
	uint8_t proc_id = 1;

	while ((dev = pci_get_device(VENDOR_ID, DEVICE_ID, dev))) {
		if (pci_enable_device(dev))
			break;
		if (pci_request_regions(dev, "Inter-VM shared memory"))
			break;
		*in = pci_iomap(dev, 2, 0);
		*out = *in + ((queue_list_size - 1) / PAGE_SIZE + 1) * PAGE_SIZE;

		for (; proc_id <= ALL_PROCESSORS; proc_id++) {
			iowrite8(0, *in + size_offset + proc_id - 1);
			iowrite8(1, *in + head_offset + proc_id - 1);
			iowrite8(0, *in + rear_offset + proc_id - 1);

			iowrite8(0, *out + size_offset + proc_id - 1);
			iowrite8(1, *out + head_offset + proc_id - 1);
			iowrite8(0, *out + rear_offset + proc_id - 1);
		}

		return;
	}
	
	printk(KERN_ERR OM_MODULE_NAME ": open_queue failed\n");
	return;
}

int is_full(void __iomem *queues, uint8_t proc_id)
{
	uint8_t queue_size;
	if (proc_id == 0 || proc_id > ALL_PROCESSORS)
		return -1;
	
	queue_size = ioread8(queues + size_offset + proc_id - 1);
	return queue_size >= QUEUE_SIZE;
}

int is_empty(void __iomem *queues, uint8_t proc_id)
{
	uint8_t queue_size;

	if (proc_id == 0 || proc_id > ALL_PROCESSORS)
		return -1;
	
	queue_size = ioread8(queues + size_offset + proc_id - 1);
	return queue_size == 0;
}

int enqueue(void __iomem *queues, uint8_t *buf, uint8_t proc_id)
{
	void __iomem *entry;
	uint8_t queue_size;
	uint8_t rear_value;
	size_t i = 0;

	if (is_full(queues, proc_id))
		return E_FULL_QUEUE;
	
	queue_size = ioread8(queues + size_offset + proc_id - 1);
	iowrite8(queue_size + 1, queues + size_offset + proc_id - 1);
	
	rear_value = ioread8(queues + rear_offset + proc_id - 1);
	iowrite8((rear_value + 1) % QUEUE_SIZE, queues + rear_offset + proc_id - 1);

	entry = queues + queue_offset + ((proc_id - 1) * QUEUE_SIZE + (rear_value + 1) % QUEUE_SIZE) * sizeof(struct queue_entry);
	iowrite8(proc_id, entry + proc_id_offset);
	iowrite8(buf[0], entry + buffer_tag_offset);

	for (; i < BUFFER_SIZE; i++) {
		iowrite8(buf[1 + i], entry + buf_offset + i);
	}

	// iowrite8_rep(queues + queue_offset + ((proc_id - 1) * QUEUE_SIZE + (rear_value + 1) % QUEUE_SIZE) * sizeof(struct queue_entry), &q, sizeof(struct queue_entry));

	return 0;
}

int dequeue(void __iomem *queues, uint8_t *buf, uint8_t proc_id)
{
	struct queue_entry q;
	void __iomem *entry;
	uint8_t queue_size;
	uint8_t head_value;
	size_t i = 0;

	if (is_empty(queues, proc_id))
		return E_EMPTY_QUEUE;

	queue_size = ioread8(queues + size_offset + proc_id - 1);
	iowrite8(queue_size - 1, queues + size_offset + proc_id - 1);

	head_value = ioread8(queues + head_offset + proc_id - 1);
	iowrite8((head_value + 1) % QUEUE_SIZE, queues + head_offset + proc_id - 1);

	entry = queues + queue_offset + ((proc_id - 1) * QUEUE_SIZE + head_value) * sizeof(struct queue_entry);
	q.proc_id = ioread8(entry + proc_id_offset);
	q.buffer_tag = ioread8(entry + buffer_tag_offset);
	for (; i < BUFFER_SIZE; i++) {
		q.buf[i] = ioread8(entry + buf_offset + i);
	}

	memcpy(buf, q.buf, BUFFER_SIZE);

	return 0;
}

uint8_t get_queue_size(void __iomem *queues, uint8_t proc_id)
{
	size_t size_offset = offsetof(struct queue_list, size);
	uint8_t value = ioread8(queues + size_offset + proc_id - 1);
	return value;
}

static int does_proc_have_message(int proc_id)
{
	return !is_empty(in_queues, proc_id);
}

static void recv_msg_from_proc(uint8_t *buf, uint8_t proc_id)
{
	/* Determine the incoming queue of the proc and read */
	dequeue(in_queues, buf, proc_id);
}

static void send_msg_to_proc(uint8_t *buf, uint8_t proc_id)
{
	/* Determine the outgoing queue of the proc and write */
	enqueue(out_queues, buf, proc_id);
}

int next_proc = 1;

static void get_next_tpm_request(uint8_t *buf, uint8_t *proc_id)
{
	int ret = 0;

	/* get requests from queues in a round robin fashion. */
	while (!ret) {
		ret = does_proc_have_message(next_proc);
		if (ret) {
			recv_msg_from_proc(buf, next_proc);
			*proc_id = next_proc;
		}

		next_proc++;
		if (next_proc > 10)
			next_proc = 1;
	}
}

static void send_tpm_response(uint8_t *buf, uint8_t proc_id)
{
	send_msg_to_proc(buf, proc_id);
}
/************************************************/

struct semaphore mutex;
uint8_t current_proc;

static int otpm_dev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t otpm_dev_read(struct file *filp, char __user *buf, size_t size,
			   loff_t *offp)
{
	uint8_t req_buf[MAILBOX_QUEUE_MSG_SIZE + 2];
	int ret;
 
	if (size != (MAILBOX_QUEUE_MSG_SIZE + 2))
		return 0;

	down(&mutex);

	get_next_tpm_request(&req_buf[1], &current_proc);
	req_buf[0] = current_proc;

	ret = copy_to_user(buf, req_buf, size);
	if (ret != 0) {
        printk("Failed to send characters to user.\n");
        return -EFAULT;
    }

	return (size - ret);
}

static ssize_t otpm_dev_write(struct file *filp, const char __user *buf,
			      size_t size, loff_t *offp)
{
	uint8_t resp_buf[MAILBOX_QUEUE_MSG_SIZE + 2];
	int ret;
 
	if (size != (MAILBOX_QUEUE_MSG_SIZE + 2))
		return 0;

	memset(resp_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE + 2);


	ret = copy_from_user(resp_buf, buf, size);
	if (ret != 0) {
        printk("Failed to read characters from user.\n");
        return -EFAULT;
    }

	send_tpm_response(resp_buf, current_proc);

	if (resp_buf[0] == SHORT_BUFFER)
		up(&mutex);
	
	return (size - ret);
}

static const struct file_operations otpm_chrdev_ops = {
	.owner		= THIS_MODULE,
	.open		= otpm_dev_open,
	.read		= otpm_dev_read,
	.write		= otpm_dev_write,
};

static struct miscdevice otpm_miscdev = {
	OM_MINOR,
	OM_MODULE_NAME,
	&otpm_chrdev_ops,
};

static int __init otpm_init(void)
{
	int err;

	printk("%s [1]\n", __func__);
	/* register char dev */
	err = misc_register(&otpm_miscdev);
	if (err) {
		printk(KERN_ERR OM_MODULE_NAME ": misc device register "
		       "failed\n");
		return err;
	}

	sema_init(&mutex, 1);

	open_queue(&in_queues, &out_queues);

	return 0;
}

static void __exit otpm_cleanup(void)
{
	misc_deregister(&otpm_miscdev);
}

module_init(otpm_init);
module_exit(otpm_cleanup);

MODULE_DESCRIPTION("OctopOS driver for creating a TPM node");
MODULE_LICENSE("GPL");

