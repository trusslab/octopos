/* OctopOS driver for Linux
 * Copyright (C) 2020 Ardalan Amiri Sani <arrdalan@gmail.com> */

/* Template based on arch/um/drivers/random.c
 */
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <init.h>
#include <irq_kern.h>
#include <os.h>
#define UNTRUSTED_DOMAIN
#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>

#define OM_MODULE_NAME "octopos_mailbox"
/* check include/linux/miscdevice.h to make sure this is not taken. */
#define OM_MINOR		243

/* FIXME: move to a header file */
void recv_msg_from_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size);
void send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size);
int handle_mailbox_interrupts(void *data);
int init_octopos_mailbox_interface(void);
void close_octopos_mailbox_interface(void);

int fd_out, fd_in, fd_intr;
struct semaphore interrupts[NUM_QUEUES + 1];

struct semaphore cmd_sem;
uint8_t cmd_buf[MAILBOX_QUEUE_MSG_SIZE - 1];

/* FIXME: very similar to the same queue in runtime.c */
uint8_t **syscall_resp_queue;
int srq_size;
int srq_msg_size;
int srq_head;
int srq_tail;
int srq_counter;
struct semaphore srq_sem;

/* FIXME: modified from the same functin in runtime.c */
int write_syscall_response(uint8_t *buf)
{
	down(&srq_sem);

	if (srq_counter >= srq_size) {
		printk("Error: syscall response queue is full\n");
		BUG();
	}

	srq_counter++;
	memcpy(syscall_resp_queue[srq_tail], buf, srq_msg_size);
	srq_tail = (srq_tail + 1) % srq_size;

	return 0;
}

/* FIXME: modified from the same functin in runtime.c */
static int read_syscall_response(uint8_t *buf)
{
	if (srq_counter <= 0) {
		printk("Error: syscall response queue is empty\n");
		BUG();
	}

	srq_counter--;
	memcpy(buf, syscall_resp_queue[srq_head], srq_msg_size);
	srq_head = (srq_head + 1) % srq_size;

	up(&srq_sem);

	return 0;
}

int issue_syscall(uint8_t *buf)
{
	send_msg_on_queue(buf, Q_OSU, MAILBOX_QUEUE_MSG_SIZE);

	/* wait on queue */
	down(&interrupts[Q_UNTRUSTED]);
	read_syscall_response(buf);
	
	return 0;
}

static int write_to_shell(char *data, int size)
{
	int ret;

	SYSCALL_SET_ZERO_ARGS_DATA(SYSCALL_WRITE_TO_SHELL, data, size)
	ret = issue_syscall(buf);
	if (ret)
		return ret;

	SYSCALL_GET_ONE_RET
	return (int) ret0;
}

static int inform_os_of_termination(void)
{
	int ret;

	SYSCALL_SET_ZERO_ARGS(SYSCALL_INFORM_OS_OF_TERMINATION)
	ret = issue_syscall(buf);
	if (ret)
		return ret;

	SYSCALL_GET_ONE_RET
	return (int) ret0;
}

static int om_dev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t om_dev_read(struct file *filp, char __user *buf, size_t size,
			   loff_t *offp)
{
	int datasize, ret;

	if (*offp != 0)
		return 0;
  
	/* wait for cmd */
	down(&cmd_sem);

	datasize = MAILBOX_QUEUE_MSG_SIZE - 1;
	if (size < datasize)
		datasize = size;
	
	ret = copy_to_user(buf, cmd_buf, datasize);
	*offp += (datasize - ret);

	return (datasize - ret);
}

static ssize_t om_dev_write(struct file *filp, const char __user *buf, size_t size,
			    loff_t *offp)
{
	char data[MAILBOX_QUEUE_MSG_SIZE];
	int ret;

	if (*offp != 0)
		return 0;
  
	if (size > MAILBOX_QUEUE_MSG_SIZE) {
		printk("Error: %s: invalid size (%d). Can't be larger than %d.\n",
		       __func__, (int) size, MAILBOX_QUEUE_MSG_SIZE);
		return -EINVAL;
	}

	ret = copy_from_user(data, buf, size);
	*offp += (size - ret);

	write_to_shell(data, size - ret);
	inform_os_of_termination();

	return (size - ret);
}

static const struct file_operations om_chrdev_ops = {
	.owner		= THIS_MODULE,
	.open		= om_dev_open,
	.read		= om_dev_read,
	.write		= om_dev_write,
};

static struct miscdevice om_miscdev = {
	OM_MINOR,
	OM_MODULE_NAME,
	&om_chrdev_ops,
};

void recv_msg_from_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	/* wait for message */
	down(&interrupts[queue_id]);
	os_write_file(fd_out, opcode, 2), 
	os_read_file(fd_in, buf, queue_msg_size);
}

static void recv_msg_from_queue_no_wait(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	os_write_file(fd_out, opcode, 2), 
	os_read_file(fd_in, buf, queue_msg_size);
}

void send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	down(&interrupts[queue_id]);
	os_write_file(fd_out, opcode, 2);
	os_write_file(fd_out, buf, queue_msg_size);
}

/* FIXME: modified from arch/umode/mailbox_interface/mailbox_runtime.c 
 * Rename and consolidate.
 */
void runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id)
{
	return recv_msg_from_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE);
}

/* FIXME: modified from arch/umode/mailbox_interface/mailbox_runtime.c 
 * Rename and consolidate.
 */
void runtime_send_msg_on_queue(uint8_t *buf, uint8_t queue_id)
{
	return send_msg_on_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE);
}

/* FIXME: modified from arch/umode/mailbox_interface/mailbox_runtime.c 
 * Rename and consolidate.
 */
void runtime_recv_msg_from_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return recv_msg_from_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

/* FIXME: modified from arch/umode/mailbox_interface/mailbox_runtime.c 
 * Rename and consolidate.
 */
void runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id)
{
	return send_msg_on_queue(buf, queue_id, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

/* FIXME: adapted from the same func in mailbox_runtime.c */
void queue_sync_getval(uint8_t queue_id, int *val)
{
	*val = interrupts[queue_id].count;
}

/* FIXME: copied with no changes from the same func in runtime.c */
/* Only to be used for queues that runtime writes to */
/* FIXME: busy-waiting */
void wait_until_empty(uint8_t queue_id, int queue_size)
{
	int left;

	while (1) {
		queue_sync_getval(queue_id, &left);
		if (left == queue_size)
			break;
	}
}

/* FIXME: adapted from the same func in mailbox_runtime.c */
void mailbox_change_queue_access(uint8_t queue_id, uint8_t access, uint8_t proc_id)
{
	uint8_t opcode[4];

	opcode[0] = MAILBOX_OPCODE_CHANGE_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	opcode[3] = proc_id;
	os_write_file(fd_out, opcode, 4);
}

/* FIXME: adapted from the same func in mailbox_runtime.c */
int mailbox_attest_queue_access(uint8_t queue_id, uint8_t access, uint8_t count)
{
	uint8_t opcode[4], ret;

	opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	opcode[3] = count;
	os_write_file(fd_out, opcode, 4);
	os_read_file(fd_in, &ret, 1);

	return (int) ret;
}

/* FIXME: adapted from the same func in mailbox_runtime.c */
void reset_queue_sync(uint8_t queue_id, int init_val)
{
	sema_init(&interrupts[queue_id], init_val);
}

/* FIXME: move somewhere else */
void *ond_tcp_receive(void);

static struct work_struct net_wq;

static void net_receive_wq(struct work_struct *work)
{
	ond_tcp_receive();
}

static irqreturn_t om_interrupt(int irq, void *data)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t interrupt;
	int n;

	while (true) {
		n = os_read_file(fd_intr, &interrupt, 1);
		printf("%s [1]: n = %d\n", __func__, n);
		if (n != 1)
			break;
		printf("%s [2]: interrupt = %d\n", __func__, interrupt);
		if (interrupt == Q_UNTRUSTED) {
			recv_msg_from_queue_no_wait(buf, Q_UNTRUSTED, MAILBOX_QUEUE_MSG_SIZE);
			if (buf[0] == RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG) {
				write_syscall_response(buf);
				up(&interrupts[Q_UNTRUSTED]);
			} else if (buf[0] == RUNTIME_QUEUE_EXEC_APP_TAG) {
				memcpy(cmd_buf, &buf[1], MAILBOX_QUEUE_MSG_SIZE - 1);
				up(&cmd_sem);
			} else {
				printk("Error: %s: received invalid message (%d).\n", __func__, buf[0]);
				BUG();
			}
		} else if (interrupt == Q_OSU ||
		    interrupt == Q_STORAGE_CMD_IN || interrupt == Q_STORAGE_CMD_OUT ||
		    interrupt == Q_STORAGE_DATA_IN || interrupt == Q_STORAGE_DATA_OUT ||
		    interrupt == Q_NETWORK_DATA_IN || interrupt == Q_NETWORK_DATA_OUT) {
			if (interrupt == Q_NETWORK_DATA_OUT)
				schedule_work(&net_wq);
			up(&interrupts[interrupt]);
		} else if (interrupt > NUM_QUEUES && interrupt <= (2 * NUM_QUEUES)) {
			/* ignore the ownership change interrupts */
		} else {
			printk("Error: interrupt from an invalid queue (%d)\n", interrupt);
			BUG();
		}
	}
	return IRQ_HANDLED;
}

/* FIXME: modified from runtime.c */
static uint8_t **allocate_memory_for_queue(int queue_size, int msg_size)
{
	int i;
	uint8_t **messages = (uint8_t **) kmalloc(queue_size * sizeof(uint8_t *), GFP_KERNEL);
	if (!messages) {
		printk("Error: couldn't allocate memory for a queue\n");
		BUG();
	}
	for (i = 0; i < queue_size; i++) {
		messages[i] = (uint8_t *) kmalloc(msg_size, GFP_KERNEL);
		if (!messages[i]) {
			printk("Error: couldn't allocate memory for a queue\n");
			BUG();
		}
	}

	return messages;
}

static int __init om_init(void)
{
	int err;

	err = init_octopos_mailbox_interface();
	if (err) {
		printk(KERN_ERR OM_MODULE_NAME ": initializing mailbox interface "
		       "failed\n");
		return err;
	}

	fd_out = os_open_file(FIFO_UNTRUSTED_OUT, of_write(OPENFLAGS()), 0);
	if (fd_out < 0) {
		printk(KERN_ERR OM_MODULE_NAME ": opening out file "
		       "failed\n");
		return fd_out;
	}

	fd_in = os_open_file(FIFO_UNTRUSTED_IN, of_read(OPENFLAGS()), 0);
	if (fd_in < 0) {
		printk(KERN_ERR OM_MODULE_NAME ": opening in file "
		       "failed\n");
		return fd_in;
	}

	fd_intr = os_open_file(FIFO_UNTRUSTED_INTR, of_read(OPENFLAGS()), 0);
	if (fd_intr < 0) {
		printk(KERN_ERR OM_MODULE_NAME ": opening intr file "
		       "failed\n");
		return fd_intr;
	}
	os_set_fd_block(fd_intr, 0);

	err = um_request_irq(OCTOPOS_IRQ, fd_intr, IRQ_READ, om_interrupt,
			     0, "octopos", NULL);
	if (err) {
		printk(KERN_ERR OM_MODULE_NAME ": interrupt register "
		       "failed\n");
		return err;
	}

	/* FIXME: is this needed? */
	//sigio_broken(fd_intr, 1);

	sema_init(&interrupts[Q_OSU], MAILBOX_QUEUE_SIZE);
	sema_init(&interrupts[Q_UNTRUSTED], 0);
	
	sema_init(&cmd_sem, 0);

	/* FIXME: very similar to runtime.c */
	/* initialize syscall response queue */
	/* FIXME: release memory on exit */
	syscall_resp_queue = allocate_memory_for_queue(MAILBOX_QUEUE_SIZE, MAILBOX_QUEUE_MSG_SIZE);
	srq_size = MAILBOX_QUEUE_SIZE;
	srq_msg_size = MAILBOX_QUEUE_MSG_SIZE;
	srq_counter = 0;
	srq_head = 0;
	srq_tail = 0;

	sema_init(&srq_sem, MAILBOX_QUEUE_SIZE);

	INIT_WORK(&net_wq, net_receive_wq);

	/* register char dev */
	err = misc_register(&om_miscdev);
	if (err) {
		printk(KERN_ERR OM_MODULE_NAME ": misc device register "
		       "failed\n");
		return err;
	}

	return 0;
}

static void cleanup(void)
{
	free_irq_by_fd(fd_intr);
}

static void __exit om_cleanup(void)
{
	os_close_file(fd_out);
	os_close_file(fd_in);
	os_close_file(fd_intr);

	close_octopos_mailbox_interface();
	
	misc_deregister(&om_miscdev);
}

module_init(om_init);
module_exit(om_cleanup);
__uml_exitcall(cleanup);

MODULE_DESCRIPTION("OctopOS mailbox driver for UML");
MODULE_LICENSE("GPL");