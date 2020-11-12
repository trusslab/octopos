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
#include <linux/timer.h>
#include <init.h>
#include <irq_kern.h>
#include <os.h>
#define UNTRUSTED_DOMAIN
#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/mailbox_umode.h>

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

bool om_inited = false;

spinlock_t mailbox_lock;

limit_t queue_limits[NUM_QUEUES + 1];
timeout_t queue_timeouts[NUM_QUEUES + 1];
void (*queue_timeout_update_callbacks[NUM_QUEUES + 1])(uint8_t queue_id,
						       timeout_t timeout);

static struct timer_list timer;

void callback_timer(struct timer_list *_timer)
{
	int i;

	mod_timer(&timer, jiffies + msecs_to_jiffies(1000));	
	
	for (i = 1; i <= NUM_QUEUES; i++) {
		if (queue_timeouts[i] &&
		    (queue_timeouts[i] != MAILBOX_NO_TIMEOUT_VAL)) {
			queue_timeouts[i]--;
			if (queue_timeout_update_callbacks[i])
				(*queue_timeout_update_callbacks[i])(i, queue_timeouts[i]);
		}
	}

}

void register_timeout_update_callback(uint8_t queue_id,
				      void (*callback)(uint8_t, timeout_t))
{
	if (queue_id < 1 || queue_id > NUM_QUEUES) {
		printk("Error: %s: invalid queue id (%d)\n", __func__, queue_id);
		return;
	}

	if (queue_timeout_update_callbacks[queue_id]) {
		printk("Error: %s: queue timeout update callback for queue %d is already "
		       "registered\n", __func__, queue_id);
		return;
	}

	queue_timeout_update_callbacks[queue_id] = callback;
}

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
	size_t per_msg_size = MAILBOX_QUEUE_MSG_SIZE - 3;
	ssize_t total_size = 0;

	/* We're informing the OS of termination.
	 * Therefore, we'll have to finish everything in
	 * this function. Won't be able to send more later.
	 */
	if (*offp != 0)
		return 0;
 
	while (size > 0) {

		if (size < per_msg_size)
			per_msg_size = size;

		size -= per_msg_size;

		ret = copy_from_user(data, buf + total_size, per_msg_size);
		*offp += (per_msg_size - ret);

		write_to_shell(data, per_msg_size - ret);

		total_size += (per_msg_size - ret);

		if (ret) {
			printk("Error: %s: copy_from_user failed to fully copy. Won't continue.\n", __func__);
			break;
		}
	}

	inform_os_of_termination();

	return total_size;
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
	unsigned long flags;

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	/* wait for message */
	down(&interrupts[queue_id]);
	spin_lock_irqsave(&mailbox_lock, flags);
	os_write_file(fd_out, opcode, 2), 
	os_read_file(fd_in, buf, queue_msg_size);
	spin_unlock_irqrestore(&mailbox_lock, flags);
}

static void recv_msg_from_queue_no_wait(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];
	unsigned long flags;

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	spin_lock_irqsave(&mailbox_lock, flags);
	os_write_file(fd_out, opcode, 2), 
	os_read_file(fd_in, buf, queue_msg_size);
	spin_unlock_irqrestore(&mailbox_lock, flags);
}

void send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];
	unsigned long flags;

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	down(&interrupts[queue_id]);
	spin_lock_irqsave(&mailbox_lock, flags);
	os_write_file(fd_out, opcode, 2);
	os_write_file(fd_out, buf, queue_msg_size);
	spin_unlock_irqrestore(&mailbox_lock, flags);
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
void mailbox_yield_to_previous_owner(uint8_t queue_id)
{
	uint8_t opcode[2];
	unsigned long flags;

	queue_limits[queue_id] = 0;
	queue_timeouts[queue_id] = 0;

	opcode[0] = MAILBOX_OPCODE_YIELD_QUEUE_ACCESS;
	opcode[1] = queue_id;
	spin_lock_irqsave(&mailbox_lock, flags);
	os_write_file(fd_out, opcode, 2);
	spin_unlock_irqrestore(&mailbox_lock, flags);
}

/* FIXME: adapted from the same func in mailbox_runtime.c */
int mailbox_attest_queue_access(uint8_t queue_id, limit_t limit,
				timeout_t timeout)
{
	uint8_t opcode[2];
	mailbox_state_reg_t state;
	unsigned long flags;

	opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
	opcode[1] = queue_id;
	spin_lock_irqsave(&mailbox_lock, flags);
	os_write_file(fd_out, opcode, 2);
	os_read_file(fd_in, &state, sizeof(mailbox_state_reg_t));
	spin_unlock_irqrestore(&mailbox_lock, flags);

	if (state.limit && (state.limit != MAILBOX_NO_LIMIT_VAL))
		queue_limits[queue_id] = state.limit;

	if (state.timeout && (state.timeout != MAILBOX_NO_TIMEOUT_VAL))
		queue_timeouts[queue_id] = state.timeout;

	return ((state.limit == limit) && (state.timeout == timeout));
}

/* FIXME: adapted from the same func in mailbox_runtime.c */
void reset_queue_sync(uint8_t queue_id, int init_val)
{
	sema_init(&interrupts[queue_id], init_val);
}

limit_t get_queue_limit(uint8_t queue_id)
{
	return queue_limits[queue_id];
}

timeout_t get_queue_timeout(uint8_t queue_id)
{
	return queue_timeouts[queue_id];
}

void decrement_queue_limit(uint8_t queue_id, limit_t count)
{
	if (queue_limits[queue_id] <= count)
		queue_limits[queue_id] = 0;
	else
		queue_limits[queue_id] -= count;
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
		if (n != 1)
			break;
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

	spin_lock_init(&mailbox_lock);

	memset(queue_limits, 0x0, sizeof(queue_limits));
	memset(queue_timeouts, 0x0, sizeof(queue_timeouts));
	memset(queue_timeout_update_callbacks, 0x0, sizeof(queue_timeout_update_callbacks));

	timer_setup(&timer, callback_timer, 0);
	mod_timer(&timer, jiffies + msecs_to_jiffies(1000));	

	/* register char dev */
	err = misc_register(&om_miscdev);
	if (err) {
		printk(KERN_ERR OM_MODULE_NAME ": misc device register "
		       "failed\n");
		return err;
	}

	om_inited = true;

	return 0;
}

static void cleanup(void)
{
	free_irq_by_fd(fd_intr);
}

static void __exit om_cleanup(void)
{
	del_timer(&timer);

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
