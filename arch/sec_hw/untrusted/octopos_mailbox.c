/* OctopOS driver for Linux
 * Copyright (C) 2020 Ardalan Amiri Sani <arrdalan@gmail.com> */

/* Template based on arch/um/drivers/random.c
 */
#ifdef CONFIG_ARM64

#include <linux/sched/signal.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>
#include <linux/init.h>
#include <linux/slab.h>
#define UNTRUSTED_DOMAIN
#define ARCH_SEC_HW
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

u32 octopos_mailbox_get_status_reg(struct octopos_mbox_ctrl *mbox_ctrl);
int octopos_mailbox_attest_owner_fast_hw(struct octopos_mbox_ctrl *mbox_ctrl);
void mailbox_yield_to_previous_owner_hw(struct octopos_mbox_ctrl *mbox_ctrl);

int xilinx_mbox_send_data_blocking(struct xilinx_mbox *mbox, 
	u32 *buffer, u32 buffer_size);
int xilinx_mbox_receive_data_blocking(struct xilinx_mbox *mbox, 
	u32 *buffer, u32 buffer_size);

extern void* mbox_map[NUM_QUEUES + 1];
extern void* mbox_ctrl_map[NUM_QUEUES + 1];

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

//struct semaphore mailbox_lock;
spinlock_t mailbox_lock;

limit_t queue_limits[NUM_QUEUES + 1];
timeout_t queue_timeouts[NUM_QUEUES + 1];
void (*queue_timeout_update_callbacks[NUM_QUEUES + 1])(uint8_t queue_id,
						       timeout_t timeout);

static struct timer_list timer;

void callback_timer(struct timer_list *_timer)
{
	int i;

	mod_timer(&timer, jiffies + msecs_to_jiffies(100));	
	
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
	printk("%s: receive command from OS\n", __func__);

	datasize = MAILBOX_QUEUE_MSG_SIZE - 1;
	if (size < datasize)
		datasize = size;

	/* sec_hw new line is \r */
#ifdef CONFIG_ARM64
	cmd_buf[strlen(cmd_buf) - 1] = '\n';
#endif
	
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
	unsigned long flags;

	/* wait for message */
	// FIXME: There is a bug preventing semaphore post on Q_STORAGE_DATA_IN
	// printk("%s %d %d %d", __func__, queue_id, queue_msg_size, interrupts[queue_id].count);
	// down(&interrupts[queue_id]);
	spin_lock_irqsave(&mailbox_lock, flags);
	xilinx_mbox_receive_data_blocking(mbox_map[queue_id],
		(u32*) buf,
		queue_msg_size);
	spin_unlock_irqrestore(&mailbox_lock, flags);
}

static void recv_msg_from_queue_no_wait(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	unsigned long flags;

	spin_lock_irqsave(&mailbox_lock, flags);
	xilinx_mbox_receive_data_blocking(mbox_map[queue_id],
		(u32*) buf,
		queue_msg_size);
	spin_unlock_irqrestore(&mailbox_lock, flags);
}

void send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	unsigned long flags;

	down(&interrupts[queue_id]);
	spin_lock_irqsave(&mailbox_lock, flags);
	xilinx_mbox_send_data_blocking(mbox_map[queue_id],
		(u32*) buf,
		queue_msg_size);
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
	unsigned long flags;

	spin_lock_irqsave(&mailbox_lock, flags);
	mailbox_yield_to_previous_owner_hw(mbox_ctrl_map[queue_id]);
	spin_unlock_irqrestore(&mailbox_lock, flags);
}

/* FIXME: adapted from the same func in mailbox_runtime.c */
int mailbox_attest_queue_access(uint8_t queue_id, limit_t limit,
				timeout_t timeout)
{
	mailbox_state_reg_t state;
	unsigned long flags;
	u32 raw_state;
	u8 factor, tail_offset;

	if (queue_id == Q_STORAGE_DATA_OUT || queue_id == Q_STORAGE_DATA_IN) {
		factor = MAILBOX_QUEUE_MSG_SIZE_LARGE / 4;
		tail_offset = MAILBOX_QUEUE_MSG_SIZE_LARGE / 4 - 2;
	} else {
		factor = MAILBOX_QUEUE_MSG_SIZE / 4;
		tail_offset = MAILBOX_QUEUE_MSG_SIZE / 4 - 2;
	}

	spin_lock_irqsave(&mailbox_lock, flags);
	if (octopos_mailbox_attest_owner_fast_hw(mbox_ctrl_map[queue_id])) {
		raw_state = octopos_mailbox_get_status_reg(mbox_ctrl_map[queue_id]);
		printk("%u state=%lu\n", (unsigned int) queue_id, (unsigned int) raw_state);
		memcpy(&state, &raw_state, sizeof(state));
		// printk("%u %u\n", (unsigned int) state.limit, (unsigned int) state.timeout);
	} else {
		printk("%s: Error: no access to mailbox\n", __func__);
		return 0;
	}
	spin_unlock_irqrestore(&mailbox_lock, flags);

	if (state.limit && (state.limit != MAILBOX_NO_LIMIT_VAL))
		queue_limits[queue_id] = state.limit / factor;

	if (state.timeout && (state.timeout != MAILBOX_NO_TIMEOUT_VAL))
		queue_timeouts[queue_id] = state.timeout;

	if (state.limit / factor == limit || 
			(limit == MAILBOX_MAX_LIMIT_VAL && state.limit == MAILBOX_MAX_LIMIT_VAL)
		)
		return 1;
	else
		return 0;
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
	u8 factor = MAILBOX_QUEUE_MSG_SIZE / 4;

	if (queue_limits[queue_id] <= count * factor)
		queue_limits[queue_id] = 0;
	else
		queue_limits[queue_id] -= count * factor;
}

/* FIXME: move somewhere else */
void *ond_tcp_receive(void);

static struct work_struct net_wq;

static void net_receive_wq(struct work_struct *work)
{
	ond_tcp_receive();
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

//	INIT_WORK(&net_wq, net_receive_wq);

	spin_lock_init(&mailbox_lock);

	memset(queue_limits, 0x0, sizeof(queue_limits));
	memset(queue_timeouts, 0x0, sizeof(queue_timeouts));
	memset(queue_timeout_update_callbacks, 0x0, sizeof(queue_timeout_update_callbacks));

	timer_setup(&timer, callback_timer, 0);
	mod_timer(&timer, jiffies + msecs_to_jiffies(100));	

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

static void __exit om_cleanup(void)
{
	del_timer(&timer);

	misc_deregister(&om_miscdev);
}

/* for use by secure hardware driver */
EXPORT_SYMBOL(interrupts);
EXPORT_SYMBOL(cmd_buf);
EXPORT_SYMBOL(cmd_sem);
EXPORT_SYMBOL(write_syscall_response);

/* for use by other devices */
EXPORT_SYMBOL(om_inited);

module_init(om_init);
module_exit(om_cleanup);

MODULE_DESCRIPTION("OctopOS mailbox driver for UML");
MODULE_LICENSE("GPL");

#endif
