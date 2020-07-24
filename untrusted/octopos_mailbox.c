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

/* move to a header file */
void recv_msg_from_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size);
void send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size);
int handle_mailbox_interrupts(void *data);
int init_octopos_mailbox_interface(void);
void close_octopos_mailbox_interface(void);

/* FIXME: use the macros in syscall.h */
#define SYSCALL_SET_ZERO_ARGS(syscall_nr)					\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	*((uint16_t *) &buf[0]) = syscall_nr;					\

#define SYSCALL_SET_ZERO_ARGS_DATA(syscall_nr, data, size)			\
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];					\
	memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);				\
	uint8_t max_size = MAILBOX_QUEUE_MSG_SIZE - 3;				\
	if (max_size >= 256) {							\
		printk("Error (%s): max_size not supported\n", __func__);	\
		return -EINVAL;							\
	}									\
	if (size > max_size) {							\
		printk("Error (%s): size not supported\n", __func__);		\
		return -EINVAL;							\
	}									\
	*((uint16_t *) &buf[0]) = syscall_nr;					\
	buf[2] = size;								\
	memcpy(&buf[3], (uint8_t *) data, size);				\

#define SYSCALL_GET_ONE_RET				\
	uint32_t ret0;					\
	ret0 = *((uint32_t *) &buf[1]);			\

static int issue_syscall(uint8_t *buf)
{
	send_msg_on_queue(buf, Q_OSU, MAILBOX_QUEUE_MSG_SIZE);

	recv_msg_from_queue(buf, Q_UNTRUSTED, MAILBOX_QUEUE_MSG_SIZE);
	if (buf[0] != RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG) {
		printk("Error: %s: received invalid message.\n", __func__);
		return -EINVAL;
	}
	
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
	uint8_t data[MAILBOX_QUEUE_MSG_SIZE];
	int datasize, ret;

	if (*offp != 0)
		return 0;
  
	recv_msg_from_queue(data, Q_UNTRUSTED, MAILBOX_QUEUE_MSG_SIZE);
	if (data[0] != RUNTIME_QUEUE_EXEC_APP_TAG) {
		printk("Error: %s: received invalid message.\n", __func__);
		return -EINVAL;
	}

	datasize = MAILBOX_QUEUE_MSG_SIZE - 1;
	if (size < datasize)
		datasize = size;
	
	ret = copy_to_user(buf, &data[1], datasize);
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

/*
static irqreturn_t random_interrupt(int irq, void *data)
{
	wake_up(&host_read_wait);

	return IRQ_HANDLED;
}
*/

static int __init om_init (void)
{
	int err, pid;

	/* register char dev */
	err = misc_register(&om_miscdev);
	if (err) {
		printk(KERN_ERR OM_MODULE_NAME ": misc device register "
		       "failed\n");
		return err;
	}

	err = init_octopos_mailbox_interface();
	if (err) {
		printk(KERN_ERR OM_MODULE_NAME ": initializing mailbox interface "
		       "failed\n");
		return err;
	}

	//pid = run_helper_thread(handle_mailbox_interrupts, NULL,
	//			CLONE_FILES | CLONE_VM | CLONE_THREAD, NULL);
	//if (pid < 0) {
	//	printk(KERN_ERR OM_MODULE_NAME ": launching the mailbox thread "
	//	       "failed\n");
	//	return pid;
	//}
	
	return 0;
}

static void cleanup(void)
{
	//free_irq_by_fd(random_fd);
}

static void __exit om_cleanup(void)
{
	close_octopos_mailbox_interface();
	
	misc_deregister(&om_miscdev);
}

module_init(om_init);
module_exit(om_cleanup);
__uml_exitcall(cleanup);

MODULE_DESCRIPTION("OctopOS mailbox driver for UML");
MODULE_LICENSE("GPL");
