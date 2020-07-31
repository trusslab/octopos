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

int fd_out, fd_in, fd_intr;
struct semaphore interrupts[NUM_QUEUES + 1];

void recv_msg_from_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];
	uint8_t interrupt;

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	/* wait for message */
	printk("%s [1]\n", __func__);
	down(&interrupts[queue_id]);
	printk("%s [2]\n", __func__);
	os_write_file(fd_out, opcode, 2), 
	printk("%s [3]\n", __func__);
	os_read_file(fd_in, buf, queue_msg_size);
	printk("%s [4]\n", __func__);
}

void send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];
	uint8_t interrupt;

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	printk("%s [1]\n", __func__);
	down(&interrupts[queue_id]);
	printk("%s [2]\n", __func__);
	os_write_file(fd_out, opcode, 2);
	printk("%s [3]\n", __func__);
	os_write_file(fd_out, buf, queue_msg_size);
	printk("%s [4]\n", __func__);
}

static irqreturn_t om_interrupt(int irq, void *data)
{
	uint8_t interrupt;
	int n;
	//printk("%s [1]\n", __func__);

	while (true) {
		n = os_read_file(fd_intr, &interrupt, 1);
		if (n != 1)
			break;
		//printk("%s [2]: interrupt = %d, n = %d\n", __func__, interrupt, n);
		if (!(interrupt == Q_UNTRUSTED || interrupt == Q_OSU)) {
			printk("Error: interrupt from an invalid queue (%d)\n", interrupt);
			BUG();
		}
		//printk("%s [3]\n", __func__);
		up(&interrupts[interrupt]);
		//printk("%s [4]\n", __func__);
	}
	return IRQ_HANDLED;
}

static int __init om_init(void)
{
	int err, pid;

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

	//sigio_broken(fd_intr, 1);

	sema_init(&interrupts[Q_OSU], MAILBOX_QUEUE_SIZE);
	sema_init(&interrupts[Q_UNTRUSTED], 0);

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
