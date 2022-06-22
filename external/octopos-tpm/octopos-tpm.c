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

#define OM_MODULE_NAME "octopos_tpm"
/* check include/linux/miscdevice.h to make sure this is not taken. */
#define OM_MINOR		MISC_DYNAMIC_MINOR

#define MAILBOX_QUEUE_MSG_SIZE	32
#define BUFFER_SIZE		(MAILBOX_QUEUE_MSG_SIZE + 1)

struct file *serial_file = NULL;
struct semaphore mutex;

int read_from_serial(uint8_t *buf, size_t size)
{
	int ret;
	ret = kernel_read(serial_file, buf, size, &serial_file->f_pos);
	if (ret < 0) {
		printk("%s: kernel_read failed with %d\n", __func__, ret);
		return -1;
	}
	return ret;
}

int write_to_serial(uint8_t *buf, int size)
{
	int ret;
	ret = kernel_write(serial_file, buf, size, &serial_file->f_pos);
	if (ret < 0) {
		printk("%s: kernel_wrute failed with %d\n", __func__, ret);
		return -1;
	}
	return ret;
}

static int otpm_dev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t otpm_dev_read(struct file *filp, char __user *buf, size_t size,
			     loff_t *offp)
{
	int ret;
	loff_t off = 0;
	uint8_t req_buf[BUFFER_SIZE];
 
	if (size != BUFFER_SIZE)
		return 0;

	down(&mutex);

	ret = read_from_serial(req_buf, BUFFER_SIZE);
	if (ret != BUFFER_SIZE) {
		printk("Failed to read characters from serial port.\n");
		return -EFAULT;
	}

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
	int ret;
	loff_t off = 0;
	uint8_t resp_buf[1];
 
	if (size != 1)
		return 0;

	memset(resp_buf, 0x0, 1);

	ret = copy_from_user(resp_buf, buf, size);
	if (ret != 0) {
        	printk("Failed to read characters from user.\n");
        	return -EFAULT;
    	}

	write_to_serial(resp_buf, 1);

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

	serial_file = filp_open("/dev/ttyS0", O_RDWR, 0);
	if (IS_ERR(serial_file) || !serial_file) {
		printk(KERN_ERR OM_MODULE_NAME ": open serial file failed\n");
		return -EINVAL;
	}

	return 0;
}

static void __exit otpm_cleanup(void)
{
	filp_close(serial_file, NULL);
	misc_deregister(&otpm_miscdev);
}

module_init(otpm_init);
module_exit(otpm_cleanup);

MODULE_DESCRIPTION("OctopOS driver for creating a TPM node");
MODULE_LICENSE("GPL");


