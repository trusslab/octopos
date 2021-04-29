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

#define OM_MODULE_NAME "octopos_tpm"
/* check include/linux/miscdevice.h to make sure this is not taken. */
#define OM_MINOR		244

#define MAILBOX_QUEUE_MSG_SIZE	64

#define SHORT_BUFFER		0
#define LARGE_BUFFER		1

/******** dummy implementations for now *********/
//#define	P_OS			1
//#define	P_KEYBOARD		2
//#define	P_SERIAL_OUT		3
//#define	P_STORAGE		4
//#define	P_NETWORK		5
//#define	P_BLUETOOTH		6
//#define	P_RUNTIME1		7
//#define	P_RUNTIME2		8
//#define P_UNTRUSTED		9

/* TPM ops */
#define OP_MEASURE		0x01
#define OP_READ			0x02
#define OP_ATTEST		0x03
#define OP_RESET		0x04

static int does_proc_have_message(int proc_id)
{
	return 1;
}

static void recv_msg_from_proc(uint8_t *buf, uint8_t proc_id)
{
	/* Determine the incoming queue of the proc and read */

	/* Dummy request */
	char hash[] = "\x62\x51\x55\xb2\xd5\xfa\xd9\xd8\x9f\xaa\x09\xdd\xec\x59\xc4\x38\xaa\xca\x8f\x07\xf7\x3a\x99\x3d\xa7\xcb\x9a\xb4\x7e\x95\xc9\xe3";
	buf[0] = OP_MEASURE;
	memcpy(&buf[1], hash, 32);
}

static void send_msg_to_proc(uint8_t *buf, uint8_t proc_id)
{
	/* Determine the outgoing queue of the proc and write */
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
		if (next_proc == 10)
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
	uint8_t req_buf[MAILBOX_QUEUE_MSG_SIZE + 1];
	int ret;

	if (*offp != 0)
		return 0;
 
	if (size != (MAILBOX_QUEUE_MSG_SIZE + 1))
		return 0;

	down(&mutex);

	get_next_tpm_request(&req_buf[1], &current_proc);
	req_buf[0] = current_proc;

	ret = copy_to_user(buf, req_buf, size);
	*offp += (size - ret);

	return (size - ret);
}

static ssize_t otpm_dev_write(struct file *filp, const char __user *buf,
			      size_t size, loff_t *offp)
{
	uint8_t resp_buf[MAILBOX_QUEUE_MSG_SIZE + 1];
	int ret;

	if (*offp != 0)
		return 0;
 
	if (size != (MAILBOX_QUEUE_MSG_SIZE + 1))
		return 0;

	memset(resp_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE + 1);

	ret = copy_from_user(resp_buf, buf, size);
	
	*offp += (size - ret);
	
	send_tpm_response(resp_buf + 1, current_proc);

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

