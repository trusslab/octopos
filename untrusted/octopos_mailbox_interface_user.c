/* OctopOS mailbox interface for UML
 * Copyright (C) 2020 Ardalan Amiri Sani <arrdalan@gmail.com>
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#define UNTRUSTED_DOMAIN
#include <octopos/mailbox.h>

int fd_out, fd_in, fd_intr;
//pthread_t mailbox_thread;
/* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];

void recv_msg_from_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];
	uint8_t interrupt;

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = queue_id;
	/* wait for message */
	printk("%s [1]\n", __func__);
	//sem_wait(&interrupts[queue_id]);
	/* FIXME */
	read(fd_intr, &interrupt, 1);
	printk("%s [2]: interrupt = %d\n", __func__, interrupt);
	write(fd_out, opcode, 2), 
	read(fd_in, buf, queue_msg_size);
}

void send_msg_on_queue(uint8_t *buf, uint8_t queue_id, int queue_msg_size)
{
	uint8_t opcode[2];
	uint8_t interrupt;

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = queue_id;
	printk("%s [1]\n", __func__);
	//sem_wait(&interrupts[queue_id]);
	printk("%s [2]\n", __func__);
	write(fd_out, opcode, 2);
	write(fd_out, buf, queue_msg_size);
	/* FIXME */
	read(fd_intr, &interrupt, 1);
}

//void *handle_mailbox_interrupts(void *data)
int handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		printk("%s [1]\n", __func__);
		read(fd_intr, &interrupt, 1);
		printk("%s [2]\n", __func__);
		if (!(interrupt == Q_UNTRUSTED && interrupt == Q_OSU)) {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
		printk("%s [3]\n", __func__);
		sem_post(&interrupts[interrupt]);
		printk("%s [4]\n", __func__);
	}

	return 0;
}

int init_octopos_mailbox_interface(void)
{
	int ret;

	/* initiaze mailbox access */
	mkfifo(FIFO_UNTRUSTED_OUT, 0666);
	mkfifo(FIFO_UNTRUSTED_IN, 0666);
	mkfifo(FIFO_UNTRUSTED_INTR, 0666);

	fd_out = open(FIFO_UNTRUSTED_OUT, O_WRONLY);
	fd_in = open(FIFO_UNTRUSTED_IN, O_RDONLY);
	fd_intr = open(FIFO_UNTRUSTED_INTR, O_RDONLY);

	//sem_init(&interrupts[Q_OSU], 0, MAILBOX_QUEUE_SIZE);
	//sem_init(&interrupts[Q_UNTRUSTED], 0, 0);
	
	//ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	//if (ret) {
	//	printf("Error: couldn't launch the mailbox thread\n");
	//	return -1;
	//}
	
	return 0;
}

void close_octopos_mailbox_interface(void)
{
	//pthread_join(mailbox_thread, NULL);

	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_UNTRUSTED_OUT); 
	remove(FIFO_UNTRUSTED_IN);
	remove(FIFO_UNTRUSTED_INTR);
}
