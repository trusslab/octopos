/* octopos storage code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/error.h>
#include <arch/mailbox.h>

int fd_out, fd_in, fd_intr;
pthread_t net_threads[2];

/* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];


extern void network_stack_init(void);

/* FIXME: identical copy form storage.c */
static void send_response(uint8_t *buf, uint8_t queue_id)
{
        uint8_t opcode[2];

        sem_wait(&interrupts[queue_id]);

        opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
        opcode[1] = queue_id;
        write(fd_out, opcode, 2);
        write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

/* FIXME: identical copy form storage.c */
static void send_received_packet(uint8_t *buf, uint8_t queue_id)
{
        uint8_t opcode[2];

        sem_wait(&interrupts[queue_id]);

        opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
        opcode[1] = queue_id;
        write(fd_out, opcode, 2);
        write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}




void net_stack_exit(void)
{
        int ret = pthread_cancel(net_threads[0]);
        if (ret)
                printf("Error: couldn't kill net_threads[0]");

        ret = pthread_cancel(net_threads[1]);
        if (ret)
                printf("Error: couldn't kill net_threads[1]");

        netdev_exit();
}




int net_stack_run(void)
{
        /* create timer thread */
        int ret = pthread_create(&net_threads[0], NULL, (pfunc_t) net_timer, NULL);
        if (ret) {
                printf("Error: couldn't launch net_thread[0]\n");
                return -1;
        }
        /* create netdev thread */
        ret = pthread_create(&net_threads[1], NULL, (pfunc_t) netdev_interrupt, NULL);
        if (ret) {
                printf("Error: couldn't launch net_thread[1]\n");
                return -1;
        }

        return 0;
}


static int initialize_network(void)
{
        network_stack_init();
        return net_stack_run();
}


static void *handle_mailbox_interrupts(void *data)
{
        uint8_t interrupt;

        while (1) {
                read(fd_intr, &interrupt, 1);
                if (interrupt < 1 || interrupt > NUM_QUEUES) {
                        printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
                        exit(-1);
                }
                sem_post(&interrupts[interrupt]);
                if (interrupt == Q_NETWORK_DATA_IN)
                        sem_post(&interrupts[Q_NETWORK_CMD_IN]);
        }
}


int init_network(void)
{
        sem_init(&interrupts[Q_NETWORK_DATA_IN], 0, 0);
        sem_init(&interrupts[Q_NETWORK_DATA_OUT], 0, MAILBOX_QUEUE_SIZE_LARGE);
        sem_init(&interrupts[Q_NETWORK_CMD_IN], 0, 0);
        sem_init(&interrupts[Q_NETWORK_CMD_OUT], 0, MAILBOX_QUEUE_SIZE);

        int ret = initialize_network();
        if (ret) {
                printf("Error: couldn't initialize the network\n");
                return -1;
        }

        mkfifo(FIFO_NETWORK_OUT, 0666);
        mkfifo(FIFO_NETWORK_IN, 0666);
        mkfifo(FIFO_NETWORK_INTR, 0666);

        fd_out = open(FIFO_NETWORK_OUT, O_WRONLY);
        fd_in = open(FIFO_NETWORK_IN, O_RDONLY);
        fd_intr = open(FIFO_NETWORK_INTR, O_RDONLY);

        ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
        if (ret) {
                printf("Error: couldn't launch the mailbox thread\n");
                return -1;
        }
	return 0;

}

void network_event_loop(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t opcode[2];
	int is_data_queue = 0;

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	
        while(1) {
                sem_wait(&interrupts[Q_NETWORK_CMD_IN]);
                sem_getvalue(&interrupts[Q_NETWORK_DATA_IN], &is_data_queue);
                if (!is_data_queue) {
                        memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
                        opcode[1] = Q_NETWORK_CMD_IN;
                        write(fd_out, opcode, 2),
                        read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
                        process_cmd(buf);
                        send_response(buf, Q_NETWORK_CMD_OUT);
                } else {
                        uint8_t *dbuf = malloc(MAILBOX_QUEUE_MSG_SIZE_LARGE);
                        if (!dbuf) {
                                printf("%s: Error: could not allocate memory\n", __func__);
                                continue;
                        }
                        sem_wait(&interrupts[Q_NETWORK_DATA_IN]);
                        opcode[1] = Q_NETWORK_DATA_IN;
                        write(fd_out, opcode, 2);
                        read(fd_in, dbuf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
                        send_packet(dbuf);
                }
        }
	
}


void close_network(void)
{
        pthread_cancel(mailbox_thread);
        pthread_join(mailbox_thread, NULL);

        close(fd_out);
        close(fd_in);
        close(fd_intr);

        remove(FIFO_NETWORK_OUT);
        remove(FIFO_NETWORK_IN);
        remove(FIFO_NETWORK_INTR);

        net_stack_exit();

}
