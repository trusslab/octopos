/* OctopOS bootloader for processors other than storage and OS */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <octopos/storage.h>
#include <octopos/mailbox.h>
#include <octopos/tpm.h>
#include <os/file_system.h>
#include <os/storage.h>
#include <arch/mailbox.h>

int fd_out, fd_in, fd_intr;
pthread_t mailbox_thread;

 /* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];
sem_t availables[NUM_QUEUES + 1];

int keyboard = 0, serial_out = 0, network = 0,
    runtime1 = 0, runtime2 = 0, untrusted = 0;

static limit_t mailbox_get_queue_access_count(uint8_t queue_id)
{
	uint8_t opcode[2];
	mailbox_state_reg_t state;

	opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
	opcode[1] = queue_id;
	write(fd_out, opcode, 2);
	read(fd_in, &state, sizeof(mailbox_state_reg_t));

	return (limit_t) state.limit;
}

/* FIXME: copied from mailbox_os.c */
void read_from_storage_data_queue(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_DATA_OUT;
	sem_wait(&interrupts[Q_STORAGE_DATA_OUT]);
	write(fd_out, opcode, 2), 
	read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}


/* FIXME: adapted from the same function in mailbox_storage.c */
static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;
	int spurious = 0;

	while (1) {
		read(fd_intr, &interrupt, 1);

		/* FIXME: check the TPM interrupt logic */
		if (interrupt == 0) {
			/* ignore the timer interrupt */
		} else if (interrupt == Q_STORAGE_DATA_OUT) {
			sem_post(&interrupts[Q_STORAGE_DATA_OUT]);
		} else if ((interrupt - NUM_QUEUES) == Q_STORAGE_DATA_OUT) {
			sem_post(&availables[Q_STORAGE_DATA_OUT]);
		} else if (interrupt == Q_TPM_IN) {
			sem_post(&interrupts[Q_TPM_IN]);
			/* Block interrupts until the program is loaded.
			 * Otherwise, we might receive some interrupts not
			 * intended for the bootloader.
			 */
			return NULL;
		} else if ((interrupt - NUM_QUEUES) == Q_TPM_IN) {
			sem_post(&availables[Q_TPM_IN]);

		/* When the OS resets a runtime (after it's done), it is possible
		 * for the bootloader (when trying to reload the runtime) to receive
		 * an interrupt acknowledging that the OS read the last syscall
		 * from the mailbox (for termination information),
		 * or the interrupt for the response to that last syscall.
		 */
		} else if (runtime1 && (interrupt == Q_OS1 || interrupt == Q_RUNTIME1)
			   && spurious <= 1) {
			spurious++;
		} else if (runtime2 && (interrupt == Q_OS2 || interrupt == Q_RUNTIME2)
			   && spurious <= 1) {
			spurious++;
		} else {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
	}
}

static void send_message_to_tpm(uint8_t* buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_TPM_IN;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

int init_mailbox(void)
{
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
	/* set the initial value of this one to 0 so that we can use it
	 * to wait for the TPM to read the message.
	 */
	sem_init(&interrupts[Q_TPM_IN], 0, 0);
	sem_init(&availables[Q_STORAGE_DATA_OUT], 0, 0);
	sem_init(&availables[Q_TPM_IN], 0, 0);

	/* FIXME */
	if (keyboard) {
		mkfifo(FIFO_KEYBOARD_OUT, 0666);
		mkfifo(FIFO_KEYBOARD_IN, 0666);
		mkfifo(FIFO_KEYBOARD_INTR, 0666);

		fd_out = open(FIFO_KEYBOARD_OUT, O_WRONLY);
		fd_in = open(FIFO_KEYBOARD_IN, O_RDONLY);
		fd_intr = open(FIFO_KEYBOARD_INTR, O_RDONLY);
	} else if (serial_out) {
		mkfifo(FIFO_SERIAL_OUT_OUT, 0666);
		mkfifo(FIFO_SERIAL_OUT_IN, 0666);
		mkfifo(FIFO_SERIAL_OUT_INTR, 0666);

		fd_out = open(FIFO_SERIAL_OUT_OUT, O_WRONLY);
		fd_in = open(FIFO_SERIAL_OUT_IN, O_RDONLY);
		fd_intr = open(FIFO_SERIAL_OUT_INTR, O_RDONLY);
	} else if (network) {
		mkfifo(FIFO_NETWORK_OUT, 0666);
		mkfifo(FIFO_NETWORK_IN, 0666);
		mkfifo(FIFO_NETWORK_INTR, 0666);

		fd_out = open(FIFO_NETWORK_OUT, O_WRONLY);
		fd_in = open(FIFO_NETWORK_IN, O_RDONLY);
		fd_intr = open(FIFO_NETWORK_INTR, O_RDONLY);
	} else if (runtime1) {
		mkfifo(FIFO_RUNTIME1_OUT, 0666);
		mkfifo(FIFO_RUNTIME1_IN, 0666);
		mkfifo(FIFO_RUNTIME1_INTR, 0666);

		fd_out = open(FIFO_RUNTIME1_OUT, O_WRONLY);
		fd_in = open(FIFO_RUNTIME1_IN, O_RDONLY);
		fd_intr = open(FIFO_RUNTIME1_INTR, O_RDONLY);
	} else if (runtime2) {
		mkfifo(FIFO_RUNTIME2_OUT, 0666);
		mkfifo(FIFO_RUNTIME2_IN, 0666);
		mkfifo(FIFO_RUNTIME2_INTR, 0666);

		fd_out = open(FIFO_RUNTIME2_OUT, O_WRONLY);
		fd_in = open(FIFO_RUNTIME2_IN, O_RDONLY);
		fd_intr = open(FIFO_RUNTIME2_INTR, O_RDONLY);
	} else if (untrusted) {
		mkfifo(FIFO_UNTRUSTED_OUT, 0666);
		mkfifo(FIFO_UNTRUSTED_IN, 0666);
		mkfifo(FIFO_UNTRUSTED_INTR, 0666);

		fd_out = open(FIFO_UNTRUSTED_OUT, O_WRONLY);
		fd_in = open(FIFO_UNTRUSTED_IN, O_RDONLY);
		fd_intr = open(FIFO_UNTRUSTED_INTR, O_RDONLY);
	} else {
		printf("Error: %s: no proc specified\n", __func__);
		exit(-1);
	}

	int ret = pthread_create(&mailbox_thread, NULL, handle_mailbox_interrupts, NULL);
	if (ret) {
		printf("Error: couldn't launch the mailbox thread\n");
		return -1;
	}

	return 0;
}

void close_mailbox(void)
{	
	pthread_cancel(mailbox_thread);
	pthread_join(mailbox_thread, NULL);
	
	close(fd_out);
	close(fd_in);
	close(fd_intr);
}

void prepare_bootloader(char *filename, int argc, char *argv[])
{
	/* FIXME */
	if (!strcmp(filename, "keyboard")) {
		keyboard = 1;
	} else if (!strcmp(filename, "serial_out")) {
		serial_out = 1;
	} else if (!strcmp(filename, "network")) {
		network = 1;
	} else if (!strcmp(filename, "runtime")) {
		if (argc != 1) {
			printf("Error: %s: invalid number of args for runtime\n", __func__);
			exit(-1);
		}
		if (!strcmp(argv[0], "1")) {
			runtime1 = 1;
		} else if (!strcmp(argv[0], "2")) {
			runtime2 = 1;
		} else {
			printf("Error: %s: invalid runtime ID (%s)\n", __func__, argv[0]);
			exit(-1);
		}
	} else if (!strcmp(filename, "linux")) {
		untrusted = 1;
	} else {
		printf("Error: %s: unknown binary\n", __func__);
		exit(-1);
	}
}

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 *
 * When booting, the bootloader waits for access to Q_STORAGE_DATA_OUT
 * (which is granted by the OS) and reads the image from that queue.
 */
int copy_file_from_boot_partition(char *filename, char *path)
{
	FILE *copy_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int offset, need_repeat = 0;

	init_mailbox();

	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error: %s: storage data queue msg size must be equal to storage block size\n", __func__);
		exit(-1);
	}
	
	copy_filep = fopen(path, "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the target file (%s).\n", __func__, path);
		return -1;
	}

	int total = 0;
	offset = 0;
repeat:
	sem_wait(&availables[Q_STORAGE_DATA_OUT]);
	limit_t count = mailbox_get_queue_access_count(Q_STORAGE_DATA_OUT);

	/*
	 * When the file is very large, which is, for example, the case
	 * for the untrusted domain kernel, the queue will need to be
	 * delegated more than once.
	 */ 
	if (count == MAILBOX_MAX_LIMIT_VAL)
		need_repeat = 1;
	else
		need_repeat = 0;

	total += count;

	for (int i = 0; i < (int) count; i++) {
		read_from_storage_data_queue(buf);
		
		fseek(copy_filep, offset, SEEK_SET);
		fwrite(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, copy_filep);

		offset += STORAGE_BLOCK_SIZE;
	}

	if (need_repeat)
		goto repeat;

	fclose(copy_filep);

	return 0;
}

void send_measurement_to_tpm(char *path)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

	if (untrusted)
		return;

	sem_wait(&availables[Q_TPM_IN]);

	buf[0] = TPM_OP_EXTEND;
	memcpy(buf + 1, path, strlen(path) + 1);

	send_message_to_tpm(buf);

	/* Wait for TPM to read the message */
	sem_wait(&interrupts[Q_TPM_IN]);

	close_mailbox();
}
