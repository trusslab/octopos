/* OctopOS loader for processors other than storage and OS */

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
#include <os/file_system.h>
#include <os/storage.h>
#include <arch/mailbox.h>

int fd_out, fd_in, fd_intr;
pthread_t mailbox_thread;

 /* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];
sem_t availables[NUM_QUEUES + 1];

int keyboard = 0, serial_out = 0, network = 0, runtime1 = 0, runtime2 = 0;

/* FIXME: adapted from the same func in mailbox_runtime.c */
static uint8_t mailbox_get_queue_access_count(uint8_t queue_id, uint8_t access)
{
	uint8_t opcode[3], count;

	opcode[0] = MAILBOX_OPCODE_ATTEST_QUEUE_ACCESS;
	opcode[1] = queue_id;
	opcode[2] = access;
	write(fd_out, opcode, 3);
	read(fd_in, &count, 1);

	return count;
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
		printf("%s [1]\n", __func__);
		read(fd_intr, &interrupt, 1);
		printf("%s [2]: interrupt = %d\n", __func__, interrupt);

		/* FIXME: check the TPM interrupt logic */
		//if (interrupt > 0 && interrupt <= NUM_QUEUES && interrupt != Q_TPM_DATA_IN) {
		if (interrupt == Q_STORAGE_DATA_OUT) {
			sem_post(&interrupts[Q_STORAGE_DATA_OUT]);
		} else if ((interrupt - NUM_QUEUES) == Q_STORAGE_DATA_OUT) {
			sem_post(&availables[Q_STORAGE_DATA_OUT]);
		} else if (interrupt == Q_TPM_DATA_IN) {
			sem_post(&interrupts[Q_TPM_DATA_IN]);
			/* Block interrupts until the program is loaded.
			 * Otherwise, we might receive some interrupts not
			 * intended for the loader.
			 */
			return NULL;
		} else if ((interrupt - NUM_QUEUES) == Q_TPM_DATA_IN) {
			sem_post(&availables[Q_TPM_DATA_IN]);

		/* When the OS resets a runtime (after it's one), it is possible
		 * for the loader (when trying to reload the runtime) to receive
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

	//sem_wait(&interrupts[Q_TPM_DATA_IN]);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_TPM_DATA_IN;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE_LARGE);
}

int init_mailbox(void)
{
	sem_init(&interrupts[Q_STORAGE_DATA_OUT], 0, 0);
	/* set the initial value of this one to 0 so that we can use it
	 * to wait for the TPM to read the message.
	 */
	sem_init(&interrupts[Q_TPM_DATA_IN], 0, 0);
	sem_init(&availables[Q_STORAGE_DATA_OUT], 0, 0);
	sem_init(&availables[Q_TPM_DATA_IN], 0, 0);

	/* FIXME */
	if (keyboard) {
		printf("%s [1]: keyboard\n", __func__);
		mkfifo(FIFO_KEYBOARD_OUT, 0666);
		mkfifo(FIFO_KEYBOARD_IN, 0666);
		mkfifo(FIFO_KEYBOARD_INTR, 0666);

		fd_out = open(FIFO_KEYBOARD_OUT, O_WRONLY);
		fd_in = open(FIFO_KEYBOARD_IN, O_RDONLY);
		fd_intr = open(FIFO_KEYBOARD_INTR, O_RDONLY);
	} else if (serial_out) {
		printf("%s [2]: serial_out\n", __func__);
		mkfifo(FIFO_SERIAL_OUT_OUT, 0666);
		mkfifo(FIFO_SERIAL_OUT_IN, 0666);
		mkfifo(FIFO_SERIAL_OUT_INTR, 0666);

		fd_out = open(FIFO_SERIAL_OUT_OUT, O_WRONLY);
		fd_in = open(FIFO_SERIAL_OUT_IN, O_RDONLY);
		fd_intr = open(FIFO_SERIAL_OUT_INTR, O_RDONLY);
	} else if (network) {
		printf("%s [3]: network\n", __func__);
		mkfifo(FIFO_NETWORK_OUT, 0666);
		mkfifo(FIFO_NETWORK_IN, 0666);
		mkfifo(FIFO_NETWORK_INTR, 0666);

		fd_out = open(FIFO_NETWORK_OUT, O_WRONLY);
		fd_in = open(FIFO_NETWORK_IN, O_RDONLY);
		fd_intr = open(FIFO_NETWORK_INTR, O_RDONLY);
	} else if (runtime1) {
		printf("%s [4]: runtime1\n", __func__);
		mkfifo(FIFO_RUNTIME1_OUT, 0666);
		mkfifo(FIFO_RUNTIME1_IN, 0666);
		mkfifo(FIFO_RUNTIME1_INTR, 0666);
		printf("%s [4.1]\n", __func__);

		fd_out = open(FIFO_RUNTIME1_OUT, O_WRONLY);
		printf("%s [4.2]\n", __func__);
		fd_in = open(FIFO_RUNTIME1_IN, O_RDONLY);
		printf("%s [4.3]\n", __func__);
		fd_intr = open(FIFO_RUNTIME1_INTR, O_RDONLY);
		printf("%s [4.4]\n", __func__);
	} else if (runtime2) {
		printf("%s [5]: runtime2\n", __func__);
		mkfifo(FIFO_RUNTIME2_OUT, 0666);
		mkfifo(FIFO_RUNTIME2_IN, 0666);
		mkfifo(FIFO_RUNTIME2_INTR, 0666);

		fd_out = open(FIFO_RUNTIME2_OUT, O_WRONLY);
		fd_in = open(FIFO_RUNTIME2_IN, O_RDONLY);
		fd_intr = open(FIFO_RUNTIME2_INTR, O_RDONLY);
	} else {
		printf("Error: %s: no proc specified\n", __func__);
		exit(-1);
	}
	printf("%s [6]\n", __func__);

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

	//remove(FIFO_KEYBOARD_OUT);
	//remove(FIFO_KEYBOARD_IN);
	//remove(FIFO_KEYBOARD_INTR);
}

void prepare_loader(char *filename, int argc, char *argv[])
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
	} else {
		printf("Error: %s: unknown binary\n", __func__);
		exit(-1);
	}
}

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 *
 * When booting, the loader waits for access to Q_STORAGE_DATA_OUT
 * (which is granted by the OS) and reads the image from that queue.
 */
int copy_file_from_boot_partition(char *filename, char *path)
{
	//uint32_t fd;
	FILE *copy_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int offset;
	printf("%s [1]\n", __func__);

	init_mailbox();

	//filep = fopen("./storage/octopos_partition_0_data", "r");
	//if (!filep) {
	//	printf("Error: %s: Couldn't open the boot partition file.\n", __func__);
	//	return -1;
	//}

	/* FIXME: size hard-coded */
	//total_blocks = 2000;

	/* FIXME: size hard-coded */
	//initialize_file_system(2000);
	//printf("%s [2.1]\n", __func__);

	//fd = file_system_open_file(filename, FILE_OPEN_MODE); 
	//if (fd == 0) {
	//	printf("Error: %s: Couldn't open file %s in octopos file system.\n",
	//	       __func__, filename);
	//	return -1;
	//}
	//printf("%s [2.2]\n", __func__);

	if (MAILBOX_QUEUE_MSG_SIZE_LARGE != STORAGE_BLOCK_SIZE) {
		printf("Error: %s: storage data queue msg size must be equal to storage block size\n", __func__);
		exit(-1);
	}
	
	copy_filep = fopen(path, "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the target file (%s).\n", __func__, path);
		return -1;
	}


	sem_wait(&availables[Q_STORAGE_DATA_OUT]);
	uint8_t count = mailbox_get_queue_access_count(Q_STORAGE_DATA_OUT, READ_ACCESS);

	offset = 0;
	printf("%s [3]\n", __func__);

	for (int i = 0; i < (int) count; i++) {
		printf("%s [4]: offset = %d\n", __func__, offset);
		read_from_storage_data_queue(buf);
		
		///* Block interrupts until the program is loaded.
		// * Otherwise, we might receive some interrupts Not
		// * intended for the loader.
		// */
		//if (i == ((int) (count - 1)))
		//	close_mailbox_thread();

		fseek(copy_filep, offset, SEEK_SET);
		fwrite(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, copy_filep);

		offset += STORAGE_BLOCK_SIZE;
	}
	printf("%s [6]\n", __func__);

	fclose(copy_filep);
	//file_system_close_file(fd);

	//close_file_system();

	//fclose(filep);

	return 0;
}

void send_measurement_to_tpm(char *path)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE_LARGE];

	printf("%s [1]\n", __func__);
	sem_wait(&availables[Q_TPM_DATA_IN]);
	printf("%s [2]\n", __func__);

	memcpy(buf, path, strlen(path) + 1);

	send_message_to_tpm(buf);
	printf("%s [3]\n", __func__);

	/* Wait for TPM to read the message */
	sem_wait(&interrupts[Q_TPM_DATA_IN]);
	printf("%s [4]\n", __func__);

	close_mailbox();
}
