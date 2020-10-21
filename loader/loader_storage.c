/* OctopOS loader for storage */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <os/file_system.h>
#include <arch/mailbox.h>

/* in file system wrapper */
extern FILE *filep;
/* FIXME: why should we need the total_blocks in loader? */
extern uint32_t total_blocks;

int fd_out, fd_intr;
pthread_t mailbox_thread;

 /* Not all will be used */
sem_t interrupts[NUM_QUEUES + 1];
sem_t availables[NUM_QUEUES + 1];

static void *handle_mailbox_interrupts(void *data)
{
	uint8_t interrupt;

	while (1) {
		printf("%s [1]\n", __func__);
		read(fd_intr, &interrupt, 1);
		printf("%s [2]: interrupt = %d\n", __func__, interrupt);

		/* FIXME: check the TPM interrupt logic */
		if (interrupt == Q_TPM_IN) {
			sem_post(&interrupts[Q_TPM_IN]);
			/* Block interrupts until the program is loaded.
			 * Otherwise, we might receive some interrupts not
			 * intended for the loader.
			 */
			return NULL;
		} else if ((interrupt - NUM_QUEUES) == Q_TPM_IN) {
			sem_post(&availables[Q_TPM_IN]);
		} else {
			printf("Error: interrupt from an invalid queue (%d)\n", interrupt);
			exit(-1);
		}
	}
}

/* FIXME: copied from loader_other.c */
static void send_message_to_tpm(uint8_t* buf)
{
	uint8_t opcode[2];

	//sem_wait(&interrupts[Q_TPM_IN]);

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_TPM_IN;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

int init_mailbox(void)
{
	/* set the initial value of this one to 0 so that we can use it
	 * to wait for the TPM to read the message.
	 */
	sem_init(&interrupts[Q_TPM_IN], 0, 0);
	sem_init(&availables[Q_TPM_IN], 0, 0);

	mkfifo(FIFO_STORAGE_OUT, 0666);
	//mkfifo(FIFO_STORAGE_IN, 0666);
	mkfifo(FIFO_STORAGE_INTR, 0666);

	fd_out = open(FIFO_STORAGE_OUT, O_WRONLY);
	//fd_in = open(FIFO_STORAGE_IN, O_RDONLY);
	fd_intr = open(FIFO_STORAGE_INTR, O_RDONLY);

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
	//close(fd_in);
	close(fd_intr);

	//remove(FIFO_STORAGE_OUT);
	//remove(FIFO_STORAGE_IN);
	//remove(FIFO_STORAGE_INTR);
}

void prepare_loader(char *filename, int argc, char *argv[])
{
	/* no op */
}

/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 *
 * When booting the storage, the loader directly reads the
 * storage image from storage medium itself.
 */
int copy_file_from_boot_partition(char *filename, char *path)
{
	uint32_t fd;
	FILE *copy_filep;
	uint8_t buf[STORAGE_BLOCK_SIZE];
	int _size;
	int offset;

	filep = fopen("./storage/octopos_partition_0_data", "r");
	if (!filep) {
		printf("Error: %s: Couldn't open the boot partition file.\n", __func__);
		return -1;
	}

	/* FIXME: size hard-coded */
	total_blocks = 2000;
	initialize_file_system(2000);

	fd = file_system_open_file(filename, FILE_OPEN_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file system.\n",
		       __func__, filename);
		return -1;
	}

	copy_filep = fopen(path, "w");
	if (!copy_filep) {
		printf("Error: %s: Couldn't open the target file (%s).\n", __func__, path);
		return -1;
	}

	offset = 0;

	while (1) {
		printf("%s [4]: offset = %d\n", __func__, offset);
		_size = file_system_read_from_file(fd, buf, STORAGE_BLOCK_SIZE, offset);
		printf("%s [5]: _size = %d\n", __func__, _size);
		if (_size == 0)
			break;

		if (_size < 0 || _size > STORAGE_BLOCK_SIZE) {
			printf("Error: %s: reading file.\n", __func__);
			break;
		}

		fseek(copy_filep, offset, SEEK_SET);
		fwrite(buf, sizeof(uint8_t), _size, copy_filep);

		offset += _size;
	}

	fclose(copy_filep);
	file_system_close_file(fd);

	close_file_system();
	fclose(filep);

	return 0;
}

void send_measurement_to_tpm(char *path)
{
	/* no op */
	//uint8_t interrupt;
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	printf("%s [1]\n", __func__);

	init_mailbox();

	/* Wait for the TPM mailbox */
	printf("%s [2]\n", __func__);
	
	//read(fd_intr, &interrupt, 1);
	//printf("%s [4]: interrupt = %d\n", __func__, interrupt);
	//if (interrupt != (NUM_QUEUES + Q_TPM_IN)) {
	//	printf("Error: %s: unexpected interrupt\n", __func__);
	//	exit(-1);
	//}
	sem_wait(&availables[Q_TPM_IN]);

	memcpy(buf, path, strlen(path) + 1);

	send_message_to_tpm(buf);
	printf("%s [2]\n", __func__);

	/* Wait for TPM to read the message */
	//read(fd_intr, &interrupt, 1);
	//printf("%s [4]: interrupt = %d\n", __func__, interrupt);
	//if (interrupt != Q_TPM_IN) {
	//	printf("Error: %s: unexpected interrupt\n", __func__);
	//	exit(-1);
	//}
	sem_wait(&interrupts[Q_TPM_IN]);

	close_mailbox();
}
