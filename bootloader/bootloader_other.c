/* OctopOS bootloader for processors other than storage and OS */
#if !defined(ARCH_SEC_HW_BOOT) || defined(ARCH_SEC_HW_BOOT_OTHER)

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifndef ARCH_SEC_HW_BOOT
#include <dlfcn.h>
#include <semaphore.h>
#include <arch/mailbox.h>
#else
#include <arch/sec_hw.h>
#include <arch/portab.h>
#include <arch/srec_errors.h>
#include <arch/srec.h>
#include <arch/octopos_mbox.h>
#endif
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <octopos/storage.h>
#include <octopos/mailbox.h>
#include <octopos/tpm.h>
#include <os/file_system.h>
#include <os/storage.h>
#include <tpm/hash.h>


#ifndef ARCH_SEC_HW_BOOT
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
	int num_tpm_in = 0;

	while (1) {
		read(fd_intr, &interrupt, 1);

		/* FIXME: check the TPM interrupt logic */
		if (interrupt == Q_STORAGE_DATA_OUT) {
			sem_post(&interrupts[Q_STORAGE_DATA_OUT]);
		} else if ((interrupt - NUM_QUEUES) == Q_STORAGE_DATA_OUT) {
			sem_post(&availables[Q_STORAGE_DATA_OUT]);
		} else if (interrupt == Q_TPM_IN) {
			sem_post(&interrupts[Q_TPM_IN]);
			/* Block interrupts until the program is loaded.
			 * Otherwise, we might receive some interrupts not
			 * intended for the bootloader.
			 */
			num_tpm_in++;
			if (num_tpm_in == TPM_EXTEND_HASH_NUM_MAILBOX_MSGS) 
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
#else

static srec_info_t srinfo;
static uint8 sr_buf[SREC_MAX_BYTES];
static uint8 sr_data_buf[SREC_DATA_MAX_BYTES];
extern UINTPTR Mbox_ctrl_regs[NUM_QUEUES + 1];
extern OCTOPOS_XMbox* Mbox_regs[NUM_QUEUES + 1];

int _sem_retrieve_mailbox_message_blocking_buf(XMbox *InstancePtr, uint8_t* buf);
int get_srec_line(uint8 *line, uint8 *buf);

/* FIXME: import headers */
int init_runtime(int runtime_id);

#endif

void prepare_bootloader(char *filename, int argc, char *argv[])
{
	/* no-op */
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
#ifndef ARCH_SEC_HW_BOOT
	FILE *copy_filep;
#else /* ARCH_SEC_HW_BOOT */

	u8 unpack_buf[1024] = {0};
	u16 unpack_buf_head = 0;
	int line_count;
	void (*laddr)();

	srinfo.sr_data = sr_data_buf;

#ifdef ARCH_SEC_HW_BOOT_STORAGE
	/* no-op */
#elif defined(ARCH_SEC_HW_BOOT_KEYBOARD)
	/* no-op */
#elif defined(ARCH_SEC_HW_BOOT_SERIAL_OUT)
	/* no-op */
#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_1)
	init_runtime(1);
#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_2)
	/* no-op */
#elif defined(ARCH_SEC_HW_BOOT_OS)
	/* no-op */
#elif defined(ARCH_SEC_HW_BOOT_NETWORK)
	/* no-op */
#elif defined(ARCH_SEC_HW_BOOT_LINUX)
	/* no-op */
#endif

	// FIXME: a better way to wait for OS to load?
	sleep(10);

#endif /* ARCH_SEC_HW_BOOT */

	uint8_t buf[STORAGE_BLOCK_SIZE];
	int offset, need_repeat = 0;

/* FIXME: some code is disabled to reduce bootloader binary size */
#ifndef ARCH_SEC_HW_BOOT
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
#endif /* ARCH_SEC_HW_BOOT */

	int total = 0;
	offset = 0;
repeat:
#ifndef ARCH_SEC_HW_BOOT
	sem_wait(&availables[Q_STORAGE_DATA_OUT]);
	limit_t count = mailbox_get_queue_access_count(Q_STORAGE_DATA_OUT);
#else
    /* unpack buffer is full, but still, haven't finish a line */
    if (unpack_buf_head > 1024 - STORAGE_BLOCK_SIZE)
        SEC_HW_DEBUG_HANG();
	limit_t count = octopos_mailbox_get_quota_limit(Mbox_ctrl_regs[Q_STORAGE_DATA_OUT]);
#endif /* ARCH_SEC_HW_BOOT */

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
#ifndef ARCH_SEC_HW_BOOT
		read_from_storage_data_queue(buf);
#else
		_sem_retrieve_mailbox_message_blocking_buf(Mbox_regs[Q_STORAGE_DATA_OUT], buf);
#endif
		
#ifndef ARCH_SEC_HW_BOOT
		fseek(copy_filep, offset, SEEK_SET);
		fwrite(buf, sizeof(uint8_t), STORAGE_BLOCK_SIZE, copy_filep);
#else
        /* copy into unpack buffer */
        memcpy(&unpack_buf[unpack_buf_head], &buf[0], STORAGE_BLOCK_SIZE);
        unpack_buf_head += STORAGE_BLOCK_SIZE;

        /* load lines until there is no complete line in unpack buffer */
        while ((line_count = get_srec_line(&unpack_buf[0], sr_buf)) > 0) {
            if (decode_srec_line(sr_buf, &srinfo) != 0)
                SEC_HW_DEBUG_HANG();

            switch (srinfo.type) {
                case SREC_TYPE_0:
                    break;
                case SREC_TYPE_1:
                case SREC_TYPE_2:
                case SREC_TYPE_3:
                    memcpy ((void*)srinfo.addr, (void*)srinfo.sr_data, srinfo.dlen);
                    break;
                case SREC_TYPE_5:
                    break;
                case SREC_TYPE_7:
                case SREC_TYPE_8:
                case SREC_TYPE_9:
                    laddr = (void (*)())srinfo.addr;

                    /* jump to start vector of loaded program */
                    (*laddr)();

                    /* the old program is dead at this point */
					SEC_HW_DEBUG_HANG();
                    break;
            }

            /* after loading the line, remove the contents being loaded */
            memcpy(&unpack_buf[0],
                    &unpack_buf[line_count],
                    unpack_buf_head - line_count);

//            sleep(5);
            unpack_buf_head -= line_count;
            memset(&unpack_buf[unpack_buf_head], 0, line_count);
        }
#endif /* ARCH_SEC_HW_BOOT */

		offset += STORAGE_BLOCK_SIZE;
	}

	if (need_repeat)
		goto repeat;

#ifndef ARCH_SEC_HW_BOOT
	fclose(copy_filep);
#endif /* ARCH_SEC_HW_BOOT */

	return 0;
}

void send_measurement_to_tpm(char *path)
{
#ifndef ARCH_SEC_HW_BOOT
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	char hash_buf[TPM_EXTEND_HASH_SIZE] = {0};
	int i;

	if (untrusted)
		return;

	sem_wait(&availables[Q_TPM_IN]);

	hash_file(path, hash_buf);
	buf[0] = TPM_OP_EXTEND;

	/* Note that we assume that two messages are needed to send the hash.
	 * See include/tpm/hash.h
	 */
	memcpy(buf + 1, hash_buf, MAILBOX_QUEUE_MSG_SIZE - 1);
	send_message_to_tpm(buf);
	memcpy(buf, hash_buf + MAILBOX_QUEUE_MSG_SIZE - 1,
	       TPM_EXTEND_HASH_SIZE - MAILBOX_QUEUE_MSG_SIZE + 1);
	send_message_to_tpm(buf);

	/* Wait for TPM to read the messages */
	for (i = 0; i < TPM_EXTEND_HASH_NUM_MAILBOX_MSGS; i++)
		sem_wait(&interrupts[Q_TPM_IN]);

	close_mailbox();
#endif
}
#endif
