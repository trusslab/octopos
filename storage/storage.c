/* octopos storage code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/error.h>

int fd_out, fd_in, fd_intr;

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
static void initialize_storage_space(void)
{
        int size = 1024;
	FILE *filep = NULL;

        filep = fopen("octopos_disk", "w");
	if (!filep) {
		printf("Error: initialize_storage_space: couldn't open octopos_disk\n");
		_exit(-1);
	}
        fseek(filep, size , SEEK_SET);
        fputc('\0', filep);
        fclose(filep);
}

static void send_response(uint8_t *buf)
{
	uint8_t opcode[2];

	opcode[0] = MAILBOX_OPCODE_WRITE_QUEUE;
	opcode[1] = Q_STORAGE_OUT;
	write(fd_out, opcode, 2);
	write(fd_out, buf, MAILBOX_QUEUE_MSG_SIZE);
}

static void process_request(uint8_t *buf)
{
	uint8_t ret_buf[MAILBOX_QUEUE_MSG_SIZE];
	size_t size;
	FILE *filep = NULL;

	/* write */
	if (buf[0] == 0) {
		filep = fopen("octopos_disk", "w");
		if (!filep) {
			printf("Error: initialize_storage_space: couldn't open octopos_disk\n");
			ret_buf[0] = ERR_FAULT; /* ret */
			send_response(ret_buf);
		}
		fseek(filep, 0, SEEK_SET);
		size = fwrite(&buf[1], sizeof(uint8_t), MAILBOX_QUEUE_MSG_SIZE - 1, filep);
		if (size == (MAILBOX_QUEUE_MSG_SIZE - 1)) {
			ret_buf[0] = 0; /* ret */
		} else {
			printf("Error: write failed, size = %d\n", (int) size);
			ret_buf[0] = ERR_FAULT; /* ret */
		}
		fclose(filep);
		send_response(ret_buf);
	} else { /* read */
		filep = fopen("octopos_disk", "r");
		if (!filep) {
			printf("Error: initialize_storage_space: couldn't open octopos_disk\n");
			ret_buf[0] = ERR_FAULT; /* ret */
			send_response(ret_buf);
		}
		fseek(filep, 0, SEEK_SET);
		size = fread(&ret_buf[1], sizeof(uint8_t), MAILBOX_QUEUE_MSG_SIZE - 1, filep);
		if (size == (MAILBOX_QUEUE_MSG_SIZE - 1)) {
			ret_buf[0] = 0; /* ret */
		} else {
			printf("Error: read failed, size = %d\n", (int) size);
			ret_buf[0] = ERR_FAULT; /* ret */
		}
		fclose(filep);
		send_response(ret_buf);
	}
}

int main(int argc, char **argv)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t interrupt, opcode[2];

	initialize_storage_space();

	mkfifo(FIFO_STORAGE_OUT, 0666);
	mkfifo(FIFO_STORAGE_IN, 0666);
	mkfifo(FIFO_STORAGE_INTR, 0666);

	fd_out = open(FIFO_STORAGE_OUT, O_WRONLY);
	fd_in = open(FIFO_STORAGE_IN, O_RDONLY);
	fd_intr = open(FIFO_STORAGE_INTR, O_RDONLY);
		
	opcode[0] = MAILBOX_OPCODE_READ_QUEUE;
	opcode[1] = Q_STORAGE_IN;
	
	while(1) {
		memset(buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
		read(fd_intr, &interrupt, 1);
		write(fd_out, opcode, 2), 
		read(fd_in, buf, MAILBOX_QUEUE_MSG_SIZE);
		process_request(buf);
	}
	
	close(fd_out);
	close(fd_in);
	close(fd_intr);

	remove(FIFO_SERIAL_OUT_OUT);
	remove(FIFO_SERIAL_OUT_IN);
	remove(FIFO_SERIAL_OUT_INTR);
}
