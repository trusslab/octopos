/* octopos storage code */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>

int fd_out, fd_in, fd_intr;
FILE *filep = NULL;

/* https://stackoverflow.com/questions/7775027/how-to-create-file-of-x-size */
static void initialize_storage_space(void)
{
        int size = 1024;

        filep = fopen("octopos_disk", "rw");
	if (!filep) {
		printf("Error: initialize_storage_space: couldn't open octopos_disk\n");
		_exit(-1);
	}
        fseek(filep, size , SEEK_SET);
        fputc('\0', filep);
}

static void close_storage_space(void)
{
        fclose(filep);
	filep = NULL;
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

	/* write */
	if (buf[0] == 0) {
		fseek(filep, 0, SEEK_SET);
		fwrite(&buf[1], sizeof(uint8_t), MAILBOX_QUEUE_MSG_SIZE - 1, filep);
		ret_buf[0] = 0; /* ret */
		send_response(ret_buf);
	} else { /* read */
		fseek(filep, 0, SEEK_SET);
		fread(&ret_buf[1], sizeof(uint8_t), MAILBOX_QUEUE_MSG_SIZE - 1, filep);
		ret_buf[0] = 0; /* ret */
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

	close_storage_space();
}
