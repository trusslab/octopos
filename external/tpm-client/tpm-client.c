#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <time.h>

#include "tpm.h"
#include "hash.h"

#define MAILBOX_QUEUE_MSG_SIZE	32
#define BUFFER_LENGTH		(MAILBOX_QUEUE_MSG_SIZE + 1)

#define OP_MEASURE		0x01
#define OP_READ			0x02

#define RET_SUCCESS		0xFF
#define RET_FAILURE		1

#define DEBUG			1


int set_serial_port_attribute(int fd, int speed)
{
	struct termios tty;
	if (tcgetattr(fd, &tty) != 0) {
		perror("error from tcgetattr");
		return -1;
	}

	cfsetospeed(&tty, speed);
	cfsetispeed(&tty, speed);

	tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;
	tty.c_cflag |= (CLOCAL | CREAD);
	tty.c_cflag &= ~(PARENB | PARODD);
	tty.c_cflag |= 0;
	tty.c_cflag &= ~CSTOPB;
	tty.c_cflag &= ~CRTSCTS;

	tty.c_iflag &= ~IGNBRK;
	tty.c_iflag |= ICANON;
	tty.c_iflag &= ~OPOST;
	tty.c_iflag &= ~(IXON | IXOFF | IXANY);

	tty.c_lflag = 0;

	tty.c_oflag = 0;

	tty.c_cc[VMIN] = 1;
	tty.c_cc[VTIME] = 0;

	if (tcsetattr(fd, TCSANOW, &tty) != 0) {
		perror("error from tcsetattr");
		return -1;
	}

	return 0;
}

int main(int argc, char const *argv[])
{
	int fd = -1;
	int rc = 0;
	uint8_t request[BUFFER_LENGTH];
	uint8_t *response;
	size_t response_size = 0;
	int read_length = 0;
	uint8_t read_char = '0';
	int op;
	struct timespec start_t;
	struct timespec end_t;
	struct timespec diff_t;

	// Open the device with read/write access
	fd = open("/dev/ttyS0", O_RDWR | O_NOCTTY);
	if (fd < 0) {
		perror("Failed to open the device.");
		return errno;
	}
	set_serial_port_attribute(fd, B9600);
	tcflush(fd, TCIFLUSH);

	while (true) {
		// Read the request
		usleep(BUFFER_LENGTH * 100);

		// Read message from serial port
		do {
			rc = read(fd, &read_char, 1);
			memcpy(&request[read_length], &read_char, 1);
			read_length += rc;
		} while(read_length < BUFFER_LENGTH && rc == 1);
		if (read_length != BUFFER_LENGTH) {
			perror("Failed to read the message from the device.");
			goto again;
		}

#ifdef DEBUG
		for (size_t i = 0; i < BUFFER_LENGTH; i++)
			printf("%02x ", request[i]);
		fflush(stdout);
#endif

		uint8_t current_proc = request[0] - 0x80 + 1;
		rc = enforce_running_process(current_proc);
		if (rc < 0) {
			perror("Failed to enforce running process.");
			goto again;
		}

#ifdef DEBUG
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_t);
#endif
		// Get the op
		op = OP_READ;
		for (size_t i = 1; i < BUFFER_LENGTH; i++) {
			if (request[i] != 0x00) {
				op = OP_MEASURE;
				break;
			}
		}

		if (op == OP_MEASURE) {
			uint8_t hash_value[TPM_EXTEND_HASH_SIZE];
			response_size = 1;
			response = (uint8_t *) malloc(response_size);

			memcpy(hash_value, request + 1, TPM_EXTEND_HASH_SIZE);
			rc = tpm_measure_service(hash_value, 0);
			response[0] = (rc == TPM2_RC_SUCCESS) ? RET_SUCCESS : RET_FAILURE;
		} else if (op == OP_READ) {
			uint32_t pcr_index = PROC_TO_PCR(current_proc);
			uint8_t send[TPM_EXTEND_HASH_SIZE] = {0};
			response_size = TPM_EXTEND_HASH_SIZE;
			response = (uint8_t *) malloc(response_size);

			rc = tpm_processor_read_pcr(pcr_index, send);
			if (rc == TPM2_RC_SUCCESS)
				memcpy(response, send, TPM_EXTEND_HASH_SIZE);
			else
				memset(response, RET_FAILURE, response_size);
		}

#ifdef DEBUG
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_t);
		if ((end_t.tv_nsec - start_t.tv_nsec) < 0) {
			diff_t.tv_sec = end_t.tv_sec-start_t.tv_sec-1;
			diff_t.tv_nsec = 1000000000 + end_t.tv_nsec - start_t.tv_nsec;
		} else {
			diff_t.tv_sec = end_t.tv_sec-start_t.tv_sec;
			diff_t.tv_nsec = end_t.tv_nsec-start_t.tv_nsec;
		}
		printf("%ld.%lds", diff_t.tv_sec, diff_t.tv_nsec);
#endif

#ifdef DEBUG
		for (size_t i = 0; i < response_size; i++)
			printf("%02x ", response[i]);
#endif
		rc = write(fd, response, response_size);
		if (rc != response_size) {
			perror("Failed to write the message to the device.");
			goto again;
		}
		tcdrain(fd);
		tcflush(fd, TCIFLUSH);

again:
		read_length = 0;
		op = 0;
		memset(request, 0, BUFFER_LENGTH);
		response_size = 0;
		SAFE_FREE(response);
		cancel_running_process();
	}

	rc = close(fd);
	if (rc != 0) {
		perror("Failed to close the device...");
		return errno;
	}

	return 0;
}
