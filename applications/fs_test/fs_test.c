/* fs_test app */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include "xil_io.h"

#ifdef ARCH_SEC_HW_RUNTIME
#include "arch/sec_hw.h"
#include "arch/app_utilities.h"
#endif

#include <octopos/runtime.h>
#include <octopos/storage.h>

/* FIXME: how does the app know the size of the buf? */
#ifndef ARCH_SEC_HW

char output_buf[64];
int num_chars = 0;
#define secure_printf(fmt, args...) {memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args);	\
				     api->write_to_secure_serial_out(output_buf);}			\

#define insecure_printf(fmt, args...) {memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args);\
				     api->write_to_shell(output_buf, num_chars);}				 \

#endif

#if RUNTIME_ID == 1
extern long long global_counter;
#else
long long global_counter;
#endif

uint8_t block[STORAGE_BLOCK_SIZE * 31];

void mailbox_yield_to_previous_owner(uint8_t queue_id);

#ifndef ARCH_SEC_HW
extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
#else
void fs_test(struct runtime_api *api)
#endif
{
#ifdef MEASURE_STORAGE_THROUGH_OS
	uint32_t fd1 = api->open_file((char *) "test_file_1.txt", FILE_OPEN_CREATE_MODE);
	if (fd1 == 0) {
		insecure_printf("Couldn't open first file (fd1 = %d)\n", fd1);
		return;
	}

	long long total_read = 0;
	long long total_write = 0;

	/* BENCHMARK: write to flash */
	insecure_printf("Enter test.");
	for (int j = 0; j < 10; j++) {
	for (int i = 0; i < 80; i++) {
		memset(block, 0xFE, STORAGE_BLOCK_SIZE * 25);
		block[99] = i;
		global_counter = 0;
		api->write_file_blocks(fd1, block, i, 25);
		total_write += global_counter;

		memset(block, 0x0, STORAGE_BLOCK_SIZE * 25);

		global_counter = 0;
		api->read_file_blocks(fd1, block, i, 25);
		total_read += global_counter;
//		// <<<
//		 mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
		insecure_printf("%d-%d: w %lld r %lld (%02x, %02x)", j, i, total_write, total_read, block[99], block[199]);

		mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
		mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);
	}
	insecure_printf("Write takes %lld", total_write);

	/* BENCHMARK: read from flash */
//	memset(block, 0x0, STORAGE_BLOCK_SIZE * 25);
//	global_counter = 0;
//	for (int i = 0; i < 65; i++) {
//		api->read_file_blocks(fd1, block, 0, 25);
//		mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);
////		insecure_printf("Read %i: %lld", i, global_counter);
//	}
	insecure_printf("Read takes %lld", total_read);
	}

	api->close_file(fd1);
	api->remove_file((char *) "test_file_1.txt");

#endif


#define MEASURE_STORAGE_ROUNDTRIP
#ifdef MEASURE_STORAGE_ROUNDTRIP
	int ret;
	// uint8_t block[STORAGE_BLOCK_SIZE];
	memset(block, 0xf0, STORAGE_BLOCK_SIZE * 31);

	insecure_printf("Benchmark start.");

	int total_read = 0;
	int total_write = 0;
	int total_req = 0;

for (int ii = 0; ii <= 651; ii++) {
	if (ii == 0) {
		/* The first secure access involves Storage domain reset */
		ret = api->request_secure_storage_access(100, MAILBOX_MAX_LIMIT_VAL,
							MAILBOX_MAX_LIMIT_VAL,
							 NULL, NULL, NULL);
		if (ret) {
			printf("Error: could not get secure access to storage.\n");
			insecure_printf("Error: could not get secure access to "
					"storage.\n %d", ret);
			return;
		}

		mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
		mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);
		mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
		mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);
		continue;
	} else {
		global_counter = 0;
		ret = api->request_secure_storage_access(100, MAILBOX_MAX_LIMIT_VAL,
							MAILBOX_MAX_LIMIT_VAL,
							 NULL, NULL, NULL);
		total_req += global_counter;
		if (ret) {
			printf("Error: could not get secure access to storage.\n");
			insecure_printf("Error: could not get secure access to "
					"storage.\n %d", ret);
			return;
		}
	}

	/* BENCHMARK: write to flash */
	// _SEC_HW_ERROR("Enter Write test");
	global_counter = 0;
	ret = api->write_secure_storage_blocks(block, 0, 31);
	total_write += global_counter;
	// _SEC_HW_ERROR("Write (%d) takes %lld", ret, global_counter);

	/* BENCHMARK: read from flash */
	memset(block, 0x0, STORAGE_BLOCK_SIZE * 31);

	// _SEC_HW_ERROR("Enter Read test");
	global_counter = 0;
	ret = api->read_secure_storage_blocks(block, 0, 31);
	total_read += global_counter;
	// _SEC_HW_ERROR("Read (%d %02x) takes %lld", ret, block[0], global_counter);

	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_DATA_OUT);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_IN);
	mailbox_yield_to_previous_owner(Q_STORAGE_CMD_OUT);

	if ((ii - 1) % 65 == 0 && (ii - 1) != 0) {
		insecure_printf("Run %d: Write %d, Read %d, Req %d", 
			(ii - 1) / 65,
			total_write,
			total_read,
			total_req);
		total_read = 0;
		total_write = 0;
		total_req = 0;
	}
}
#endif

//	uint32_t data = 0;
//	int index = 0;
//
//	insecure_printf("fs_test starting.\n");
//
// 	insecure_printf("Test 1\n");
// 	uint32_t fd1 = api->open_file((char *) "test_file_1.txt", FILE_OPEN_CREATE_MODE);
// 	if (fd1 == 0) {
// 		insecure_printf("Couldn't open first file (fd1 = %d)\n", fd1);
// 		return;
// 	}
// 	uint32_t fd2 = api->open_file((char *) "test_file_2.txt", FILE_OPEN_CREATE_MODE);
// 	if (fd2 == 0) {
// 		api->close_file(fd1);
// 		insecure_printf("Couldn't open second file (fd2 = %d)\n", fd2);
// 		return;
// 	}
//
// 	data = 13;
// 	api->write_to_file(fd1, (uint8_t *) &data, 4, 0);
// 	api->write_to_file(fd1, (uint8_t *) &data, 4, 4);
// 	data = 15;
// 	api->write_to_file(fd2, (uint8_t *) &data, 4, 0);
// 	api->write_to_file(fd2, (uint8_t *) &data, 4, 4);
//
// 	api->read_from_file(fd1, (uint8_t *) &data, 4, 4);
// 	insecure_printf("data (first file) = %d\n", data);
// 	if (data != 13) {
// 		insecure_printf("Test 1 (1) failed\n");
// 		goto out;
// 	}
// 	api->read_from_file(fd2, (uint8_t *) &data, 4, 4);
// 	insecure_printf("data (first file) = %d\n", data);
// 	if (data != 15) {
// 		insecure_printf("Test 1 (2) failed\n");
// 		goto out;
// 	}
//
// 	insecure_printf("Test 1 passed.\n");
// 	insecure_printf("Test 2\n");
// #ifndef ARCH_SEC_HW
// 	uint8_t block[STORAGE_BLOCK_SIZE * 100];
// #else
// 	uint8_t block[STORAGE_BLOCK_SIZE * 2];
// #endif
// 	memset(block, 0x0, STORAGE_BLOCK_SIZE);
//
// 	block[10] = 14;
// 	// // DEBUG
// 	// for (int j = 15; j<300; j++)
// 	// 	block[j] = j % 255;
//
// 	api->write_file_blocks(fd2, block, 0, 1);
// 	memset(block, 0x0, STORAGE_BLOCK_SIZE);
// 	api->read_file_blocks(fd2, block, 0, 1);
// 	insecure_printf("block[10] = %d\n", (int) block[10]);
// 	if (block[10] != 14) {
// 		insecure_printf("Test 2 failed\n");
// 		goto out;
// 	}
// 	insecure_printf("Test 2 passed.\n");
//
// /* sec_hw skip this test because
//  * block[STORAGE_BLOCK_SIZE * 100] is way too large
//  */
// #ifndef ARCH_SEC_HW
// 	insecure_printf("Test 3\n");
// 	memset(block, 0x0, STORAGE_BLOCK_SIZE * 100);
//
// 	index = (99 * STORAGE_BLOCK_SIZE) + 10;
// 	block[index] = 12;
// 	api->write_file_blocks(fd2, block, 1, 100);
// 	memset(block, 0x0, STORAGE_BLOCK_SIZE * 100);
// 	api->read_file_blocks(fd2, block, 1, 100);
// 	insecure_printf("block[index] = %d\n", (int) block[index]);
// 	if (block[index] != 12) {
// 		insecure_printf("Test 3 failed\n");
// 		goto out;
// 	}
// 	insecure_printf("Test 3 passed.\n");
// #endif
//
//out:
//	api->close_file(fd1);
//	api->remove_file((char *) "test_file_1.txt");
//	api->close_file(fd2);
//	api->remove_file((char *) "test_file_2.txt");
}
