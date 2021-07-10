#include "xil_printf.h"
#include <arch/mailbox_os.h>
#include <arch/sec_hw.h>
#include <arch/portab.h>
#include <arch/srec_errors.h>
#include <arch/srec.h>
#include "sleep.h"
#include "xstatus.h"
#include "os/storage.h"
#include <os/file_system.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>

static srec_info_t srinfo;
static uint8 sr_buf[SREC_MAX_BYTES];
static uint8 sr_data_buf[SREC_DATA_MAX_BYTES];

void bootloader_close_file_system(void);

int get_srec_line(uint8 *line, uint8 *buf)
{
	uint8 c;
	int count = 0;

	while (1) {
		c  = *line++;
		if (c == 0xD) {
			/* Eat up the 0xA too */
			c = *line++;
			return count + 2;
		}

		*buf++ = c;
		count++;
		if (count > SREC_MAX_BYTES)
			return -LD_SREC_LINE_ERROR;
	}

	return -LD_SREC_LINE_ERROR;
}

void os_request_boot_image_by_line(char *filename, char *path)
{
	u8 unpack_buf[1024] = {0};
	u8 buf[STORAGE_BLOCK_SIZE];
	u16 unpack_buf_head = 0;
	int line_count;
	void (*laddr)();
	uint32_t fd;
	int _size;
	int offset;

	srinfo.sr_data = sr_data_buf;

	fd = file_system_open_file(filename, FILE_OPEN_MODE); 

	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file system.\r\n",
			   __func__, filename);
		return;
	}

	offset = 0;

	while (1) {
		/* unpack buffer is full, but still, haven't finish a line */
		if (unpack_buf_head > 1024 - STORAGE_BLOCK_SIZE)
			SEC_HW_DEBUG_HANG();

		/* read message from file */
		/* mailbox register must align to 4, so we have to read into an aligned buffer first */
		_size = file_system_read_from_file(fd, buf, STORAGE_BLOCK_SIZE, offset);
		if (_size == 0)
			break;

		if (_size < 0 || _size > STORAGE_BLOCK_SIZE) {
			printf("Error: %s: reading file.\n", __func__);
			break;
		}

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
					memcpy((void*)srinfo.addr, (void*)srinfo.sr_data, srinfo.dlen);
					break;
				case SREC_TYPE_5:
					break;
				case SREC_TYPE_7:
				case SREC_TYPE_8:
				case SREC_TYPE_9:
					laddr = (void (*)())srinfo.addr;

					/* clean up before load program */
					file_system_close_file(fd);

					/* jump to start vector of loaded program */
					(*laddr)();

					/* the old program is dead at this point */
					break;
			}

			/* after loading the line, remove the contents being loaded */
			memcpy(&unpack_buf[0],
					&unpack_buf[line_count],
					unpack_buf_head - line_count);

			unpack_buf_head -= line_count;
			memset(&unpack_buf[unpack_buf_head], 0, line_count);
		}

		offset += _size;
	}

	/* if program reaches here, something goes wrong */
	SEC_HW_DEBUG_HANG();
	return;
}

/* FIXME: storage has direct access to flash, so why not reading more each time? */
#define STORAGE_BOOT_BLOCK_SIZE STORAGE_BLOCK_SIZE
#define STORAGE_BOOT_UNPACK_BUF_SIZE 8192

#if STORAGE_BOOT_BLOCK_SIZE >= STORAGE_BOOT_UNPACK_BUF_SIZE
#error STORAGE_BOOT_BLOCK_SIZE cannot be bigger than STORAGE_BOOT_UNPACK_BUF_SIZE
#endif

void storage_request_boot_image_by_line(char *filename)
{
	u8 unpack_buf[STORAGE_BOOT_UNPACK_BUF_SIZE] = {0};
	u8 buf[STORAGE_BOOT_BLOCK_SIZE];
	u16 unpack_buf_head = 0;
	u32 fd;
	int line_count;
	void (*laddr)();
	int _size;
	int offset = 0;

	fd = file_system_open_file(filename, FILE_OPEN_MODE); 
	if (fd == 0) {
		printf("Error: %s: Couldn't open file %s in octopos file "
			   "system.\n", __func__, filename);
		return;
	}

	srinfo.sr_data = sr_data_buf;

	while (1) {
		/* unpack buffer is full, but still, haven't finish a line */
		if (unpack_buf_head > STORAGE_BOOT_UNPACK_BUF_SIZE - STORAGE_BOOT_BLOCK_SIZE)
			SEC_HW_DEBUG_HANG();

		/* read message from file */
		_size = file_system_read_from_file(fd, buf, STORAGE_BOOT_BLOCK_SIZE,
						   offset);
		if (_size == 0)
			break;

		if (_size < 0 || _size > STORAGE_BOOT_BLOCK_SIZE) {
			printf("Error: %s: reading file.\n", __func__);
			break;
		}

		offset += _size;

		/* copy into unpack buffer */
		memcpy(&unpack_buf[unpack_buf_head], &buf[0], STORAGE_BOOT_BLOCK_SIZE);
		unpack_buf_head += STORAGE_BOOT_BLOCK_SIZE;

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

					/* clean up before load program */
					bootloader_close_file_system();
					
					/* jump to start vector of loaded program */
					(*laddr)();

					/* the old program is dead at this point */
					break;
			}

			/* after loading the line, remove the contents being loaded */
			memcpy(&unpack_buf[0],
					&unpack_buf[line_count],
					unpack_buf_head - line_count);

			unpack_buf_head -= line_count;
			memset(&unpack_buf[unpack_buf_head], 0, line_count);
		}

		offset += _size;
	}

	/* if program reaches here, something goes wrong */
	SEC_HW_DEBUG_HANG();
	return;
}
