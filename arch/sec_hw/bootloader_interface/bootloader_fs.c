#include "xil_printf.h"
#include <arch/mailbox_os.h>
#include <arch/sec_hw.h>
#include <arch/portab.h>
#include <arch/srec_errors.h>
#include <arch/srec.h>
#include "sleep.h"
#include "xstatus.h"
#include "os/storage.h"
#include <octopos/mailbox.h>
#include <octopos/storage.h>

static srec_info_t srinfo;
static uint8 sr_buf[SREC_MAX_BYTES];
static uint8 sr_data_buf[SREC_DATA_MAX_BYTES];

uint8 get_srec_line(uint8 *line, uint8 *buf)
{
    uint8 c;
    int count = 0;

    while (1) {
        c  = *line++;
        if (c == 0xD) {
            /* Eat up the 0xA too */
            c = *line++;
            return 0;
        }

        *buf++ = c;
        count++;
        if (count > SREC_MAX_BYTES)
            return LD_SREC_LINE_ERROR;
    }
}

void os_request_boot_image_by_line(uint32_t proc_id, uint32_t runtime_id)
{
	u8 unpack_buf[1024];
	u16 unpack_buf_head = 0;
	u8 ret;
	void (*laddr)();

	srinfo.sr_data = sr_data_buf;

	// FIXME: is there a better way to wait for storage boot?
	sleep(5);
	u32 message_count = OS_IMAGE_SIZE / STORAGE_BLOCK_SIZE;

	STORAGE_SET_TWO_ARGS(proc_id, runtime_id)
	buf[0] = STORAGE_OP_BOOT_REQ;
	send_msg_to_storage_no_response(buf);

	for (uint32_t i = 0; i < message_count; i++) {

		// FIXME
		/* unpack buffer is full, but still, haven't finish a line */
		if (unpack_buf_head > 1024 - STORAGE_BLOCK_SIZE)
			SEC_HW_DEBUG_HANG();

		read_from_storage_data_queue(&unpack_buf[unpack_buf_head]);

		/* load the line */
        if ((ret = get_srec_line(&unpack_buf[0], sr_buf)) != 0)
        	SEC_HW_DEBUG_HANG();

        if ((ret = decode_srec_line(sr_buf, &srinfo)) != 0)
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

                /* we already reach the end of image, there may be paddings.
                 * consume these paddings in this loop.
                 */
                while(i < message_count - 1)
                	read_from_storage_data_queue(&unpack_buf[0]);

                /* consume the ack from CMD queue */
                get_response_from_storage(buf);

                /* jump to start vector of loaded program */
                (*laddr)();

                /* the old program is dead at this point */
                break;
	        }

        // FIXME
        /* copy the leftover to the beginning of queue */
		unpack_buf_head += STORAGE_BLOCK_SIZE;
	}

	/* if program reaches here, something goes wrong */
	SEC_HW_DEBUG_HANG();
	return;
}
