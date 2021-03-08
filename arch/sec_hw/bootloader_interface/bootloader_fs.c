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
	u8 line_buf[256];
	u8 ret;
	void (*laddr)();

	srinfo.sr_data = sr_data_buf;

	STORAGE_SET_TWO_ARGS(proc_id, runtime_id)
	buf[0] = STORAGE_OP_BOOT_REQ;
	send_msg_to_storage_no_response(buf);

	for (uint32_t i = 0; i < OS_IMAGE_LINE_NUMBER; i++) {
		 /* FIXME: large queue: each 512 message has 2 lines */
		for (uint32_t j = 0; j < (SREC_MAX_BYTES + 1) / STORAGE_BLOCK_SIZE; j++) {
			read_from_storage_data_queue(line_buf + (j * STORAGE_BLOCK_SIZE));
		}

        if ((ret = get_srec_line(line_buf, sr_buf)) != 0)
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

                /* sanity check */
                if (OS_IMAGE_LINE_NUMBER - 1 != i)
                	SEC_HW_DEBUG_HANG();

                get_response_from_storage(buf);

                (*laddr)();
                break;
	        }
	}

	/* We will be dead at this point */
	return;
}
