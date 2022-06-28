#ifdef ARCH_SEC_HW_OFFLINE_LOADER
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "srec.h"
#include "portab.h"

srec_info_t srinfo;
uint8 sr_buf[SREC_MAX_BYTES];
uint8 sr_data_buf[SREC_DATA_MAX_BYTES];
uint8 *flbuf;

#define PROTECTED_RANGE 0x3FFF

uint8 flash_get_srec_line(uint8 *buf)
{
    uint8 c;
    int count = 0;

    while (1) {
        c  = *flbuf++;
        printf("%08x:%08x:%d:%c\n", flbuf, buf, count, c);
        if (c == 0xD) {
                /* Eat up the 0xA too */
            c = *flbuf++;
            return 0;
	    }

        *buf++ = c;
        count++;
        if (count > SREC_MAX_BYTES)
            return LD_SREC_LINE_ERROR;
    }
}

int offline_loader(char *elf_name, char *output_path, char* buffer_size_s, char* base)
{
    int buffer_size = (int)strtol(buffer_size_s, NULL, 0);
    uint8 * target_buffer;
    uint8 ret;
    int base_addr = (int)strtol(base, NULL, 0);

    /* open file */
    FILE *fp = fopen(elf_name, "r");
    if (fp == NULL) {
        printf("Error: open file %s failed\n", elf_name);
        return -1;
    }

    /* read file into buffer */
    fseek(fp, 0, SEEK_END); 
    int size = ftell(fp); 
    fseek(fp, 0, SEEK_SET);
    flbuf = (uint8 *)malloc(size+1);
    fread(flbuf, size, 1, fp);
    flbuf[size]=0;
    printf("%d %08x\n", size, flbuf);
    fclose(fp);

    target_buffer = (uint8*)malloc(buffer_size);
    
    
    while (1) {
        if ((ret = flash_get_srec_line (sr_buf)) != 0)
            return ret;

        if ((ret = decode_srec_line (sr_buf, &srinfo)) != 0)
            return ret;

        switch (srinfo.type) {
	    case SREC_TYPE_0:
		break;
	    case SREC_TYPE_1:
	    case SREC_TYPE_2:
	    case SREC_TYPE_3:
        if (srinfo.addr - base_addr < buffer_size)
            memcpy ((void*) ((int) (srinfo.addr - base_addr) + (int)target_buffer), 
                (void*)srinfo.sr_data, srinfo.dlen);
        else if (srinfo.addr - base_addr < buffer_size + PROTECTED_RANGE)
            /* ignore write to common_heap_and_stack and protected range */
            continue;
        else {
            printf("ERROR: program address out of range%08x\n", (srinfo.addr - base_addr));
            return -1;
        }
		break;
	    case SREC_TYPE_5:
		break;
	    case SREC_TYPE_7:
	    case SREC_TYPE_8:
	    case SREC_TYPE_9:
		printf("main at %08x\n", srinfo.addr);
        FILE *pout = fopen(output_path, "wb");

        if (pout){
            fwrite(target_buffer, buffer_size, 1, pout);
            printf("success!\n");
        } else{
            return -1;
        }

        fclose(pout);
        return 0;
		break;
	    }
    }

    return -1;
}
    

int main(int argc, char *argv[])
{
    /* the first argument is the elf file name */
    /* the second argument is the output file name */
    /* the third argument is the target buffer size */
    /* the fourth argument is the base address */
    if (argc != 5) {
        printf("Usage: offline_loader <elf> <output> <buf_size> <base_addr>\n");
        return -1;
    }

    return offline_loader(argv[1], argv[2], argv[3], argv[4]);
}



#endif /* ARCH_SEC_HW_OFFLINE_LOADER */
