/* OctopOS bootloader */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#ifndef ARCH_SEC_HW_BOOT
#include <dlfcn.h>
#include <semaphore.h>
#endif
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/syscall.h>

#ifdef ARCH_SEC_HW_BOOT

#include <arch/sec_hw.h>
#include <arch/portab.h>
#include <arch/srec_errors.h>
#include <arch/mem_layout.h>
#include <arch/srec.h>

void init_platform();
void cleanup_platform();
void cleanup_qspi_flash();


/* Defines */
#define CR       13
//#define VERBOSE

/* Declarations */
static void display_progress (uint32 lines);
static uint8 load_exec ();
static uint8 flash_get_srec_line (uint8 *buf);
extern void init_stdout();

extern int srec_line;
// extern uint8_t binary[STORAGE_IMAGE_SIZE + 48] __attribute__ ((aligned(64)));

extern void outbyte(char c);


/* Data structures */
static srec_info_t srinfo;
static uint8 sr_buf[SREC_MAX_BYTES];
static uint8 sr_data_buf[SREC_DATA_MAX_BYTES];

static uint8 *flbuf;

#ifdef VERBOSE
static int8 *errors[] = {
    "",
    "Error while copying executable image into RAM",
    "Error while reading an SREC line from flash",
    "SREC line is corrupted",
    "SREC has invalid checksum."
};
#endif

#ifdef VERBOSE
static void display_progress (uint32 count)
{
    /* Send carriage return */
    outbyte (CR);
    print  ("Bootloader: Processed (0x)");
    putnum (count);
    print (" S-records");
}
#endif

static uint8 load_exec()
{
    uint8 ret;
    void (*laddr)();
    int8 done = 0;

    srinfo.sr_data = sr_data_buf;

    while (!done) {
        if ((ret = flash_get_srec_line (sr_buf)) != 0)
            return ret;

        if ((ret = decode_srec_line (sr_buf, &srinfo)) != 0)
            return ret;

#ifdef VERBOSE
        display_progress (srec_line);
#endif
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
                done = 1;
                ret = 0;
                break;
        }
    }

#ifdef VERBOSE
    print ("\r\nExecuting program starting at address: ");
    putnum ((uint32)laddr);
    print ("\r\n");
#endif

    (*laddr)();

    /* We will be dead at this point */
    return 0;
}

static uint8 flash_get_srec_line (uint8 *buf)
{
    uint8 c;
    int count = 0;

    while (1) {
        c  = *flbuf++;
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
#endif

void prepare_bootloader(char *filename, int argc, char *argv[]);
/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 */
int copy_file_from_boot_partition(char *filename, char *path);
void send_measurement_to_tpm(char *path);

//DEBUG >>>
//#ifdef ARCH_SEC_HW_BOOT_STORAGE
//
//int load_boot_image_from_storage(int pid, void *ptr);
//
//uint8_t binary[STORAGE_IMAGE_SIZE + 48] __attribute__ ((aligned(64)));
//
//#endif
//debug <<<

// debug
#ifdef ARCH_SEC_HW_BOOT_STORAGE
int bss_nop_counter = 0;
#endif

#ifndef ARCH_SEC_HW_BOOT
int main(int argc, char *argv[])
#else
int main()
#endif
{
#ifndef ARCH_SEC_HW_BOOT
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: bootloader init\n", __func__);

	if (argc < 2) {
		fprintf(stderr, "Usage: ``bootloader <executable_name> [parameters]''.\n");
		return -1;
	}

	char *name = argv[1];
#else /* ARCH_SEC_HW_BOOT */

// debug
//#ifdef ARCH_SEC_HW_BOOT_STORAGE
//    sleep(10);
//#endif
//#ifndef ARCH_SEC_HW_BOOT_STORAGE
    /* FIXME: zeroing DDR memory is not necessary for the first boot */
    memset((void*) DDR_BASE_ADDRESS, 0, DDR_RANGE);
//#endif

//// debug
//#ifdef ARCH_SEC_HW_BOOT_STORAGE
//////	for (bss_nop_counter = 0; bss_nop_counter < 100000000; bss_nop_counter++)
//////		asm("nop");
//////    memset((void*) 0x60000000, 0, 0x1ffffff);
//    sleep(10);
//#endif

#ifdef ARCH_SEC_HW_BOOT_STORAGE
	char *name = ":storage";
#elif defined(ARCH_SEC_HW_BOOT_KEYBOARD)
	char *name = ":keyboard";
#elif defined(ARCH_SEC_HW_BOOT_SERIAL_OUT)
	char *name = ":serial_out";
#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_1)
	char *name = ":runtime1";
#elif defined(ARCH_SEC_HW_BOOT_RUNTIME_2)
	char *name = ":runtime2";
#elif defined(ARCH_SEC_HW_BOOT_OS)
	char *name = ":os";
#elif defined(ARCH_SEC_HW_BOOT_NETWORK)
	char *name = ":network";
#elif defined(ARCH_SEC_HW_BOOT_LINUX)
	char *name = ":linux";
#endif /* ARCH_SEC_HW_BOOT_STORAGE */

#endif /* ARCH_SEC_HW_BOOT */
	char path[128];
	memset(path, 0x0, 128);
	strcpy(path, "./bootloader/");
	strcat(path, name);

#ifndef ARCH_SEC_HW_BOOT
	/* FIXME */
	if (!strcmp(name, "runtime"))
		strcat(path, argv[2]);

	prepare_bootloader(name, argc - 2, argv + 2);
#else
	prepare_bootloader(path, 0, NULL);
#endif

	copy_file_from_boot_partition(name, path);

	//debug >>>
//#ifdef ARCH_SEC_HW_BOOT_STORAGE
//	load_boot_image_from_storage(P_STORAGE, binary);
//	cleanup_qspi_flash();
//
//	    flbuf = binary;
//	    load_exec();
//
//	    /* we are in error if load_exec() returns */
//	    SEC_HW_DEBUG_HANG();
//#endif

#ifndef ARCH_SEC_HW_BOOT
	/* Add exec permission for the copied file */
	chmod(path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);

	send_measurement_to_tpm(path);
	
	/* FIXME */
	if (!strcmp(name, "runtime")) {

		/* Create the args for execv */
		char new_name[128];
		memset(new_name, 0x0, 128);
		strcpy(new_name, argv[1]);
		strcat(new_name, argv[2]);
		char *const args[] = {new_name, (char *) argv[2], NULL};
		execv(path, args);
	} else if (!strcmp(name, "linux")) {
		char *const args[] = {name, (char *) argv[2], (char *) argv[3], NULL};
		execv(path, args);
	} else {
		char *const args[] = {name, NULL};
		execv(path, args);
	}
#endif /* ARCH_SEC_HW_BOOT */

	return 0;
}
