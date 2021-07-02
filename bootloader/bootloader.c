/* OctopOS bootloader */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#ifndef ARCH_SEC_HW_BOOT
#include <dlfcn.h>
#include <fcntl.h>
#include <semaphore.h>
#include <tpm/hash.h>
#include <tpm/rsa.h>
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

/* Need to make sure msgs are big enough so that we don't overflow
 * when processing incoming msgs and preparing outgoing ones.
 */
#if MAILBOX_QUEUE_MSG_SIZE < 64
#error MAILBOX_QUEUE_MSG_SIZE is too small.
#endif

void init_platform();
void cleanup_platform();
void cleanup_qspi_flash();

/* Defines */
#define CR       13

/* Declarations */
static void display_progress (uint32 lines);
static uint8 load_exec ();
static uint8 flash_get_srec_line (uint8 *buf);
extern void init_stdout();

extern int srec_line;

extern void outbyte(char c);

/* Data structures */
static srec_info_t srinfo;
static uint8 sr_buf[SREC_MAX_BYTES];
static uint8 sr_data_buf[SREC_DATA_MAX_BYTES];

static uint8 *flbuf;

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
void bootloader_close_file_system(void);
void send_measurement_to_tpm(char *path);

#ifdef ARCH_UMODE
unsigned char admin_public_key[] =
"-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwWFcfENwpIqWp3spCLTg\n"\
"XncdEG4eBQQK6YV4cvX//b2ab8rkwo+xmLD0lGqpFrtWHAvtiI5fqh5jPHZwrd54\n"\
"1bIXcrJOrhhAJGiEW/i/aQB/XQyFWDWt/+wr6SE7J5KZEHZpVxsSeu9yuIWDSYTp\n"\
"cOk674/leUjIpPpxZkbHVQe0R/Dja1Xi5SRnyeuYX7fSV2mDNltZ3sCuCXyVNgJ1\n"\
"wtFGZj87NCHw7vbPJxI8hb2ro3REbUUzfeB0A+tizU54MkCot50iqgX0C3TLavC4\n"\
"UysSb22EZY89zS6eZ174Lru4XYEIpStT6IzurmvLbU2AECkkRNlJBc6e+jMR8z34\n"\
"cQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

/*
 * @path: path of the file the signature of which we're checking.
 * @signature_path: the file containing the signature.
 */
static int secure_boot_check(char *path, char *signature_path)
{
	uint8_t file_hash_computed[TPM_EXTEND_HASH_SIZE];
	uint8_t file_hash_decrypted[TPM_EXTEND_HASH_SIZE];
	uint8_t signature[RSA_SIGNATURE_SIZE];
	FILE *filep;
	int ret;
	uint32_t size;

	/* generate the hash */
	hash_file(path, file_hash_computed);

	/* decrypt the signature to get the hash */
	filep = fopen(signature_path, "r");
	if (!filep) {
		printf("Error: %s: Couldn't open %s (r).\n", __func__,
		       signature_path);
		return -1;
	}

	fseek(filep, 0, SEEK_SET);
	size = (uint32_t) fread(signature, sizeof(uint8_t), RSA_SIGNATURE_SIZE,
				filep);
	if (size != RSA_SIGNATURE_SIZE) {
		printf("Error: %s: couldn't read the signature.\n", __func__);
		fclose(filep);
		return -1;
	}

	fclose(filep);

	ret = public_decrypt((unsigned char *) signature, RSA_SIGNATURE_SIZE,
			     admin_public_key, file_hash_decrypted);
	if (ret != TPM_EXTEND_HASH_SIZE) {
		printf("Error: %s: couldn't decrypt the signature (%d).\n",
		       __func__, ret);
		return -1;
	}

	ret = memcmp(file_hash_computed, file_hash_decrypted,
		     TPM_EXTEND_HASH_SIZE);
	if (ret) {
		printf("Error: %s: computed and decrypted hashes don't match.\n",
		       __func__);
		return -1;
	}

	return 0;
}
#endif

int main(int argc, char *argv[])
{
	char path[128];
	int ret;
#ifndef ARCH_SEC_HW_BOOT
	char *name;
	sem_t *sem;
	char signature_filename[128];
	char signature_filepath[128];

	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: bootloader init\n", __func__);

	if (argc < 2) {
		fprintf(stderr, "Usage: ``bootloader <executable_name> "
			"[parameters]''.\n");
		return -1;
	}

	name = argv[1];
#else /* ARCH_SEC_HW_BOOT */

	/* Clear target memory contents */
	memset((void*) DDR_BASE_ADDRESS, 0, DDR_RANGE);

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

#ifndef ARCH_SEC_HW_BOOT
	sem = sem_open("/tpm_sem", O_CREAT, 0644, 1);
	if (sem == SEM_FAILED) {
		printf("Error: couldn't open tpm semaphore.\n");
		exit(-1);
	}
#endif /* ARCH_SEC_HW_BOOT */

	memset(path, 0x0, 128);
	/* FIXME: use a different path. */
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

#ifndef ARCH_SEC_HW_BOOT
	strcpy(signature_filename, name);
	strcat(signature_filename, "_signature");
	strcpy(signature_filepath, "./bootloader/");
	strcat(signature_filepath, signature_filename);
	/* Receive the signature file and check for secure boot. */
	copy_file_from_boot_partition(signature_filename, signature_filepath);
	ret = secure_boot_check(path, signature_filepath);
	if (ret) {
		printf("Error: %s: secure boot failed.\n", __func__);
		return -1;
	}

	printf("%s: passed secure boot.\n", __func__);
	
	bootloader_close_file_system();

	/* Add exec permission for the copied file */
	chmod(path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);

	sem_wait(sem);
	send_measurement_to_tpm(path);
	sem_post(sem);
	sem_close(sem);

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
		char *const args[] = {name, (char *) argv[2], (char *) argv[3],
				      NULL};
		execv(path, args);
	} else {
		char *const args[] = {name, NULL};
		execv(path, args);
	}
#endif /* ARCH_SEC_HW_BOOT */

	return 0;
}
