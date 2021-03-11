/* OctopOS bootloader */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <tpm/hash.h>
#include <tpm/rsa.h>

void prepare_bootloader(char *filename, int argc, char *argv[]);
/*
 * @filename: the name of the file in the partition
 * @path: file path in the host file system
 */
int copy_file_from_boot_partition(char *filename, char *path);
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
	char *name;
	sem_t *sem;
	char path[128];
	int ret;

	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: bootloader init\n", __func__);

	/* Need to make sure msgs are big enough so that we don't overflow
	 * when processing incoming msgs and preparing outgoing ones.
	 */
	/* FIXME: find the smallest bound. 64 is conservative. */
	if (MAILBOX_QUEUE_MSG_SIZE < 64) {
		printf("Error: %s: MAILBOX_QUEUE_MSG_SIZE is too small (%d).\n",
		       __func__, MAILBOX_QUEUE_MSG_SIZE);
		return -1;
	}

	if (argc < 2) {
		fprintf(stderr, "Usage: ``bootloader <executable_name> "
			"[parameters]''.\n");
		return -1;
	}

	name = argv[1];
	
	sem = sem_open("/tpm_sem", O_CREAT, 0644, 1);
	if (sem == SEM_FAILED) {
		printf("Error: couldn't open tpm semaphore.\n");
		exit(-1);
	}

	memset(path, 0x0, 128);
	/* FIXME: use a different path. */
	strcpy(path, "./bootloader/");
	strcat(path, name);
	/* FIXME */
	if (!strcmp(name, "runtime"))
		strcat(path, argv[2]);

	prepare_bootloader(name, argc - 2, argv + 2);
	copy_file_from_boot_partition(name, path);

#ifdef ARCH_UMODE
	/* Receive the signature file for bluetooth needed for secure boot. */
	if (!strcmp(name, "bluetooth")) {
		/* FIXME: the first parameter won't be used. */
		copy_file_from_boot_partition((char *) "bluetooth_signature",
				(char *) "./bootloader/bluetooth_signature");
		ret = secure_boot_check((char *) "./bootloader/bluetooth",
				(char *) "./bootloader/bluetooth_signature");
		if (ret) {
			printf("Error: %s: secure boot failed.\n", __func__);
			return -1;
		}
	}
#endif

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

	return 0;
}
