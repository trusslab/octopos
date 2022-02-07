#ifndef _OS_INCLUDE_STORAGE_H_
#define _OS_INCLUDE_STORAGE_H_

#include <tpm/hash.h>
#include <arch/syscall.h>

#define PARTITION_SIZE		1000 /* blocks */

struct partition {
	uint32_t partition_id;
	uint32_t size;
	uint8_t is_created;
	uint8_t key[TPM_EXTEND_HASH_SIZE];
};

/* Status of the storage service */
#define OS_ACCESS	0 /* OS has access but its partition isn't bound. */
#define OS_USE		1 /* OS has access and its partition is bound. */
#define APP_ACCESS	2 /* An app has access. */

void wait_for_storage(void);
int wait_for_storage_for_os_use(void);
void handle_request_secure_storage_creation_syscall(uint8_t runtime_proc_id,
						    uint8_t *buf);
void handle_request_secure_storage_access_syscall(uint8_t runtime_proc_id,
						  uint8_t *buf);
uint32_t initialize_storage(void);

#endif /* _OS_INCLUDE_STORAGE_H_ */
