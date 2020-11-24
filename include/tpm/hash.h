#include <octopos/mailbox.h>

#if (MAILBOX_QUEUE_MSG_SIZE >= 33) && (MAILBOX_QUEUE_MSG_SIZE < 66)
/* In this case, two messages will be needed, which is what is assumed in the
 * code that sends/receives the hash over the mailbox.
 */
#define TPM_EXTEND_HASH_SIZE			65
#define TPM_EXTEND_HASH_NUM_MAILBOX_MSGS	2
#endif

int hash_file(char *path, char *hash_buf);
