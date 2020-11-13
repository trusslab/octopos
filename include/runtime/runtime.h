/* FIXME: also repeated in mailbox_runtime.c */
#ifdef ARCH_UMODE
typedef int bool;
#define true	(int) 1
#define false	(int) 0
#endif

/* FIXME: do these funcs belong in the same header file? */
void issue_syscall(uint8_t *buf);
void queue_sync_getval(uint8_t queue_id, int *val);
void wait_until_empty(uint8_t queue_id, int queue_size);
void report_queue_usage(uint8_t queue_id);
