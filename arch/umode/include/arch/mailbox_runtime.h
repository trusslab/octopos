/* FIXME: consolidate with arch/mailbox.h of secure_hw */
void mailbox_yield_to_previous_owner(uint8_t queue_id);
int mailbox_attest_queue_access(uint8_t queue_id, limit_t limit,
				timeout_t timeout);
int mailbox_attest_queue_owner(uint8_t queue_id, uint8_t owner);
void runtime_recv_msg_from_queue(uint8_t *buf, uint8_t queue_id);
void runtime_send_msg_on_queue(uint8_t *buf, uint8_t queue_id);
void runtime_recv_msg_from_queue_large(uint8_t *buf, uint8_t queue_id);
void runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id);
void is_ownership_change(int *is_change);
void reset_queue_sync(uint8_t queue_id, int init_val);
void queue_sync_getval(uint8_t queue_id, int *val);
void wait_on_queue(uint8_t queue_id);
void wait_for_app_load(void);
void load_application_arch(char *msg, struct runtime_api *api);
void runtime_core(void);
int init_runtime(int runtime_id);
void close_runtime(void);
