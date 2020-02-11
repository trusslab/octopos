#include <octopos/mailbox.h>
#include <arch/defines.h>
#ifdef ARCH_SEC_HW
#include <arch/sec_hw.h>
#endif

#define SCHED_NOT_STARTED	0
#define SCHED_READY		1
#define SCHED_RUNNING		2

#define APP_NAME_SIZE	   MAILBOX_QUEUE_MSG_SIZE /* We'll send the app name in
						     msg to runtime */

#define APP_MSG_BUF_SIZE   MAILBOX_QUEUE_MSG_SIZE

struct app {
	char name[APP_NAME_SIZE];
	int id;
	int input_src;
	int output_dst;
	int state;
	uint64_t start_time;
	struct runtime_proc *runtime_proc;
	bool waiting_for_msg;
	uint8_t msg_buf[APP_MSG_BUF_SIZE];
	int msg_size;
	bool has_pending_msg;
	/* secure storage */
	bool sec_partition_created;
	int sec_partition_id;
	/* network */
	bool socket_created;
	uint32_t socket_saddr;
	uint32_t socket_sport;
	uint32_t socket_daddr;
	uint32_t socket_dport;
};

#define RUNTIME_PROC_IDLE		0
#define RUNTIME_PROC_RUNNING_APP	1
#define RUNTIME_PROC_RESERVED		2
#define RUNTIME_PROC_RESETTING		3

struct runtime_proc {
	uint8_t id;
	int state;
	struct app *app;
	uint8_t pending_secure_ipc_request;
};

void update_timer_ticks(void);
int sched_create_app(char *app_name);
int sched_connect_apps(int input_app_id, int output_app_id, int two_way);
int sched_run_app(int app_id);
void sched_clean_up_app(uint8_t runtime_proc_id);
void sched_pause_app(uint8_t runtime_proc_id);
struct runtime_proc *get_runtime_proc(int id);
struct app *get_app(int app_id);
uint8_t get_runtime_queue_id(uint8_t runtime_proc_id);
bool is_valid_runtime_queue_id(int queue_id);
uint8_t get_runtime_proc_id(uint8_t runtime_queue_id);
void sched_next_app(void);
int sched_runtime_ready(uint8_t runtime_proc_id);
void initialize_scheduler(void);
