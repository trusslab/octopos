#include <octopos/mailbox.h>

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
	struct runtime_proc *runtime_proc;
	bool waiting_for_msg;
	uint8_t msg_buf[APP_MSG_BUF_SIZE];
	int msg_size;
	bool has_pending_msg;
};

#define RUNTIME_PROC_IDLE		0
#define RUNTIME_PROC_RUNNING_APP	1
#define RUNTIME_PROC_RESERVED		2

struct runtime_proc {
	uint8_t id;
	int state;
	struct app *app;
	uint8_t pending_secure_ipc_request;
};
