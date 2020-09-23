/* octopos scheduler */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <octopos/runtime.h>
#include <octopos/error.h>
#include <os/scheduler.h>
#include <arch/mailbox_os.h>
#include <arch/defines.h>

#define MAX_NUM_APPS	64 /* must be divisible by 8 */
uint8_t app_id_bitmap[MAX_NUM_APPS / 8];

struct app_list_node {
	struct app *app;
	struct app_list_node *next;
};

struct app_list_node *all_app_list_head = NULL;
struct app_list_node *all_app_list_tail = NULL;

struct app_list_node *ready_queue_head = NULL;
struct app_list_node *ready_queue_tail = NULL;

uint8_t RUNTIME_PROC_IDS[NUM_RUNTIME_PROCS] = {P_RUNTIME1, P_RUNTIME2, P_UNTRUSTED};
uint8_t RUNTIME_QUEUE_IDS[NUM_RUNTIME_PROCS] = {Q_RUNTIME1, Q_RUNTIME2, Q_UNTRUSTED};

struct runtime_proc *runtime_procs = NULL;

uint64_t timer_ticks = 0;

/* FIXME: hack for the untrusted domain */
struct runtime_proc untrusted_runtime_proc;
struct app untrusted_app;

void update_timer_ticks(void)
{
	timer_ticks++;
}

static uint64_t get_timer_ticks(void)
{
	return timer_ticks;
}

uint8_t get_runtime_queue_id(uint8_t runtime_proc_id)
{
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		if (RUNTIME_PROC_IDS[i] == runtime_proc_id)
			return RUNTIME_QUEUE_IDS[i];
	}

	return 0;
}

bool is_valid_runtime_queue_id(int queue_id)
{
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		if (RUNTIME_QUEUE_IDS[i] == queue_id)
			return true;
	}

	return false;
}

uint8_t get_runtime_proc_id(uint8_t runtime_queue_id)
{
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		if (RUNTIME_QUEUE_IDS[i] == runtime_queue_id)
			return RUNTIME_PROC_IDS[i];
	}

	return 0;
}


static struct runtime_proc *get_idle_runtime_proc(void)
{
	static struct runtime_proc *waiting_for_proc = NULL;
	static int wait_counter = 0;

	if (waiting_for_proc) {
		if (waiting_for_proc->state != RUNTIME_PROC_IDLE) {
			wait_counter++;

			if (wait_counter > 5) { /* FIXME: 5 is arbitrary for now */
				printf("Error (%s): runtime_proc %d is not stopping. Need to hard reset.\n",
				       __func__, waiting_for_proc->id);
				/* FIXME: implement hard reset */
			}

			return NULL;
		} else {
			struct runtime_proc *runtime_proc = waiting_for_proc;
			waiting_for_proc = NULL;
			return runtime_proc;
		}
	}

	/* Let's first see if any of the runtimes are idle */
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		/* FIXME: this needs to be in a critical section */
		if (runtime_procs[i].state == RUNTIME_PROC_IDLE) {
			runtime_procs[i].state = RUNTIME_PROC_RESERVED;
			return &runtime_procs[i];
		}
	}

	uint64_t largest_elapsed = 0;
	uint64_t current_ticks = get_timer_ticks();
	struct runtime_proc *candidate = NULL;
	/* Now, let' see if we can context switch any of them */
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		if (runtime_procs[i].state == RUNTIME_PROC_RUNNING_APP) {
			uint64_t elapsed = current_ticks - runtime_procs[i].app->start_time;
			if (elapsed >= 10 && elapsed > largest_elapsed) { /* FIXME: 10 is arbitrary for now */
				candidate = &runtime_procs[i];
				largest_elapsed = elapsed;
			}
		}
	}

	if (candidate) {
		uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
		buf[0] = RUNTIME_QUEUE_CONTEXT_SWITCH_TAG;
		check_avail_and_send_msg_to_runtime(candidate->id, buf);
		waiting_for_proc = candidate;
		wait_counter = 0;
	}

	return NULL;
}

static void run_app_on_runtime_proc(struct app *app, struct runtime_proc *runtime_proc)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];

	if (!runtime_proc)
		return;

	buf[0] = RUNTIME_QUEUE_EXEC_APP_TAG;
	strcpy((char *) &buf[1], app->name);

	/* FIXME: send_msg_to_runtime doesn't check for ret from runtime. It assumes success. */
	int ret = check_avail_and_send_msg_to_runtime(runtime_proc->id, buf);
	if (ret) {
		printf("%s: Error: couldn't run app %s\n", __func__, app->name);
		runtime_proc->state = RUNTIME_PROC_IDLE;
		return;
	}

	app->state = SCHED_RUNNING;
	app->runtime_proc = runtime_proc;
	app->start_time = get_timer_ticks();
	runtime_proc->app = app;
	runtime_proc->state = RUNTIME_PROC_RUNNING_APP;
}

static int get_unused_app_id(void)
{
	for (int i = 0; i < (MAX_NUM_APPS / 8); i++) {
		if (app_id_bitmap[i] == 0xFF)
			continue;

		uint8_t mask = 0b00000001;
		for (int j = 0; j < 8; j++) {
			if (((uint8_t) (app_id_bitmap[i] | ~mask)) != 0xFF) {
				app_id_bitmap[i] |= mask;
				return (i * 8) + j + 1;
			}

			mask = mask << 1;
		}
	}

	return ERR_EXIST;
}

static void mark_app_id_as_unused(int _app_id)
{
	int app_id = _app_id - 1;

	if (app_id >= MAX_NUM_APPS) {
		printf("%s: Error: invalid app_id %d\n", __func__, app_id);
		return;
	}

	int byte_off = app_id / 8;
	int bit_off = app_id % 8;

	uint8_t mask = 0b00000001;
	for (int i = 0; i < bit_off; i++)
		mask = mask << 1;

	app_id_bitmap[byte_off] &= ~mask;
}

static bool is_app_available(char *app_name)
{
	/* FIXME: implement */
	return true;
}

static int add_app_to_list(struct app *app, struct app_list_node **head, struct app_list_node **tail)
{
	struct app_list_node *node =
		(struct app_list_node *) malloc(sizeof(struct app_list_node));
	if (!node)
		return ERR_MEMORY;

	node->app = app;
	node->next = NULL;

	if ((*head) == NULL && (*tail) == NULL) {
		/* first node */
		(*head) = node;
		(*tail) = node;
	} else {
		(*tail)->next = node;
		(*tail) = node;
	}

	return 0;
}

static int remove_app_from_list(struct app *app, struct app_list_node **head, struct app_list_node **tail)
{
	struct app_list_node *prev_node = NULL;

	for (struct app_list_node *node = (*head); node;
	     node = node->next) {
		if (node->app == app) {
			if (prev_node == NULL) { /* removing head */
				if (node == (*tail)) { /* last node */
					(*head) = NULL;
					(*tail) = NULL;
				} else {
					(*head) = node->next;
				}
			} else {
				prev_node->next = node->next;
				if (node == (*tail)) {
					(*tail) = prev_node;
				}
			}

			return 0;
		}

		prev_node = node;
	}
	return ERR_EXIST;
}

static int add_app_to_all_app_list(struct app *app)
{
	return add_app_to_list(app, &all_app_list_head, &all_app_list_tail);
}

static int remove_app_from_all_app_list(struct app *app)
{
	return remove_app_from_list(app, &all_app_list_head, &all_app_list_tail);
}

struct app *get_app(int app_id)
{
	for (struct app_list_node *node = all_app_list_head; node;
	     node = node->next) {
		if (node->app->id == app_id)
			return node->app;
	}

	return NULL;
}

static int add_app_to_ready_queue(struct app *app)
{
	int result = add_app_to_list(app, &ready_queue_head, &ready_queue_tail);
	return result;
}

static int remove_app_from_ready_queue(struct app *app)
{
	int result = remove_app_from_list(app, &ready_queue_head, &ready_queue_tail);
	return result;
}

static struct app *get_app_from_ready_queue(void)
{
	if (!ready_queue_head)
		return NULL;

	struct app *app = ready_queue_head->app;

	remove_app_from_ready_queue(app); 

	return app;
}

static bool is_any_ready_app(void)
{
	if (!ready_queue_head)
		return false;

	return true;
}

int sched_create_app(char *app_name)
{
	int app_name_size = strlen(app_name);
	if (app_name_size >= APP_NAME_SIZE) {
		printf("%s: Error: app name is too long\n", __func__);
		return ERR_INVALID;
	}

	if (!is_app_available(app_name))
		return ERR_EXIST;

	int app_id = get_unused_app_id();
	if (app_id <= 0) {
		printf("%s: Error: couldn't get a valid app id (%d)\n", __func__, app_id);
		return ERR_FAULT;
	}

	struct app *app = (struct app *) calloc(sizeof(struct app), 1);
	if (!app) {
		printf("%s: Error: couldn't allocate memory for app struct\n", __func__);
		return ERR_MEMORY;
	}

	strcpy(app->name, app_name);
	app->id = app_id;
	app->input_src = 0; /* shell */
	app->output_dst = 0; /* shell */
	app->state = SCHED_NOT_STARTED;
	app->sec_partition_created = false;
	app->sec_partition_id = -1;
	app->socket_created = false;
	app->socket_saddr = 0;
	app->socket_sport = 0;
	app->socket_daddr = 0;
	app->socket_dport = 0;

	add_app_to_all_app_list(app);

	return app_id;
}

int sched_connect_apps(int input_app_id, int output_app_id, int two_way)
{
	struct app *input_app = get_app(input_app_id);
	if (!input_app_id) {
		printf("%s: Error: couldn't find app %d\n", __func__, input_app_id);
		return ERR_EXIST;
	}

	struct app *output_app = get_app(output_app_id);
	if (!output_app_id) {
		printf("%s: Error: couldn't find app %d\n", __func__, output_app_id);
		return ERR_EXIST;
	}

	input_app->input_src = output_app_id;
	output_app->output_dst = input_app_id;
	if (two_way) {
		input_app->output_dst = output_app_id;
		output_app->input_src = input_app_id;
	}

	return 0;
}

/* FIXME: change func name */
int sched_run_app(int app_id)
{
	struct app *app = get_app(app_id);
	if (!app) {
		printf("%s: Error: couldn't find app %d\n", __func__, app_id);
		return ERR_EXIST;
	}

	if (app->state != SCHED_NOT_STARTED) {
		printf("%s: Error: unexpected app status\n", __func__);
		return ERR_UNEXPECTED;
	}

	app->state = SCHED_READY;

	add_app_to_ready_queue(app);

	sched_next_app();

	return 0;
}

struct runtime_proc *get_runtime_proc(int id)
{
	/* FIXME: hack for the untrusted domain */
	if (id == P_UNTRUSTED)
		return &untrusted_runtime_proc;

	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		if (runtime_procs[i].id == id)
			return &runtime_procs[i];
	}

	return NULL;
}

/* TODO: the scheduling algorithm needs to be implemented here */
void sched_next_app(void)
{
	bool ret = is_any_ready_app();
	if (!ret)
		return;

	struct runtime_proc *runtime_proc = get_idle_runtime_proc();
	if (!runtime_proc)
		return;

	struct app *app = get_app_from_ready_queue();
	/* should not happen */
	if (!app) {
		printf("Error (%s): app is NULL!\n", __func__);
		return;
	}

	run_app_on_runtime_proc(app, runtime_proc);
}

void sched_clean_up_app(uint8_t runtime_proc_id)
{
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc) {
		printf("%s: Error: invalid runtime proc id %d\n", __func__, runtime_proc_id);
		return;
	}

	if (runtime_proc->state != RUNTIME_PROC_RUNNING_APP) {
		printf("%s: Error: invalid runtime proc state\n", __func__);
		return;
	}

	struct app *app = runtime_proc->app;
	if (!app) {
		printf("%s: Error: app struct is NULL\n", __func__);
		return;
	}

	runtime_proc->state = RUNTIME_PROC_RESETTING;	
	runtime_proc->app = NULL;	

	mark_app_id_as_unused(app->id);
	remove_app_from_all_app_list(app);
	free(app);
}

void sched_pause_app(uint8_t runtime_proc_id)
{
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc) {
		printf("%s: Error: invalid runtime proc id %d\n", __func__, runtime_proc_id);
		return;
	}

	if (runtime_proc->state != RUNTIME_PROC_RUNNING_APP) {
		printf("%s: Error: invalid runtime proc state\n", __func__);
		return;
	}

	struct app *app = runtime_proc->app;
	if (!app) {
		printf("%s: Error: app struct is NULL\n", __func__);
		return;
	}

	app->state = SCHED_READY;
	add_app_to_ready_queue(app);

	runtime_proc->state = RUNTIME_PROC_RESETTING;	
}

int sched_runtime_ready(uint8_t runtime_proc_id)
{
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc) {
		printf("%s: Error: invalid runtime proc id %d\n", __func__, runtime_proc_id);
		return ERR_INVALID;
	}

	if (runtime_proc->state != RUNTIME_PROC_RESETTING) {
		printf("%s: Error: invalid runtime proc state\n", __func__);
		return ERR_INVALID;
	}

	runtime_proc->state = RUNTIME_PROC_IDLE;

	return 0;
}

int sched_runtime_reset(uint8_t runtime_proc_id)
{
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc) {
		printf("%s: Error: invalid runtime proc id %d\n", __func__, runtime_proc_id);
		return ERR_INVALID;
	}

	if (runtime_proc->state != RUNTIME_PROC_IDLE) {
		printf("%s: Error: invalid runtime proc state\n", __func__);
		return ERR_INVALID;
	}

	runtime_proc->state = RUNTIME_PROC_RESETTING;

	return 0;
}

void initialize_scheduler(void)
{
	/* initialize app id bitmap */
	if (MAX_NUM_APPS % 8) {
		printf("%s: Error: MAX_NUM_APPS must be divisible by 8\n", __func__);
		_exit(-1);
	}

	for (int i = 0; i < (MAX_NUM_APPS / 8); i++)
		app_id_bitmap[i] = 0;


	/* initialize runtime procs */
	runtime_procs = (struct runtime_proc *) calloc(sizeof(struct runtime_proc), NUM_RUNTIME_PROCS);
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		runtime_procs[i].id = RUNTIME_PROC_IDS[i];
		runtime_procs[i].state = RUNTIME_PROC_RESETTING;
		runtime_procs[i].app = NULL;
		runtime_procs[i].pending_secure_ipc_request = 0;
	}
	
	/* FIXME: hack for the untrusted domain */
	untrusted_app.state = SCHED_RUNNING;
	untrusted_app.runtime_proc = &untrusted_runtime_proc;
	untrusted_runtime_proc.app = &untrusted_app;
	untrusted_runtime_proc.state = RUNTIME_PROC_RUNNING_APP;
}
