/* octopos scheduler */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <octopos/error.h>
#include "scheduler.h"


#define MAX_NUM_APPS	64 /* must be divisible by 8 */
uint8_t app_id_bitmap[MAX_NUM_APPS / 8];

struct app_list_node {
	struct app *app;
	struct app_list_node *next;
};

struct app_list_node *app_list_head = NULL;
struct app_list_node *app_list_tail = NULL;

uint8_t RUNTIME_PROC_IDS[NUM_RUNTIME_PROCS] = {P_RUNTIME};

struct runtime_proc *runtime_procs = NULL;

/* FIXME: move to header file */
int send_msg_to_runtime(uint8_t runtime_proc_id, uint8_t *buf);

static struct runtime_proc *get_idle_runtime_proc(void)
{
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		/* FIXME: this needs to be in a critical section */
		if (runtime_procs[i].state == RUNTIME_PROC_IDLE) {
			runtime_procs[i].state = RUNTIME_PROC_RESERVED;
			return &runtime_procs[i];
		}
	}

	return NULL;
}

static void try_running_app(struct app *app)
{
	struct runtime_proc *runtime_proc = get_idle_runtime_proc();

	if (!runtime_proc)
		return;

	/* FIXME: send_msg_to_runtime doesn't check for ret from runtime. It assumes success. */
	int ret = send_msg_to_runtime(runtime_proc->id, (uint8_t *) app->name);
	if (ret) {
		printf("%s: Error: couldn't run app %s\n", __func__, app->name);
		runtime_proc->state = RUNTIME_PROC_IDLE;
		return;
	}

	app->state = SCHED_RUNNING;
	app->runtime_proc = runtime_proc;
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

static int add_app_to_list(struct app *app)
{
	struct app_list_node *node = 
		(struct app_list_node *) malloc(sizeof(struct app_list_node));
	if (!node)
		return ERR_MEMORY;

	node->app = app;
	node->next = NULL;

	if (app_list_head == NULL && app_list_tail == NULL) {
		/* first node */
		app_list_head = node;
		app_list_tail = node;
	} else {
		app_list_tail->next = node;
		app_list_tail = node;
	}

	return 0;
}

static int remove_app_from_list(struct app *app)
{
	struct app_list_node *prev_node = NULL;

	for (struct app_list_node *node = app_list_head; node;
	     node = node->next) {
		if (node->app == app) {
			if (prev_node == NULL) { /* removing head */
				if (app_list_head == app_list_tail) { /* last node */
					app_list_head = NULL;
					app_list_tail = NULL;
				} else {
					app_list_head = node->next;
				}
			} else {
				prev_node->next = node->next;
			}

			return 0;
		}

		prev_node = node;
	}

	return ERR_EXIST;
}

struct app *get_app(int app_id)
{
	for (struct app_list_node *node = app_list_head; node;
	     node = node->next) {
		if (node->app->id == app_id)
			return node->app;
	}

	return NULL;
}

static struct app *get_ready_app(void)
{
	for (struct app_list_node *node = app_list_head; node;
	     node = node->next) {
		if (node->app->state == SCHED_READY)
			return node->app;
	}

	return NULL;
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

	add_app_to_list(app);

	return app_id;
}

int sched_connect_apps(int input_app_id, int output_app_id)
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

	return 0;
}

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

	try_running_app(app);

	return 0;
}

struct runtime_proc *get_runtime_proc(int id)
{
	for (int i = 0; i < NUM_RUNTIME_PROCS; i++) {
		if (runtime_procs[i].id == id)
			return &runtime_procs[i];
	}

	return NULL;
}

/* TODO: the scheduling algorithm needs to be implemented here */
void sched_next_app(void)
{
	struct app *app = get_ready_app();

	if (app)
		try_running_app(app);
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

	runtime_proc->state = RUNTIME_PROC_IDLE;	
	runtime_proc->app = NULL;	

	mark_app_id_as_unused(app->id);
	remove_app_from_list(app);
	free(app);
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
		runtime_procs[i].state = RUNTIME_PROC_IDLE;
	}
}
