/* OctopOS shell
 * Forked from https://gist.github.com/966049.git
 */

/* Compile with: g++ -Wall –Werror -o shell shell.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/error.h>
#include <os/scheduler.h>
#include <os/syscall.h>
#include <arch/mailbox_os.h>
#include <arch/defines.h>

/* The array below will hold the arguments: args[0] is the command. */
static char* args[512];
pid_t pid;
int command_pipe[2];
 
#define READ  0
#define WRITE 1

#define SHELL_STATE_WAITING_FOR_CMD		0
#define SHELL_STATE_RUNNING_APP			1
#define SHELL_STATE_APP_WAITING_FOR_INPUT	2

struct app *foreground_app = NULL;

int shell_status = SHELL_STATE_WAITING_FOR_CMD;

/* FIXME: move all mailbox-related stuff out of shell */
char output_buf[MAILBOX_QUEUE_MSG_SIZE];
#define output_printf(fmt, args...) {memset(output_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE); sprintf(output_buf, fmt, ##args); send_output((uint8_t *) output_buf);}

/*
 * Handle commands separatly
 * input: return value from previous command (useful for pipe file descriptor)
 * first: 1 if first command in pipe-sequence (no input from previous pipe)
 * last: 1 if last command in pipe-sequence (no input from previous pipe)
 *
 * EXAMPLE: If you type "ls | grep shell | wc" in your shell:
 *    fd1 = command(0, 1, 0), with args[0] = "ls"
 *    fd2 = command(fd1, 0, 0), with args[0] = "grep" and args[1] = "shell"
 *    fd3 = command(fd2, 0, 1), with args[0] = "wc"
 *
 * So if 'command' returns a file descriptor, the next 'command' has this
 * descriptor as its 'input'.
 */
static int command(int input, int first, int last, int double_pipe, int bg)
{
#ifdef ARCH_UMODE
	/* FIXME: add support for passing args to apps */

	if (first == 1 && last == 0 && input == 0) {
		// First command
		return sched_create_app(args[0]);
	} else if (first == 0 && last == 0 && input != 0) {
		// Middle command
		int app_id = sched_create_app(args[0]);
		sched_connect_apps(app_id, input, 0);
		sched_run_app(input);
		return app_id;
	} else {
		// Last command
		int app_id = sched_create_app(args[0]);
		if (input) {
			sched_connect_apps(app_id, input, double_pipe);
			sched_run_app(input);
		}
		sched_run_app(app_id);
		if (!bg) {
			foreground_app = get_app(app_id);
			shell_status = SHELL_STATE_RUNNING_APP;
		} else {
			output_printf("octopos$> ");
		}
		return app_id;
	}
#else
	return 0;
#endif
}

/* Final cleanup, 'wait' for processes to terminate.
 *  n : Number of times 'command' was invoked.
 */
static void cleanup(int n)
{
#ifdef ARCH_UMODE
	int i;
	for (i = 0; i < n; ++i) 
		wait(NULL); 
#endif
}

static int run(char* cmd, int input, int first, int last, int double_pipe, int bg);
static int n = 0; /* number of calls to 'command' */


/* Process a command line */
static void process_input_line(char *line)
{
	int input = 0;
	int first = 1;
	int single = 1;
	int bg = 0;

	/* detect double pipe */
	char* cmd = line;
	/* FIXME: use '||' instead of '%' */
	char* next = strchr(cmd, '%'); /* Find '%' */
	if (next != NULL) {
		/* 'next' points to '%' */
		*next = '\0';
		input = run(cmd, input, first, 0, 1, 0);

		cmd = next + 1;
		first = 0;
		input = run(cmd, input, first, 1, 1, 0);
		cleanup(n);
		n = 0;
		return;
	}

	input = 0;
	first = 1;
	cmd = line;
	next = strchr(cmd, '|'); /* Find first '|' */

	while (next != NULL) {
		single = 0;
		/* 'next' points to '|' */
		*next = '\0';
		input = run(cmd, input, first, 0, 0, 0);

		cmd = next + 1;
		next = strchr(cmd, '|'); /* Find next '|' */
		first = 0;
	}

	if (!single) {
		input = run(cmd, input, first, 1, 0, 0);
		cleanup(n);
		n = 0;
		return;
	}

	/* see if it's a background command (cmd &) */
	next = strchr(cmd, '&');
	if (next != NULL) {
		bg = 1;
		/* 'next' points to '&' */
		*next = '\0';
	}

	input = run(cmd, input, first, 1, 0, bg);
	cleanup(n);
	n = 0;
}

static void process_app_input(struct app *app, uint8_t *line, int num_chars)
{
#ifdef ARCH_UMODE
	if (app && app->runtime_proc)
		syscall_read_from_shell_response(app->runtime_proc->id,
					 line, num_chars);
	else
		printf("%s: Error: couldn't send input to app\n", __func__);

	shell_status = SHELL_STATE_RUNNING_APP;
#endif
}

#define MAX_LINE_SIZE	MAILBOX_QUEUE_MSG_SIZE
static char line[MAX_LINE_SIZE];
static int num_chars = 0;

void shell_process_input(char buf)
{
	line[num_chars] = buf;
	output_printf("%c", buf);
	num_chars++;
	if (buf == '\n' || num_chars >= MAX_LINE_SIZE) {
		if (shell_status == SHELL_STATE_WAITING_FOR_CMD)
			process_input_line(line);
		else if (shell_status == SHELL_STATE_APP_WAITING_FOR_INPUT)
			process_app_input(foreground_app, (uint8_t *) line, num_chars);
		/* don't need to do anything if SHELL_STATE_RUNNING_APP */
		num_chars = 0;
	}
}

void inform_shell_of_termination(uint8_t runtime_proc_id)
{
#ifdef ARCH_UMODE
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
		printf("%s: Error: NULL runtime_proc or app\n", __func__);
		return;
	}

	if (runtime_proc->app == foreground_app) {
		shell_status = SHELL_STATE_WAITING_FOR_CMD;
		foreground_app = NULL;
		output_printf("octopos$> ");
	}
	sched_clean_up_app(runtime_proc_id);
#endif
}

void inform_shell_of_pause(uint8_t runtime_proc_id)
{
#ifdef ARCH_UMODE
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
		printf("%s: Error: NULL runtime_proc or app\n", __func__);
		return;
	}

	if (runtime_proc->app == foreground_app) {
		shell_status = SHELL_STATE_WAITING_FOR_CMD;
		foreground_app = NULL;
		output_printf("octopos$> ");
	}
	sched_pause_app(runtime_proc_id);
#endif
}

int app_write_to_shell(struct app *app, uint8_t *data, int size)
{
	if (app != foreground_app) {
		/* only the foreground app can write to shell */
		return -ERR_INVALID;
	}

	if (shell_status != SHELL_STATE_RUNNING_APP) {
		printf("Error: shell is not running an app\n");
		return ERR_INVALID;
	}

	if (size > MAILBOX_QUEUE_MSG_SIZE) {
		printf("Error: size of data to be written to shell is too large\n");
		return ERR_INVALID;
	}

	/* FIXME: don't use output_buf here. It's a char array. */
	memset(output_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);
	memcpy(output_buf, data, size);
	send_output((uint8_t *) output_buf);

	return 0;
}

int app_read_from_shell(struct app *app)
{
	if (app != foreground_app) {
		/* only the foreground app can read from shell */
		return -ERR_INVALID;
	}

	shell_status = SHELL_STATE_APP_WAITING_FOR_INPUT;
	
	return 0;
}

void initialize_shell(void)
{
	output_printf("octopos shell: Type 'exit' or send EOF to exit.\r\n");
	/* Print the command prompt */
	output_printf("octopos$> ");
}
 
static void split(char* cmd);
 
static int run(char* cmd, int input, int first, int last, int double_pipe, int bg)
{
	split(cmd);
	if (args[0] != NULL) {
		if (strcmp(args[0], "exit") == 0) 
			exit(0);
		n += 1;
		return command(input, first, last, double_pipe, bg);
	}
	return 0;
}
 
static char* skipwhite(char* s)
{
	while (isspace(*s)) ++s;
	return s;
}
 
static void split(char* cmd)
{
	cmd = skipwhite(cmd);
	char* next = strchr(cmd, ' ');
	int i = 0;
 
	while(next != NULL) {
		next[0] = '\0';
		args[i] = cmd;
		++i;
		cmd = skipwhite(next + 1);
		next = strchr(cmd, ' ');
	}
 
	if (cmd[0] != '\0') {
		args[i] = cmd;
		next = strchr(cmd, '\n');
		next[0] = '\0';
		++i; 
	}
 
	args[i] = NULL;
}

