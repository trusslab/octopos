/* OctopOS shell
 * Forked from https://gist.github.com/966049.git
 */

/*
 * Based on https://xilinx-wiki.atlassian.net/wiki/spaces/A/pages/18841941/Zynq+UltraScale+MPSoC+-+IPI+Messaging+Example
 */

/******************************************************************************
 * Copyright (C) 2017 Xilinx, Inc.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * Use of the Software is limited solely to applications:
 * (a) running on a Xilinx device, or
 * (b) that interact with a Xilinx device through a bus or interconnect.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * XILINX  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
 * OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Except as contained in this notice, the name of the Xilinx shall not be used
 * in advertising or otherwise to promote the sale, use or other dealings in
 * this Software without prior written authorization from Xilinx.
 ******************************************************************************/

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

#include "xscugic.h"
#include "xttcps.h"
#include "xipipsu.h"

/* The array below will hold the arguments: args[0] is the command. */
static char* args[512];
pid_t pid;
int command_pipe[2];
 
#define READ  0
#define WRITE 1

#define SHELL_STATE_WAITING_FOR_CMD		0
#define SHELL_STATE_RUNNING_APP			1
#define SHELL_STATE_APP_WAITING_FOR_INPUT	2

#ifdef 	ARCH_SEC_HW_OS
extern 	XIpiPsu 				ipi_pmu_inst;

#define RESP_AND_MSG_NUM_OFFSET	0x1U
#define IPI_HEADER_OFFSET		0x0U
#define IPI_HEADER				0x1E0000 /* 1E - Target Module ID */
#endif

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
	if (app && app->runtime_proc)
		syscall_read_from_shell_response(app->runtime_proc->id,
					 line, num_chars);
	else
		printf("%s: Error: couldn't send input to app\n", __func__);

	shell_status = SHELL_STATE_RUNNING_APP;
}

#define MAX_LINE_SIZE	MAILBOX_QUEUE_MSG_SIZE
static char line[MAX_LINE_SIZE];
static int num_chars = 0;

void shell_process_input(char buf)
{
	line[num_chars] = buf;
	output_printf("%c", buf);
	num_chars++;
#ifdef ARCH_SEC_HW
	if (buf == '\r' || num_chars >= MAX_LINE_SIZE) {
#else
	if (buf == '\n' || num_chars >= MAX_LINE_SIZE) {
#endif
		if (shell_status == SHELL_STATE_WAITING_FOR_CMD)
			process_input_line(line);
		else if (shell_status == SHELL_STATE_APP_WAITING_FOR_INPUT)
			process_app_input(foreground_app, (uint8_t *) line, num_chars);
		/* don't need to do anything if SHELL_STATE_RUNNING_APP */
		num_chars = 0;
	}
}



// DEBUG ONLY
u32 octopos_mailbox_get_status_reg(UINTPTR base);

void inform_shell_of_termination(uint8_t runtime_proc_id)
{
	_SEC_HW_DEBUG("runtime_proc_id=%d", runtime_proc_id);
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
#ifdef ARCH_SEC_HW
		_SEC_HW_ERROR("NULL runtime_proc or app", __func__);
#else
		printf("%s: Error: NULL runtime_proc or app\n", __func__);
#endif
		return;
	}

	// DEBUG ONLY
    _SEC_HW_ERROR("queue %d: ctrl reg content %08x", Q_SERIAL_OUT, octopos_mailbox_get_status_reg(125U));

	if (runtime_proc->app == foreground_app) {
		shell_status = SHELL_STATE_WAITING_FOR_CMD;
		foreground_app = NULL;
		output_printf("octopos$> ");
	}
	sched_clean_up_app(runtime_proc_id);

	/* Send IPI to PMU, PMU will reset the runtime */
	u32 pmu_ipi_status = XST_FAILURE;

    static u32 MsgPtr[2] = {IPI_HEADER, 0U};
    MsgPtr[RESP_AND_MSG_NUM_OFFSET] += 1;
    pmu_ipi_status = XIpiPsu_WriteMessage(&ipi_pmu_inst, XPAR_XIPIPS_TARGET_PSU_PMU_0_CH0_MASK,
			MsgPtr, 2U, XIPIPSU_BUF_TYPE_MSG);

	if(pmu_ipi_status != (u32)XST_SUCCESS) {
		_SEC_HW_ERROR("RPU: IPI Write message failed");
		return;
	}

	pmu_ipi_status = XIpiPsu_TriggerIpi(&ipi_pmu_inst, XPAR_XIPIPS_TARGET_PSU_PMU_0_CH0_MASK);

	if(pmu_ipi_status != (u32)XST_SUCCESS) {
		_SEC_HW_ERROR("RPU: IPI Trigger failed");
		return;
	}

	pmu_ipi_status = XIpiPsu_PollForAck(&ipi_pmu_inst, XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK, (~0));

	if(pmu_ipi_status != (u32)XST_SUCCESS) {
		_SEC_HW_ERROR("RPU: IPI Poll for ack failed");
		return;
	}
}

void inform_shell_of_pause(uint8_t runtime_proc_id)
{
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

