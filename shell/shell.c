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
 
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define OCTOPOS_SHELL	1

/* The array below will hold the arguments: args[0] is the command. */
static char* args[512];
pid_t pid;
int command_pipe[2];
 
#define READ  0
#define WRITE 1

#ifdef OCTOPOS_SHELL
/*
 * Communications to keyboard and serial output
 */
char output_fifo[64] = "/tmp/octopos_mailbox_shell_out";
int output_fd;

#define OUTPUT_CHANNEL_MSG_SIZE	256
#define channel_printf(fmt, args...); sprintf(output_buf, fmt, ##args); send_output(output_buf);

char output_buf[OUTPUT_CHANNEL_MSG_SIZE];

char input_fifo[64] = "/tmp/octopos_mailbox_shell_in";
int input_fd;

#define INPUT_CHANNEL_MSG_SIZE	1

char input_buf[INPUT_CHANNEL_MSG_SIZE];

static int intialize_output_channel(void)
{
	mkfifo(output_fifo, 0666);
	output_fd = open(output_fifo, O_WRONLY);

	return 0;
}

static void close_output_channel(void)
{
	close(output_fd);
}

static int intialize_input_channel(void)
{
	mkfifo(input_fifo, 0666);
	input_fd = open(input_fifo, O_RDONLY);

	return 0;
}

static void close_input_channel(void)
{
	close(input_fd);
}

static int send_output(char *buf)
{
	return write(output_fd, buf, OUTPUT_CHANNEL_MSG_SIZE);
}

static int recv_input(char *buf)
{
	return read(input_fd, buf, INPUT_CHANNEL_MSG_SIZE);
}

static int channel_read_line(char *line, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		memset(input_buf, 0x0, INPUT_CHANNEL_MSG_SIZE);
		recv_input(input_buf);
		line[i] = input_buf[0]; /* only support INPUT_CHANNEL_MSG_SIZE of 1 */
		channel_printf("%c", input_buf[0]);
		if (input_buf[0] == '\n')
			break;
	}

	return i;
}	
#endif /* OCTOPOS_SHELL */

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
static int command(int input, int first, int last)
{
	int pipettes[2];
 
	/* Invoke pipe */
	pipe( pipettes );	
	pid = fork();
 
	/*
	 SCHEME:
	 	STDIN --> O --> O --> O --> STDOUT
	*/
 
	if (pid == 0) {
		if (first == 1 && last == 0 && input == 0) {
			// First command
			dup2( pipettes[WRITE], STDOUT_FILENO );
		} else if (first == 0 && last == 0 && input != 0) {
			// Middle command
			dup2(input, STDIN_FILENO);
			dup2(pipettes[WRITE], STDOUT_FILENO);
		} else {
			// Last command
			dup2( input, STDIN_FILENO );
			//Ardalan
#ifdef OCTOPOS_SHELL
			dup2(pipettes[WRITE], STDOUT_FILENO);
#endif /* OCTOPOS_SHELL */
		}
 
		if (execvp( args[0], args) == -1) {
#ifdef OCTOPOS_SHELL
			/* FIXME: we should not use the output_buf here. */
			sprintf(output_buf, "Error: Failed to execute %s\n", args[0]);
			write(pipettes[WRITE], output_buf, OUTPUT_CHANNEL_MSG_SIZE); 
#endif /* OCTOPOS_SHELL */
			_exit(EXIT_FAILURE); // If child fails
		}
	}

#ifdef OCTOPOS_SHELL
	if (pid > 0 && last == 1) {
		memset(output_buf, 0x0, OUTPUT_CHANNEL_MSG_SIZE);
		read(pipettes[READ], output_buf, OUTPUT_CHANNEL_MSG_SIZE);
		send_output(output_buf);
	}
#endif /* OCTOPOS_SHELL */

	if (input != 0) 
		close(input);
 
	// Nothing more needs to be written
	close(pipettes[WRITE]);
 
	// If it's the last command, nothing more needs to be read
	if (last == 1) {
		close(pipettes[READ]);
	}
 
	return pipettes[READ];
}
 
/* Final cleanup, 'wait' for processes to terminate.
 *  n : Number of times 'command' was invoked.
 */
static void cleanup(int n)
{
	int i;
	for (i = 0; i < n; ++i) 
		wait(NULL); 
}
 
static int run(char* cmd, int input, int first, int last);
static char line[1024];
static int n = 0; /* number of calls to 'command' */

int main()
{
#ifdef OCTOPOS_SHELL
	intialize_input_channel();
	intialize_output_channel();

	channel_printf("SIMPLE SHELL: Type 'exit' or send EOF to exit.\n");
#else /* OCTOPOS_SHELL */
	printf("SIMPLE SHELL: Type 'exit' or send EOF to exit.\n");
#endif /* OCTOPOS_SHELL */
	while (1) {
		/* Print the command prompt */
#ifdef OCTOPOS_SHELL
		channel_printf("octopos$> ");
#else /* OCTOPOS_SHELL */
		printf("$> ");
#endif /* OCTOPOS_SHELL */
		fflush(NULL);
 
		/* Read a command line */
#ifdef OCTOPOS_SHELL
		if (!channel_read_line(line, 1024)) 
#else /* OCTOPOS_SHELL */
		if (!fgets(line, 1024, stdin)) 
#endif /* OCTOPOS_SHELL */
			return 0;
 
		int input = 0;
		int first = 1;
 
		char* cmd = line;
		char* next = strchr(cmd, '|'); /* Find first '|' */
 
		while (next != NULL) {
			/* 'next' points to '|' */
			*next = '\0';
			input = run(cmd, input, first, 0);
 
			cmd = next + 1;
			next = strchr(cmd, '|'); /* Find next '|' */
			first = 0;
		}
		input = run(cmd, input, first, 1);
		cleanup(n);
		n = 0;
	}

#ifdef OCTOPOS_SHELL
	close_output_channel();
	close_input_channel();
#endif /* OCTOPOS_SHELL */
	return 0;
}
 
static void split(char* cmd);
 
static int run(char* cmd, int input, int first, int last)
{
	split(cmd);
	if (args[0] != NULL) {
		if (strcmp(args[0], "exit") == 0) 
			exit(0);
		n += 1;
		return command(input, first, last);
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
