/* OctopOS network code for the OS */
#include <arch/defines.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <octopos/mailbox.h>
#include <octopos/storage.h>
#include <octopos/syscall.h>
#include <octopos/error.h>
#include <os/scheduler.h>
#include <os/network.h>
#include <arch/mailbox_os.h>

#ifdef ARCH_UMODE
static int network_set_up_socket(uint32_t saddr, uint32_t sport,
				 uint32_t daddr, uint32_t dport)
{
	NETWORK_SET_FOUR_ARGS(saddr, sport, daddr, dport)
	send_cmd_to_network(buf);
	NETWORK_GET_ONE_RET

	return (int) ret0;
}


static int get_network_src_addr(uint32_t *saddr)
{
	/* FIXME: hard-coded */
	*saddr = 0x0100000a;

	return 0;
}

static int get_unused_tcp_port(uint32_t *sport)
{
	/* FIXME: hard-coded */
	*sport = 128;

	return 0;
}
#endif

void handle_allocate_socket_syscall(uint8_t runtime_proc_id,
				    uint8_t *buf)
{
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
		SYSCALL_SET_TWO_RETS((uint32_t) 0, (uint32_t) 0)
		return;
	}
	struct app *app = runtime_proc->app;

	SYSCALL_GET_FOUR_ARGS
	uint32_t protocol = arg0;
	uint32_t requested_port = arg1;
	uint32_t daddr = arg2;
	uint32_t dport = arg3;

	if (protocol != TCP_SOCKET) {
		SYSCALL_SET_TWO_RETS((uint32_t) 0, (uint32_t) 0)
		return;
	}

	if (app->socket_created) {
		printf("%s: Error: only support one socket per app (for now)\n", __func__);
		SYSCALL_SET_TWO_RETS((uint32_t) 0, (uint32_t) 0)
		return;
	}

	/* FIXME: hard-coded */
	uint32_t saddr, sport;
	int ret = get_network_src_addr(&saddr);
	if (ret) {
		SYSCALL_SET_TWO_RETS((uint32_t) 0, (uint32_t) 0)
		return;
	}

	if (requested_port) {
		/* FIXME: check to see if port is available */
		sport = requested_port;
		ret = 0;
	} else {
		ret = get_unused_tcp_port(&sport);
	}

	if (ret) {
		SYSCALL_SET_TWO_RETS((uint32_t) 0, (uint32_t) 0)
		return;
	}

	app->socket_saddr = saddr;
	app->socket_sport = sport;
	app->socket_daddr = daddr;
	app->socket_dport = dport;
	app->socket_created = true;

	SYSCALL_SET_TWO_RETS(saddr, sport)
}

void handle_request_network_access_syscall(uint8_t runtime_proc_id,
					   uint8_t *buf)
{
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
		return;
	}

	struct app *app = runtime_proc->app;
	if (!app->socket_created) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		return;
	}

	SYSCALL_GET_ONE_ARG
	uint32_t count = arg0;

	/* No more than 200 block reads/writes */
	/* FIXME: hard-coded */
	if (count > 200) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		return;
	}

	int ret_in = is_queue_available(Q_NETWORK_DATA_IN);
	int ret_out = is_queue_available(Q_NETWORK_DATA_OUT);
	/* Or should we make this blocking? */
	if (!ret_in || !ret_out) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_AVAILABLE)
		return;
	}

	wait_until_empty(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

	int ret = network_set_up_socket(app->socket_saddr, app->socket_sport,
					app->socket_daddr, app->socket_dport);
	if (ret) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
		return;
	}

	mark_queue_unavailable(Q_NETWORK_DATA_IN);
	mark_queue_unavailable(Q_NETWORK_DATA_OUT);

#ifdef ARCH_SEC_HW
	mailbox_change_queue_access(Q_NETWORK_DATA_IN, WRITE_ACCESS, runtime_proc_id, (uint16_t) count);
	mailbox_change_queue_access(Q_NETWORK_DATA_OUT, READ_ACCESS, runtime_proc_id, (uint16_t) count);
#else
	mailbox_change_queue_access(Q_NETWORK_DATA_IN, WRITE_ACCESS, runtime_proc_id, (uint8_t) count);
	mailbox_change_queue_access(Q_NETWORK_DATA_OUT, READ_ACCESS, runtime_proc_id, (uint8_t) count);
#endif

	SYSCALL_SET_ONE_RET((uint32_t) 0)
}

void handle_close_socket_syscall(uint8_t runtime_proc_id,
				 uint8_t *buf)
{
	struct runtime_proc *runtime_proc = get_runtime_proc(runtime_proc_id);
	if (!runtime_proc || !runtime_proc->app) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_FAULT)
		return;
	}

	struct app *app = runtime_proc->app;
	if (!app->socket_created) {
		SYSCALL_SET_ONE_RET((uint32_t) ERR_INVALID)
		return;
	}

	app->socket_created = false;
	app->socket_saddr = 0;
	app->socket_sport = 0;
	app->socket_daddr = 0;
	app->socket_dport = 0;

	SYSCALL_SET_ONE_RET((uint32_t) 0)
}