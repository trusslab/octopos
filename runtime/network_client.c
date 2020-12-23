/* octopos network client */
#ifndef CONFIG_UML /* Linux UML */
#include <arch/defines.h>

#include <stdio.h>
#include <string.h>
#ifdef ARCH_UMODE
#include <fcntl.h>
#endif
#include <unistd.h>
#include <stdint.h>

#ifdef ARCH_UMODE
#include <dlfcn.h>
#endif

#include <stdlib.h>
#include <runtime/runtime.h>
#include <runtime/network_client.h>
#else /* CONFIG_UML */
#define UNTRUSTED_DOMAIN
#include <linux/module.h>
#include <octopos/runtime/runtime.h>
#include "network_client.h"
#endif /* CONFIG_UML */
#include <octopos/mailbox.h>
#include <octopos/syscall.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/error.h>
#ifndef UNTRUSTED_DOMAIN
#include <arch/mailbox_runtime.h> 
#endif

#ifdef UNTRUSTED_DOMAIN
#define printf printk
#endif

bool has_network_access = false;
/* deprecate? */
int network_access_count = 0;

#ifndef UNTRUSTED_DOMAIN
/* FIXME: conslidate with the callback system of the untrusted domain. */
extern limit_t queue_limits[];
extern timeout_t queue_timeouts[];
extern queue_update_callback_t queue_update_callbacks[];
#endif

#ifdef CONFIG_UML
/* FIXME: move to a header file */
void runtime_recv_msg_from_queue_large(uint8_t *buf, uint8_t queue_id);
void runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id);
#endif

#ifndef ARCH_SEC_HW
// TODO: missing pkbuf definition
void ip_send_out(struct pkbuf *pkb)
{
	int size = pkb->pk_len + sizeof(*pkb);
	NETWORK_SET_ZERO_ARGS_DATA(pkb, size)
	runtime_send_msg_on_queue_large(buf, Q_NETWORK_DATA_IN);

#ifndef UNTRUSTED_DOMAIN
	report_queue_usage(Q_NETWORK_DATA_IN);
#endif
}
#endif

uint8_t *ip_receive(uint8_t *buf, uint16_t *size)
{
	runtime_recv_msg_from_queue_large(buf, Q_NETWORK_DATA_OUT);
	*size = 0;
	NETWORK_GET_ZERO_ARGS_DATA
	*size = data_size;

#ifndef UNTRUSTED_DOMAIN
	report_queue_usage(Q_NETWORK_DATA_OUT);
#endif

	return data;
}

int syscall_allocate_tcp_socket(unsigned int *saddr, unsigned short *sport,
		unsigned int daddr, unsigned short dport)
{
	SYSCALL_SET_FOUR_ARGS(SYSCALL_ALLOCATE_SOCKET, (uint32_t) TCP_SOCKET,
			(uint32_t) *sport, (uint32_t) daddr, (uint32_t) dport)
	issue_syscall(buf);
	SYSCALL_GET_TWO_RETS

	if (!ret0 && !ret1)
		return ERR_FAULT;

	*saddr = ret0;
	*sport = ret1;

	return 0;
}

#ifndef UNTRUSTED_DOMAIN
void reset_network_queues_tracker(void)
{
	/* FIXME: redundant when called from yield_network_access() */
	has_network_access = false;
	network_access_count = 0;

	queue_limits[Q_NETWORK_DATA_IN] = 0;
	queue_timeouts[Q_NETWORK_DATA_IN] = 0;
	queue_update_callbacks[Q_NETWORK_DATA_IN] = NULL;

	queue_limits[Q_NETWORK_DATA_OUT] = 0;
	queue_timeouts[Q_NETWORK_DATA_OUT] = 0;
	queue_update_callbacks[Q_NETWORK_DATA_OUT] = NULL;
}
#endif

int yield_network_access(void)
{
	if (!has_network_access) {
		printf("%s: Error: no network access to yield\n", __func__);
		return ERR_INVALID;
	}

	has_network_access = false;
	network_access_count = 0;

	net_stop_receive();

	/* FIXME: we should have a bounded wait here in case the network service
	 * does not read all messages off the queue.
	 * Yielding the queue resets the queues therefore there is no concern
	 * about the leaking of the leftover messages.
	 */
	wait_until_empty(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

	mailbox_yield_to_previous_owner(Q_NETWORK_DATA_IN);
	mailbox_yield_to_previous_owner(Q_NETWORK_DATA_OUT);

#ifndef UNTRUSTED_DOMAIN
	reset_network_queues_tracker();
#endif
	
	return 0;
}

/*
 * @expected_pcr: if not NULL, we request the PCR val for the network service
 * and compare it with expected_pcr.
 * @return_pcr: if expected_pcr is NULL but return_pcr is not, we'll request
 * and return the PCR val for the network service. This is useful because the
 * app might not have the expected value when it first asks for network access.
 * It can get the measured value here and compare it with the expected value
 * later.
 *
 * FIXME: @callback, @expected_pcr, and @return_pcr can be set by the UNTRUSTED_DOMAIN
 * domain, but they're no ops.
 */
int request_network_access(limit_t limit, timeout_t timeout,
			   queue_update_callback_t callback,
			   uint8_t *expected_pcr, uint8_t *return_pcr)
{
	int ret;

	if (has_network_access) {
		printf("%s: Error: already has network access\n", __func__);
		return ERR_INVALID;
	}

	reset_queue_sync(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
	reset_queue_sync(Q_NETWORK_DATA_OUT, 0);

	SYSCALL_SET_TWO_ARGS(SYSCALL_REQUEST_NETWORK_ACCESS, (uint32_t) limit,
			     (uint32_t) timeout)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	ret = mailbox_attest_queue_access(Q_NETWORK_DATA_IN, limit, timeout);
	if (!ret) {
		printf("%s: Error: failed to attest network write access\n",
		       __func__);
		return ERR_FAULT;
	}

	ret = mailbox_attest_queue_access(Q_NETWORK_DATA_OUT, limit, timeout);
	if (!ret) {
		printf("%s: Error: failed to attest network read access\n",
		       __func__);
		wait_until_empty(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
		mailbox_yield_to_previous_owner(Q_NETWORK_DATA_IN);
		return ERR_FAULT;
	}

#ifndef UNTRUSTED_DOMAIN
	/* Note: we set the limit/timeout values right after attestation and
	 * before we call check_proc_pcr() or read_tpm_pcr_for_proc().
	 * This is because those calls issue syscalls, which might take
	 * arbitrary amounts of time.
	 */
	queue_limits[Q_NETWORK_DATA_IN] = limit;
	queue_timeouts[Q_NETWORK_DATA_IN] = timeout;

	queue_limits[Q_NETWORK_DATA_OUT] = limit;
	queue_timeouts[Q_NETWORK_DATA_OUT] = timeout;

	if (expected_pcr) {
		ret = check_proc_pcr(P_NETWORK, expected_pcr);
		if (ret) {
			/* FIXME: the next three error blocks are identical. */
			printf("%s: Error: unexpected PCR\n", __func__);
			wait_until_empty(Q_NETWORK_DATA_IN,
					 MAILBOX_QUEUE_SIZE_LARGE);
			mailbox_yield_to_previous_owner(Q_NETWORK_DATA_IN);
			mailbox_yield_to_previous_owner(Q_NETWORK_DATA_OUT);

			queue_limits[Q_NETWORK_DATA_IN] = 0;
			queue_timeouts[Q_NETWORK_DATA_IN] = 0;
			queue_limits[Q_NETWORK_DATA_OUT] = 0;
			queue_timeouts[Q_NETWORK_DATA_OUT] = 0;
			return ERR_UNEXPECTED;
		}
	} else if (return_pcr) {
		ret = read_tpm_pcr_for_proc(P_NETWORK, return_pcr);
		if (ret) {
			printf("%s: Error: couldn't read PCR\n", __func__);
			wait_until_empty(Q_NETWORK_DATA_IN,
					 MAILBOX_QUEUE_SIZE_LARGE);
			mailbox_yield_to_previous_owner(Q_NETWORK_DATA_IN);
			mailbox_yield_to_previous_owner(Q_NETWORK_DATA_OUT);

			queue_limits[Q_NETWORK_DATA_IN] = 0;
			queue_timeouts[Q_NETWORK_DATA_IN] = 0;
			queue_limits[Q_NETWORK_DATA_OUT] = 0;
			queue_timeouts[Q_NETWORK_DATA_OUT] = 0;
			return ERR_FAULT;
		}
	}
#endif

	ret = net_start_receive();
	if (ret) {
		printf("Error: set_up_receive failed\n");
			wait_until_empty(Q_NETWORK_DATA_IN,
					 MAILBOX_QUEUE_SIZE_LARGE);
			mailbox_yield_to_previous_owner(Q_NETWORK_DATA_IN);
			mailbox_yield_to_previous_owner(Q_NETWORK_DATA_OUT);

#ifndef UNTRUSTED_DOMAIN
			queue_limits[Q_NETWORK_DATA_IN] = 0;
			queue_timeouts[Q_NETWORK_DATA_IN] = 0;
			queue_limits[Q_NETWORK_DATA_OUT] = 0;
			queue_timeouts[Q_NETWORK_DATA_OUT] = 0;
#endif
		return ERR_FAULT;
	}

#ifndef UNTRUSTED_DOMAIN
	queue_update_callbacks[Q_NETWORK_DATA_IN] = callback;
	queue_update_callbacks[Q_NETWORK_DATA_OUT] = callback;
#endif

	has_network_access = true;
	network_access_count = limit;

	return 0;
}

void syscall_close_socket(void)
{
	SYSCALL_SET_ZERO_ARGS(SYSCALL_CLOSE_SOCKET)
	issue_syscall(buf);
}
