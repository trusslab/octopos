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
/* FIXME: sock.h is only needed to satisfy the dependencies in other header files */
#include <network/sock.h>
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
int network_access_count = 0;

#ifdef CONFIG_UML
/* FIXME: move to a header file */
void runtime_recv_msg_from_queue_large(uint8_t *buf, uint8_t queue_id);
void runtime_send_msg_on_queue_large(uint8_t *buf, uint8_t queue_id);
#endif

static int send_msg_to_network(uint8_t *buf)
{
	runtime_send_msg_on_queue_large(buf, Q_NETWORK_DATA_IN);

	return 0;
}

void ip_send_out(struct pkbuf *pkb)
{
	int size = pkb->pk_len + sizeof(*pkb);
	printf("%s [1]: pkb->pk_len = %d\n", __func__, pkb->pk_len);
	NETWORK_SET_ZERO_ARGS_DATA(pkb, size)
	send_msg_to_network(buf);
}

uint8_t *ip_receive(uint8_t *buf, uint16_t *size)
{
	runtime_recv_msg_from_queue_large(buf, Q_NETWORK_DATA_OUT);
	*size = 0;
	NETWORK_GET_ZERO_ARGS_DATA
	*size = data_size;

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

int yield_network_access(void)
{
	if (!has_network_access) {
		printf("%s: Error: no network access to yield\n", __func__);
		return ERR_INVALID;
	}

	has_network_access = false;
	network_access_count = 0;

	net_stop_receive();

	wait_until_empty(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);

#ifdef ARCH_SEC_HW
	mailbox_yield_to_previous_owner(Q_NETWORK_DATA_IN);
	mailbox_yield_to_previous_owner(Q_NETWORK_DATA_OUT);
#else
	mailbox_change_queue_access(Q_NETWORK_DATA_IN, WRITE_ACCESS, P_OS);
	mailbox_change_queue_access(Q_NETWORK_DATA_OUT, READ_ACCESS, P_OS);
#endif
	
	return 0;
}

int request_network_access(int count)
{
	if (has_network_access) {
		printf("%s: Error: already has network access\n", __func__);
		return ERR_INVALID;
	}

	reset_queue_sync(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
	reset_queue_sync(Q_NETWORK_DATA_OUT, 0);

	SYSCALL_SET_ONE_ARG(SYSCALL_REQUEST_NETWORK_ACCESS, count)
	issue_syscall(buf);
	SYSCALL_GET_ONE_RET
	if (ret0)
		return (int) ret0;

	/* FIXME: if any of the attetations fail, we should yield the other one */
	int attest_ret = mailbox_attest_queue_access(Q_NETWORK_DATA_IN,
					WRITE_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest network write access\n", __func__);
		return ERR_FAULT;
	}

	attest_ret = mailbox_attest_queue_access(Q_NETWORK_DATA_OUT,
					READ_ACCESS, count);
	if (!attest_ret) {
		printf("%s: Error: failed to attest network read access\n", __func__);
		return ERR_FAULT;
	}

	int ret = net_start_receive();
	if (ret) {
		printf("Error: set_up_receive failed\n");
		wait_until_empty(Q_NETWORK_DATA_IN, MAILBOX_QUEUE_SIZE_LARGE);
		mailbox_change_queue_access(Q_NETWORK_DATA_IN, WRITE_ACCESS, P_OS);
		mailbox_change_queue_access(Q_NETWORK_DATA_OUT, READ_ACCESS, P_OS);
		return ERR_FAULT;
	}

	has_network_access = true;
	network_access_count = count;

	return 0;
}


