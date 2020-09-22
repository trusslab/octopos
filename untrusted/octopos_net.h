#ifndef _OCTOPOS_NET_H_
#define _OCTOPOS_NET_H_
/* FIXME */
#define CONFIG_OCTOPOS
int octopos_open_socket(__be32 daddr, __be32 saddr, __be16 dport, __be16 sport);
void octopos_close_socket_atomic(struct sock *sk);
#endif
