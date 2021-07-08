#include "arch/network/netif/octopos_pbuf.h"

struct octopos_pbuf *octopos_pbuf_alloc(unsigned short length)
{
	struct octopos_pbuf * p;
    p = (struct octopos_pbuf *)malloc(sizeof(struct octopos_pbuf));
	p->payload = malloc(length);
	p->len = length;
//	p->next = (void *)0;
	return p;
}
void octopos_pbuf_free(struct octopos_pbuf *p)
{
	free(p->payload);
	free(p);
}
