#ifdef ARCH_SEC_HW_NETWORK
#ifndef OCTOPOS_HDR_PBUF_H
#define OCTOPOS_HDR_PBUF_H

/* Main packet buffer struct */
struct octopos_pbuf {
	/* pointer to the actual data in the buffer */
//	struct octopos_pbuf *next;
	void *payload;
	unsigned short len;
};

struct octopos_pbuf *octopos_pbuf_alloc(unsigned short length);
void octopos_pbuf_free(struct octopos_pbuf *p);

#endif
#endif /* ARCH_SEC_HW_NETWORK */
