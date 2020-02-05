#include "netif.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"
//#include "raw.h"
//#include "udp.h"
/* FIXME: we only need this one for the definition of tcp_in */
#include "tcp.h"
#include "icmp.h"
#include "route.h"
#include "lib.h"

void ip_recv_local(struct pkbuf *pkb)
{
	printf("%s [1]\n", __func__);
	struct ip *iphdr = pkb2ip(pkb);
	printf("%s [2]\n", __func__);

	/* fragment reassambly */
	if (iphdr->ip_fragoff & (IP_FRAG_OFF | IP_FRAG_MF)) {
		printf("%s [3]\n", __func__);
		if (iphdr->ip_fragoff & IP_FRAG_DF) {
			ipdbg("error fragment");
			free_pkb(pkb);
			return;
		}
		pkb = ip_reass(pkb);
		if (!pkb)
			return;
		iphdr = pkb2ip(pkb);
	}
	printf("%s [4]\n", __func__);

	/* copy pkb to raw */
	/* FIXME */
	//raw_in(pkb);

	/* pass to upper-level */
	switch (iphdr->ip_pro) {
	case IP_P_ICMP:
		printf("%s [5]: ICMP\n", __func__);
		icmp_in(pkb);
		break;
	case IP_P_TCP:
		printf("%s [6]: TCP\n", __func__);
		/* FIXME */
		tcp_in(pkb);
		break;
	case IP_P_UDP:
		printf("%s [7]: UDP\n", __func__);
		/* FIXME */
		//udp_in(pkb);
		break;
	default:
		free_pkb(pkb);
		ipdbg("unknown protocol");
		break;
	}
	printf("%s [8]\n", __func__);
}

void ip_recv_route(struct pkbuf *pkb)
{
	printf("%s [1]\n", __func__);
	if (rt_input(pkb) < 0)
		return;
	/* Is this packet sent to us? */
	if (pkb->pk_rtdst->rt_flags & RT_LOCALHOST) {
		printf("%s [1]: our packet\n", __func__);
		ip_recv_local(pkb);
	} else {
		printf("%s [3]: forward packet\n", __func__);
		ip_hton(pkb2ip(pkb));
		ip_forward(pkb);
	}
	printf("%s [4]\n", __func__);
}

void ip_in(struct netdev *dev, struct pkbuf *pkb)
{
	struct ether *ehdr = (struct ether *)pkb->pk_data;
	struct ip *iphdr = (struct ip *)ehdr->eth_data;
	int hlen;
	printf("%s [1]\n", __func__);

	/* Fussy sanity check */
	if (pkb->pk_type == PKT_OTHERHOST) {
		ipdbg("ip(l2) packet is not for us");
		goto err_free_pkb;
	}

	if (pkb->pk_len < ETH_HRD_SZ + IP_HRD_SZ) {
		ipdbg("ip packet is too small");
		goto err_free_pkb;
	}

	if (ipver(iphdr) != IP_VERSION_4) {
		ipdbg("ip packet is not version 4");
		goto err_free_pkb;
	}

	hlen = iphlen(iphdr);
	if (hlen < IP_HRD_SZ) {
		ipdbg("ip header is too small");
		goto err_free_pkb;
	}

	if (ip_chksum((unsigned short *)iphdr, hlen) != 0) {
		ipdbg("ip checksum is error");
		goto err_free_pkb;
	}

	ip_ntoh(iphdr);
	if (iphdr->ip_len < hlen ||
		pkb->pk_len < ETH_HRD_SZ + iphdr->ip_len) {
		ipdbg("ip size is unknown");
		goto err_free_pkb;
	}

	if (pkb->pk_len > ETH_HRD_SZ + iphdr->ip_len)
		pkb_trim(pkb, ETH_HRD_SZ + iphdr->ip_len);

	/* Now, we can take care of the main ip processing safely. */
	ipdbg(IPFMT " -> " IPFMT "(%d/%d bytes)",
				ipfmt(iphdr->ip_src), ipfmt(iphdr->ip_dst),
				hlen, iphdr->ip_len);
	printf("%s [2]\n", __func__);
	ip_recv_route(pkb);
	printf("%s [3]\n", __func__);
	return;

err_free_pkb:
	free_pkb(pkb);
}

