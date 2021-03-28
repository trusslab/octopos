#ifdef ARCH_SEC_HW_NETWORK

/*
 *  Lowest net device code:
 *    virtual net device driver based on tap device
 */
//#include "netif.h"
#include <network/ether.h>
#include <network/ip.h>
#include <network/lib.h>
#include <network/list.h>
#include <network/netcfg.h>
#include <network/arp.h>

//#include "tap.h"

#include "netif/xadapter.h"
#include "netif/xaxiemacif.h"
#include "xllfifo_hw.h"
#include "xllfifo.h"

extern int initialize_network_hardware(struct netif *);
struct netif *xil_netif;
struct netif server_netif;

struct netdev *xileth;
int hardware_ready = 0;


static void xileth_dev_exit(struct netdev *dev)
{
}

static int xileth_dev_init(struct netdev *dev)
{
	/* init tap: out network nic */
	/* init xileth: information for our netstack */
	if(hardware_ready){
		dev->net_mtu = xil_netif->mtu;
		dev->net_ipaddr = xil_netif->ip_addr.addr;
		dev->net_mask = xil_netif->netmask.addr;
		hwacpy(dev->net_hwaddr, xil_netif->hwaddr);
		dbg("%s ip address: " IPFMT, dev->net_name, ipfmt(dev->net_ipaddr));
		dbg("%s hw address: " MACFMT, dev->net_name, macfmt(dev->net_hwaddr));
	/* net stats have been zero */
	}
	return 0;
}

static int xileth_xmit(struct netdev *dev, struct pkbuf *pkb)
{
	int l;
	struct xemac_s *xemac = (struct xemac_s *)(xil_netif->state);
	xaxiemacif_s *xaxiemacif = (xaxiemacif_s *)(xemac->state);
	XLlFifo *llfifo = &xaxiemacif->axififo;
	//l = write(tap->fd, pkb->pk_data, pkb->pk_len);
	l= pkb->pk_len;
	XLlFifo_Write(llfifo, pkb->pk_data, l);
	XLlFifo_TxSetLen(llfifo, l);
	if (l != pkb->pk_len) {
		devdbg("write net dev");
		dev->net_stats.tx_errors++;
	} else {
		dev->net_stats.tx_packets++;
		dev->net_stats.tx_bytes += l;
		devdbg("write net dev size: %d\n", l);
	}
	return l;
}

static struct netdev_ops xileth_ops = {
	.init = xileth_dev_init,
	.xmit = xileth_xmit,
	.exit = xileth_dev_exit,
};

static int xileth_recv(struct pkbuf *pkb)
{
	int l;
	struct xemac_s *xemac = (struct xemac_s *)(xil_netif->state);
	struct pbuf *p;
	xaxiemacif_s *xaxiemacif = (xaxiemacif_s *)(xemac->state);
//	printf("%s: [0] %d\n\r",__func__,pq_qlength(xaxiemacif->recv_q));
	if (pq_qlength(xaxiemacif->recv_q) == 0)
		return 0;
	printf("%s: [1] something on the queue \n\r",__func__);
	p = (struct pbuf *)pq_dequeue(xaxiemacif->recv_q);
	l = p->tot_len;
	pkb->pk_len = l;
	memcpy(pkb->pk_data, p->payload, l);
	free(p->payload);
	free(p);
	//l = read(tap->fd, pkb->pk_data, pkb->pk_len);
	if (l <= 0) {
		devdbg("read net dev");
		xileth->net_stats.rx_errors++;
	} else {
		devdbg("read net dev size: %d\n", l);
		xileth->net_stats.rx_packets++;
		xileth->net_stats.rx_bytes += l;
		pkb->pk_len = l;
	}
	return l;
}

static void xileth_rx(void)
{
	struct pkbuf *pkb = alloc_netdev_pkb(xileth);
	if (xileth_recv(pkb) > 0)
		net_in(xileth, pkb);	/* pass to upper */
	else
		free_pkb(pkb);
}

void xileth_poll(void)
{
	xileth_rx();
}

void xileth_init(void)
{
	xil_netif = &server_netif;
	xileth = netdev_alloc("xileth", &xileth_ops);
	initialize_network_hardware(xil_netif);
	hardware_ready = 1;
	xileth_dev_init(xileth);

}

void xileth_exit(void)
{
	netdev_free(xileth);
}
#endif
