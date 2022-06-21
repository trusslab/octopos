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
#include "arch/network/ethernet_hw_params.h"
#include "arch/network/netif/xaxiemacif.h"
#include "xllfifo_hw.h"
#include "xllfifo.h"
#include "arch/network/netif/octopos_pbuf.h"

struct xemac_s *xil_xemac;
struct xemac_s server_xemac;
u8_t mac_hwaddr[6];
u8_t mac_hwaddr_len = 6U;


struct netdev *xileth;
int hardware_ready = 0;
int xil_netif_initialized =0;

#define DEFAULT_IP_ADDRESS_HEX	0x0a00a8c0 // "192.168.0.10"
#define DEFAULT_IP_MASK_HEX		0x00ffffff // "255.255.255.0"





extern err_t octopos_xemac_init(struct xemac_s *xemac, unsigned char * mac_addr,  unsigned  mac_baseaddr);

int initialize_network_hardware(struct xemac_s *xemac)
{


	/* the mac address of the board. this should be unique per board */
	unsigned char mac_ethernet_address[] = {
			0x00, 0x0a, 0x35, 0x00, 0x22, 0x01 };
	int i;
	/* set mac address */
	for (i = 0; i < 6; i++){
		mac_hwaddr[i] = mac_ethernet_address[i];

	}
	if (octopos_xemac_init(xemac, mac_ethernet_address,
				PLATFORM_EMAC_BASEADDR)) {
		xil_printf("Error adding N/W interface\r\n");
		return -1;
	}


	printf("%s: success\r\n",__func__);
	return 0;
}

static void xileth_dev_exit(struct netdev *dev)
{
}

static int xileth_dev_init(struct netdev *dev)
{
	/* init tap: out network nic */
	/* init xileth: information for our netstack */
	if(hardware_ready){
		dev->net_mtu = 1500 - 14;
		dev->net_ipaddr = DEFAULT_IP_ADDRESS_HEX;
		dev->net_mask = DEFAULT_IP_MASK_HEX;
		hwacpy(dev->net_hwaddr, mac_hwaddr);
		dbg("%s ip address: " IPFMT, dev->net_name, ipfmt(dev->net_ipaddr));
		dbg("%s hw address: " MACFMT, dev->net_name, macfmt(dev->net_hwaddr));
	/* net stats have been zero */
	}
	return 0;
}

static int xileth_xmit(struct netdev *dev, struct pkbuf *pkb)
{
	int l;
//	struct xemac_s *xemac = (struct xemac_s *)(xil_netif->state);
	struct xemac_s *xemac = xil_xemac;
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
	if(xil_netif_initialized == 1){
		struct xemac_s *xemac = xil_xemac;
		struct octopos_pbuf *p;
		xaxiemacif_s *xaxiemacif = (xaxiemacif_s *)(xemac->state);

		if (pq_qlength(xaxiemacif->recv_q) == 0)
			return 0;
		p = (struct octopos_pbuf *)pq_dequeue(xaxiemacif->recv_q);
		l = p->len;
		pkb->pk_len = l;
		memcpy(pkb->pk_data, p->payload, l);
		octopos_pbuf_free(p);
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
	}else{
		return 0;
	}

}

static void xileth_rx(void)
{
	// struct pkbuf *pkb = alloc_netdev_pkb(xileth);
	struct pkbuf *pkb = alloc_fixed_netdev_pkb(xileth);
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
	xil_xemac = &server_xemac;
	xileth = netdev_alloc("xileth", &xileth_ops);
	initialize_network_hardware(xil_xemac);
	hardware_ready = 1;
	xileth_dev_init(xileth);
	xil_netif_initialized = 1;

}

void xileth_exit(void)
{
	netdev_free(xileth);
}
#endif
