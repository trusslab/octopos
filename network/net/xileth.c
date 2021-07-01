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
#include "arch/ethernet_hw_params.h"

//#include "tap.h"

#include "netif/xadapter.h"
#include "netif/xaxiemacif.h"
#include "xllfifo_hw.h"
#include "xllfifo.h"
#include "lwip/inet.h"

//extern int initialize_network_hardware(struct netif *);
struct netif *xil_netif;
struct netif server_netif;

struct netdev *xileth;
int hardware_ready = 0;
int xil_netif_initialized =0;

#define DEFAULT_IP_ADDRESS_HEX	0x0a01a8c0 // "192.168.1.10"
#define DEFAULT_IP_MASK_HEX		0x00ffffff // "255.255.255.0"


#ifdef MJMJ
#define DEFAULT_IP_ADDRESS	"192.168.1.10"
#define DEFAULT_IP_MASK		"255.255.255.0"
#define DEFAULT_GW_ADDRESS	"192.168.1.1"



static void assign_default_ip(ip_addr_t *ip, ip_addr_t *mask, ip_addr_t *gw)
{
	int err;

	xil_printf("Configuring default IP %s \r\n", DEFAULT_IP_ADDRESS);

	err = inet_aton(DEFAULT_IP_ADDRESS, ip);
	printf("ip = %x\r\n", ip->addr);
	if (!err)
		xil_printf("Invalid default IP address: %d\r\n", err);

	err = inet_aton(DEFAULT_IP_MASK, mask);
	printf("mask = %x\r\n", mask->addr);
	if (!err)
		xil_printf("Invalid default IP MASK: %d\r\n", err);

	err = inet_aton(DEFAULT_GW_ADDRESS, gw);
	printf("gw = %x\r\n", gw->addr);
	if (!err)
		xil_printf("Invalid default gateway address: %d\r\n", err);
}
#endif

err_t
ethernet_input(struct pbuf *p, struct netif *netif)
{
	  return ERR_OK;
}

/*
 * xemac_add: this is a function to add xaxiemacif interface
 */
struct netif *
xemac_add(struct netif *netif,
	ip_addr_t *ipaddr, ip_addr_t *netmask, ip_addr_t *gw,
	unsigned char *mac_ethernet_address,
	unsigned mac_baseaddr)
{
	int i;
	/* set mac address */
	netif->hwaddr_len = 6;
	for (i = 0; i < 6; i++)
		netif->hwaddr[i] = mac_ethernet_address[i];

    netif->mtu = 0;
	netif->flags = 0;
	/* remember netif specific state information data */
	netif->state = (void*)(UINTPTR)mac_baseaddr;
	netif->num = 1;
	netif->input = ethernet_input;
	if (xaxiemacif_init(netif) != ERR_OK) {
	  return NULL;
	}
	return netif;
}



int initialize_network_hardware(struct netif *netif)
{


	/* the mac address of the board. this should be unique per board */
	printf("%s: mj[0]\r\n",__func__);
	unsigned char mac_ethernet_address[] = {
		0x00, 0x0a, 0x35, 0x00, 0x01, 0x02 };
	if (!xemac_add(netif, NULL, NULL, NULL, mac_ethernet_address,
				PLATFORM_EMAC_BASEADDR)) {
		xil_printf("Error adding N/W interface\r\n");
		return -1;
	}
	printf("%s: mj[1]\r\n",__func__);
//	netif_set_default(netif);
//	netif_set_up(netif);
//	printf("%s: mj[2]\r\n",__func__);
//	assign_default_ip(&(netif->ip_addr), &(netif->netmask), &(netif->gw));
//	print_ip_settings(&(netif->ip_addr), &(netif->netmask), &(netif->gw));
	xil_printf("\r\n");

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
		dev->net_mtu = xil_netif->mtu;
		dev->net_ipaddr = DEFAULT_IP_ADDRESS_HEX;
		dev->net_mask = DEFAULT_IP_MASK_HEX;
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
	printf("%s: mj[0]\r\n",__func__);
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
		struct xemac_s *xemac = (struct xemac_s *)(xil_netif->state);
		struct pbuf *p;
	//	printf("%s: xemac=%p\r\n",xemac);
		xaxiemacif_s *xaxiemacif = (xaxiemacif_s *)(xemac->state);

//		printf("%s: [0] %d\n\r",__func__,pq_qlength(xaxiemacif->recv_q));
		if (pq_qlength(xaxiemacif->recv_q) == 0)
			return 0;
//		printf("%s: [1] something on the queue \n\r",__func__);
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
	}else{
		return 0;
	}

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
	xil_netif_initialized = 1;

}

void xileth_exit(void)
{
	netdev_free(xileth);
}
#endif
