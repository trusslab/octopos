/*
 *  Lowest net device code:
 *    independent net device layer
 */
#include "netif.h"
#include "ether.h"
#include "lib.h"
#include "list.h"
#include "netcfg.h"

/* localhost net device list */
struct list_head net_devices;

extern void loop_init(void);
extern void veth_init(void);
extern void loop_exit(void);
extern void veth_exit(void);
extern void veth_poll(void);

/* Alloc localhost net devices */
struct netdev *netdev_alloc(char *devstr, struct netdev_ops *netops)
{
	struct netdev *dev;
	dev = xzalloc(sizeof(*dev));
	/* add into localhost net device list */
	list_add_tail(&dev->net_list, &net_devices);
	/* set name */
	dev->net_name[NETDEV_NLEN - 1] = '\0';
	strncpy((char *)dev->net_name, devstr, NETDEV_NLEN - 1);
	dev->net_ops = netops;
	if (netops && netops->init)
		netops->init(dev);
	return dev;
}

void netdev_free(struct netdev *dev)
{
	if (dev->net_ops && dev->net_ops->exit)
		dev->net_ops->exit(dev);
	list_del(&dev->net_list);
	free(dev);
}

void netdev_interrupt(void)
{
	veth_poll();
}

/* create veth and lo */
void netdev_init(void)
{
	list_init(&net_devices);
	loop_init();
	veth_init();
}

void netdev_exit(void)
{
	veth_exit();
	loop_exit();
}

#ifdef DEBUG_PKB
void _netdev_tx(struct netdev *dev, struct pkbuf *pkb, int len,
		unsigned short proto, unsigned char *dst)
#else
void netdev_tx(struct netdev *dev, struct pkbuf *pkb, int len,
		unsigned short proto, unsigned char *dst)
#endif
{
	struct ether *ehdr = (struct ether *)pkb->pk_data;

	/* first copy to eth_dst, maybe eth_src will be copied to eth_dst */
	ehdr->eth_pro = _htons(proto);
	hwacpy(ehdr->eth_dst, dst);
	hwacpy(ehdr->eth_src, dev->net_hwaddr);

	l2dbg(MACFMT " -> " MACFMT "(%s)",
				macfmt(ehdr->eth_src),
				macfmt(ehdr->eth_dst),
				ethpro(proto));

	pkb->pk_len = len + ETH_HRD_SZ;
	/* real transmit packet */
	dev->net_ops->xmit(dev, pkb);
	free_pkb(pkb);
}

int local_address(unsigned int addr)
{
	struct netdev *dev;
	/* wildchar */
	if (!addr)
		return 1;
	/* loop back address */
	if (LOCALNET(loop) == (loop->net_mask & addr))
		return 1;
	/* nic bind address */
	list_for_each_entry(dev, &net_devices, net_list) {
		if (dev->net_ipaddr == addr)
			return 1;
	}
	return 0;
}
