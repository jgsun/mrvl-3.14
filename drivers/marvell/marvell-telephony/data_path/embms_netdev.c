/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * (C) Copyright 2015 Marvell International Ltd.
 * All Rights Reserved
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/debugfs.h>

static struct net_device *embms_netdev;

static int embms_netdev_open(struct net_device *netdev)
{
	netif_start_queue(netdev);
	return 0;
}

static int embms_netdev_stop(struct net_device *netdev)
{
	netif_stop_queue(netdev);
	return 0;
}

static netdev_tx_t embms_netdev_tx(struct sk_buff *skb, struct net_device *netdev)
{
	netdev->stats.tx_packets++;
	netdev->stats.tx_bytes += skb->len;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;

}

int embms_netdev_rx(struct sk_buff *skb)
{
	struct net_device *netdev = embms_netdev;
	struct iphdr *ip_header = (struct iphdr *)skb->data;
	__be16	protocol;

	if (!netdev) {
		pr_err("%s: embms_netdev is NULL\n", __func__);
		return -1;
	}

	if (ip_header->version == 4) {
		protocol = htons(ETH_P_IP);
	} else if (ip_header->version == 6) {
		protocol = htons(ETH_P_IPV6);
	} else {
		netdev_err(netdev, "embms_netdev_rx: invalid ip version: %d\n",
		       ip_header->version);
		netdev->stats.rx_dropped++;
		dev_kfree_skb_any(skb);
		return -1;
	}

	skb->dev = netdev;
	skb->protocol = protocol;

	if (netif_rx(skb) == NET_RX_SUCCESS) {
		netdev->stats.rx_packets++;
		netdev->stats.rx_bytes += skb->len;
	} else {
		netdev->stats.rx_dropped++;
		pr_notice_ratelimited(
			"embms_netdev_rx: packet dropped by netif_rx\n");
		return -1;
	}

	return 0;
}

static const struct net_device_ops embms_netdev_ops = {
	.ndo_open		= embms_netdev_open,
	.ndo_stop		= embms_netdev_stop,
	.ndo_start_xmit	= embms_netdev_tx
};

static void embms_netdev_setup(struct net_device *netdev)
{
	netdev->netdev_ops	= &embms_netdev_ops;
	netdev->type		= ARPHRD_VOID;
	netdev->mtu		= 1500;
	netdev->addr_len	= 0;
	netdev->flags		= IFF_NOARP;
	netdev->hard_header_len	= 16;
	netdev->priv_flags	&= ~IFF_XMIT_DST_RELEASE;
	netdev->destructor	= free_netdev;
}

static int __init embms_netdev_init(void)
{
	const char ifname[] = "embms0";
	struct net_device *dev;
	int ret;

	dev = alloc_netdev(0, ifname, embms_netdev_setup);
	if (!dev) {
		pr_err("%s: alloc_netdev for %s fail\n",
		       __func__, ifname);
		return -ENOMEM;
	}
	ret = register_netdev(dev);
	if (ret) {
		pr_err("%s: register_netdev for %s fail\n",
		       __func__, ifname);
		free_netdev(dev);
		return ret;
	}
	embms_netdev = dev;
	return 0;
};

static void __exit embms_netdev_exit(void)
{
	struct net_device *dev;

	dev = embms_netdev;
	if (!dev)
		return;

	if (dev->flags & IFF_UP)
		embms_netdev_stop(dev);

	unregister_netdev(dev);
	embms_netdev = NULL;
}

module_init(embms_netdev_init);
module_exit(embms_netdev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION("Marvell eMBMS Network Device Driver");
