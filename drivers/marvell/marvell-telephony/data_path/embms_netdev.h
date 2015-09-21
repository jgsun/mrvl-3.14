/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * (C) Copyright 2015 Marvell International Ltd.
 * All Rights Reserved
 */


#ifndef _EMBMS_NETDEV_H_
#define _EMBMS_NETDEV_H_

#include <linux/skbuff.h>

int embms_netdev_rx(struct sk_buff *skb);


#endif /* _EMBMS_NETDEV_H_ */
