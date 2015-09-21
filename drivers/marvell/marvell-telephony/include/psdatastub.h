/*

 *(C) Copyright 2007 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * All Rights Reserved
 */

#ifndef _PSD_DATA_CHANNEL_H_
#define _PSD_DATA_CHANNEL_H_

#define MAX_CID_NUM    15

#define PSD_DATA_SEND_OK 0
#define PSD_DATA_SEND_BUSY (-1)
#define PSD_DATA_SEND_DROP (-2)

enum {
	PSD_QUEUE_HIGH,
	PSD_QUEUE_DEFAULT,
	PSD_QUEUE_CNT
};

struct sk_buff;
struct psd_user {
	void *priv;
	size_t headroom;
	int (*on_receive)(void *priv, struct sk_buff *skb);
	void (*on_throttle)(void *priv, bool is_throttle);
};

int psd_register(const struct psd_user *user, int cid);
int psd_unregister(const struct psd_user *user, int cid);

unsigned short psd_select_queue(struct sk_buff *skb);
int psd_data_tx(int cid, int simid, struct sk_buff *skb);

#endif
