
/*
    Marvell PXA9XX ACIPC-MSOCKET driver for Linux
    Copyright (C) 2010 Marvell International Ltd.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DATA_CHANNEL_COMMON_H_
#define _DATA_CHANNEL_COMMON_H_

#include <linux/list.h>

enum {
	PSD_LINK_DOWN,
	PSD_LINK_UP,
};

struct sk_buff;
struct cpload_cp_addr;

struct psd_driver {
	/* init the driver */
	int (*init)(void *priv);
	/* exit the driver */
	void (*exit)(void *priv);
	/* set ring buffer address */
	int (*set_addr)(void *priv, const struct cpload_cp_addr *addr);
	/* transfer data */
	int (*data_tx)(void *priv, int cid, int prio,
		struct sk_buff *skb, void *queue);
	bool (*is_tx_stopped)(void *priv);
	/* cp link status changed */
	void (*link_status_changed)(void *priv, int status);

	/* queue allocation */
	void* (*alloc_queue)(void *priv, int cid);
	void (*free_queue)(void *priv, void *queue);

	/* the driver version */
	int version;

	/* driver name */
	const char *name;

	/* private info */
	void *priv;

	struct device_driver driver;
};

extern struct dentry *psd_debugfs_root_dir;

static inline unsigned padding_size(unsigned len,
	unsigned aligned_size)
{
	return (~len + 1) & (aligned_size - 1);
}

static inline unsigned padded_size(unsigned len,
	unsigned aligned_size)
{
	return (len + (aligned_size - 1)) & ~(aligned_size - 1);
}

int register_psd_driver(struct psd_driver *driver);
void unregister_psd_driver(struct psd_driver *driver);
int psd_data_rx(unsigned char cid, struct sk_buff *skb);
void psd_tx_stop(void);
void psd_tx_resume(void);
void psd_rx_stop(void);
bool psd_is_link_up(void);
size_t psd_get_headroom(int cid);

#endif /* _DATA_CHANNEL_COMMON_H_ */
