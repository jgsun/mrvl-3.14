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

#include <linux/sched.h>
#include <linux/device.h>
#include <linux/pm_wakeup.h>
#include <linux/version.h>
#include <linux/export.h>
#include <linux/netdevice.h>	/* dev_kfree_skb_any */
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/ctype.h>
#include <linux/ratelimit.h>
#include <linux/pxa9xx_acipc.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include "debugfs.h"
#include "pxa_cp_load.h"
#include "psdatastub.h"
#include "data_path_common.h"
#include "shm_share.h"
#include "msocket.h"
#include "embms_netdev.h"

#define NETWORK_EMBMS_CID    0xFF

#define IPV4_ACK_LENGTH_LIMIT 96
#define IPV6_ACK_LENGTH_LIMIT 128

struct psd_context {
	struct psd_user __rcu *user;
	void __rcu *queue;
};

struct psd_device {
	int version;
	char *name;
	struct psd_driver *driver;
	struct device dev;
};

#define to_psd_driver(drv) container_of(drv, struct psd_driver, driver)
#define to_psd_device(dev) container_of(dev, struct psd_device, dev)

static struct psd_device psd_dev = {
	.name = "psd",
};

static struct psd_context psd_contexts[MAX_CID_NUM];

static u32 ack_opt = true;
static u32 data_drop = true;
static u32 ndev_fc;

bool data_enabled = true;

int psd_register(const struct psd_user *user, int cid)
{
	int ret;
	void *queue = NULL;

	ret = cmpxchg(&psd_contexts[cid].user, NULL, user) ==
		NULL ? 0 : -EEXIST;
	if (ret == 0) {
		if (psd_dev.driver && psd_dev.driver->alloc_queue) {
			queue =
				psd_dev.driver->alloc_queue(
					psd_dev.driver->priv,
					cid);
			if (queue == NULL) {
				psd_unregister(psd_contexts[cid].user, cid);
				ret = -1;
			}
		} else {
			queue = (void *)(unsigned long)0xff;
		}
	}

	if (ret == 0) {
		rcu_assign_pointer(psd_contexts[cid].queue, queue);
		synchronize_net();
	}

	return ret;
}
EXPORT_SYMBOL(psd_register);

int psd_unregister(const struct psd_user *user, int cid)
{
	int ret;
	ret = cmpxchg(&psd_contexts[cid].user, user, NULL) ==
		user ? 0 : -ENOENT;
	if (ret == 0) {
		void *queue = rcu_dereference(psd_contexts[cid].queue);

		rcu_assign_pointer(psd_contexts[cid].queue, NULL);
		synchronize_net();
		if (psd_dev.driver && psd_dev.driver->free_queue)
			psd_dev.driver->free_queue(psd_dev.driver->priv,
				queue);
	}
	return ret;
}
EXPORT_SYMBOL(psd_unregister);

static inline bool is_ack_packet(struct sk_buff *skb)
{
	struct iphdr *iph;
	bool is_ack;

	iph = ip_hdr(skb);
	is_ack = iph &&
		((iph->version == 4 && skb->len <= IPV4_ACK_LENGTH_LIMIT) ||
		(iph->version == 6 && skb->len <= IPV6_ACK_LENGTH_LIMIT));

	return is_ack;
}

unsigned short psd_select_queue(struct sk_buff *skb)
{
	bool is_ack;

	if (!ack_opt)
		return PSD_QUEUE_HIGH;

	is_ack = is_ack_packet(skb);
	return is_ack ? PSD_QUEUE_HIGH : PSD_QUEUE_DEFAULT;
}
EXPORT_SYMBOL(psd_select_queue);

int psd_data_tx(int cid, int simid, struct sk_buff *skb)
{
	int prio;
	int ret;

	if (unlikely(!data_enabled)) {
		pr_err_ratelimited("%s: data is disabled\n",
			__func__);
		goto drop;
	}

	if (unlikely(!psd_dev.driver ||
			!psd_dev.driver->data_tx ||
			!psd_dev.driver->is_tx_stopped)) {
		pr_err_ratelimited("%s: low-level driver is not ready\n",
			__func__);
		goto drop;
	}

	prio = skb->queue_mapping;

	/*
	 * tx_q is full or link is down
	 * allow ack when queue is full
	 */
	if (unlikely((prio != PSD_QUEUE_HIGH &&
		psd_dev.driver->is_tx_stopped(psd_dev.driver->priv)) ||
		 !psd_is_link_up())) {
		pr_err_ratelimited("%s: tx_q is full or link is down\n",
			__func__);

		if (data_drop) {
			pr_err_ratelimited("%s: drop the packet\n", __func__);
			goto drop;
		} else {
			pr_err_ratelimited("%s: return net busy to upper layer\n",
				__func__);
			return PSD_DATA_SEND_BUSY;
		}
	}

	rcu_read_lock();
	ret = psd_dev.driver->data_tx(psd_dev.driver->priv,
		cid, simid, prio, skb,
		rcu_dereference(psd_contexts[cid].queue));
	rcu_read_unlock();
	return ret;
drop:
	dev_kfree_skb_any(skb);
	return PSD_DATA_SEND_DROP;
}
EXPORT_SYMBOL(psd_data_tx);

int psd_data_rx(unsigned char cid, struct sk_buff *skb)
{
	struct psd_user *user;

	if (cid == NETWORK_EMBMS_CID) {
		embms_netdev_rx(skb);
		goto done;
	} else if (likely(cid >= 0 && cid < MAX_CID_NUM)) {
		rcu_read_lock();
		user = rcu_dereference(psd_contexts[cid].user);
		if (likely(user && user->on_receive))
			user->on_receive(user->priv, skb);
		rcu_read_unlock();
		if (!user)
			pr_err_ratelimited(
				"%s: no psd user for cid:%d\n",
				__func__, cid);
		else
			goto done;
	} else
		pr_err_ratelimited(
			"%s: invalid cid:%d\n",
			__func__, cid);

	dev_kfree_skb_any(skb);
done:
	return 0;
}

size_t psd_get_headroom(int cid)
{
	struct psd_user *user;
	size_t headroom = 0;

	if (unlikely(cid < 0 || cid >= MAX_CID_NUM))
		return 0;
	rcu_read_lock();
	user = rcu_dereference(psd_contexts[cid].user);
	if (likely(user))
		headroom = user->headroom;
	rcu_read_unlock();

	return headroom;
}

static void psd_tx_traffic_control(bool is_throttle)
{
	int i;

	if (!ndev_fc)
		return;

	for (i = 0; i < MAX_CID_NUM; ++i) {
		struct psd_user *user;
		rcu_read_lock();
		user = rcu_dereference(psd_contexts[i].user);
		if (user && user->on_throttle)
			user->on_throttle(user->priv, is_throttle);
		rcu_read_unlock();
	}
}

void psd_tx_stop(void)
{
	psd_tx_traffic_control(true);
}

void psd_tx_resume(void)
{
	psd_tx_traffic_control(false);
}

void psd_rx_stop(void)
{
	return;
}

static void psd_link_down(void)
{
	return;
}

static void psd_link_up(void)
{
	return;
}

bool psd_is_link_up(void)
{
	return cp_is_synced;
}

static int cp_link_status_notifier_func(struct notifier_block *this,
	unsigned long code, void *cmd)
{
	bool psd_is_synced = code == MsocketLinkupProcId;

	if (psd_is_synced)
		psd_link_up();
	else
		psd_link_down();

	if (likely(psd_dev.driver && psd_dev.driver->link_status_changed))
		psd_dev.driver->link_status_changed(psd_dev.driver->priv,
			psd_is_synced ? PSD_LINK_UP : PSD_LINK_DOWN);

	return 0;
}

static struct notifier_block cp_link_status_notifier = {
	.notifier_call = cp_link_status_notifier_func,
};

static int cp_mem_set_notifier_func(struct notifier_block *this,
	unsigned long code, void *cmd)
{
	struct cpload_cp_addr *addr = (struct cpload_cp_addr *)cmd;

	if (likely(psd_dev.driver && psd_dev.driver->set_addr))
		psd_dev.driver->set_addr(psd_dev.driver->priv, addr);

	return 0;
}

static struct notifier_block cp_mem_set_notifier = {
	.notifier_call = cp_mem_set_notifier_func,
};

static struct dentry *tel_debugfs_root_dir;
struct dentry *psd_debugfs_root_dir;

static int __init psd_debugfs_init(void)
{
	tel_debugfs_root_dir = tel_debugfs_get();
	if (!tel_debugfs_root_dir)
		return -ENOMEM;

	psd_debugfs_root_dir = debugfs_create_dir("psd", tel_debugfs_root_dir);
	if (IS_ERR_OR_NULL(psd_debugfs_root_dir))
		goto putrootfs;

	if (IS_ERR_OR_NULL(debugfs_create_bool("ndev_fc", S_IRUGO | S_IWUSR,
			psd_debugfs_root_dir, &ndev_fc)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_bool("data_drop", S_IRUGO | S_IWUSR,
			psd_debugfs_root_dir, &data_drop)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_bool("ack_opt", S_IRUGO | S_IWUSR,
			psd_debugfs_root_dir, &ack_opt)))
		goto error;

	return 0;

error:
	debugfs_remove_recursive(psd_debugfs_root_dir);
	psd_debugfs_root_dir = NULL;
putrootfs:
	tel_debugfs_put(tel_debugfs_root_dir);
	tel_debugfs_root_dir = NULL;
	return -1;
}

static int psd_debugfs_exit(void)
{
	debugfs_remove_recursive(psd_debugfs_root_dir);
	psd_debugfs_root_dir = NULL;
	tel_debugfs_put(tel_debugfs_root_dir);
	tel_debugfs_root_dir = NULL;
	return 0;
}

static int psd_match(struct device *dev, struct device_driver *drv)
{
	struct psd_device *pdev = to_psd_device(dev);
	struct psd_driver *pdrv = to_psd_driver(drv);

	return pdev->version == pdrv->version;
}

static struct bus_type psd_bus_type = {
	.name = "psd",
	.match = psd_match,
};

static int register_psd_device(struct psd_device *dev)
{
	dev->dev.bus = &psd_bus_type;
	dev_set_name(&dev->dev, "%s", dev->name);
	return device_register(&dev->dev);
}

static void unregister_psd_device(struct psd_device *dev)
{
	device_unregister(&dev->dev);
}

static int psd_driver_probe(struct device *dev)
{
	struct psd_device *pdev = to_psd_device(dev);
	struct psd_driver *pdrv = to_psd_driver(dev->driver);

	pdev->driver = pdrv;

	if (pdrv->init)
		return pdrv->init(pdrv->priv);

	return 0;
}

static int psd_driver_remove(struct device *dev)
{
	struct psd_device *pdev = to_psd_device(dev);
	struct psd_driver *pdrv = to_psd_driver(dev->driver);

	pdev->driver = NULL;

	if (pdrv->exit)
		pdrv->exit(pdrv->priv);

	return 0;
}

int register_psd_driver(struct psd_driver *driver)
{
	driver->driver.name = driver->name;
	driver->driver.bus = &psd_bus_type;
	driver->driver.probe = psd_driver_probe;
	driver->driver.remove = psd_driver_remove;
	return driver_register(&driver->driver);
}

void unregister_psd_driver(struct psd_driver *driver)
{
	driver_unregister(&driver->driver);
}

static int psd_probe(struct platform_device *pdev)
{
	if (psd_debugfs_init() < 0) {
		pr_err("%s: init debugfs failed\n", __func__);
		return -1;
	}

	if (register_cp_link_status_notifier(&cp_link_status_notifier) < 0) {
		pr_err("%s: register link status notifier failed\n",
			__func__);
		goto putdebugfs;
	}

	if (register_cp_mem_set_notifier(&cp_mem_set_notifier) < 0) {
		pr_err("%s: register mem set notifier failed\n",
			__func__);
		goto unregcls;
	}

	if (of_property_read_u32(pdev->dev.of_node, "version",
					&psd_dev.version)) {
		pr_info("%s: no version found, assume version 1\n",
			__func__);
		psd_dev.version = 1;
	}

	if (register_psd_device(&psd_dev) < 0) {
		pr_err("%s: register psd device failed\n",
			__func__);
		goto unregcms;
	}

	return 0;

unregcms:
	unregister_cp_mem_set_notifier(&cp_mem_set_notifier);
unregcls:
	unregister_cp_link_status_notifier(&cp_link_status_notifier);
putdebugfs:
	psd_debugfs_exit();

	return -1;
}

static int psd_remove(struct platform_device *dev)
{
	unregister_psd_device(&psd_dev);
	unregister_cp_mem_set_notifier(&cp_mem_set_notifier);
	unregister_cp_link_status_notifier(&cp_link_status_notifier);
	psd_debugfs_exit();
	return 0;
}

static struct of_device_id psd_dt_ids[] = {
	{ .compatible = "marvell,data-path", },
	{}
};

static struct platform_driver data_path_driver = {
	.probe		= psd_probe,
	.remove		= psd_remove,
	.driver		= {
		.name	= "psd",
		.of_match_table = psd_dt_ids,
		.owner	= THIS_MODULE,
	},
};

static int __init psd_init(void)
{
	int ret;

	ret = bus_register(&psd_bus_type);
	if (ret) {
		pr_err("%s: register psd bus error: %d\n",
			__func__, ret);
		return ret;
	}

	ret = platform_driver_register(&data_path_driver);
	if (ret) {
		pr_err("%s: register platform driver error: %d\n",
			__func__, ret);
		bus_unregister(&psd_bus_type);
	}

	return ret;
}

static void __exit psd_exit(void)
{
	platform_driver_unregister(&data_path_driver);
	bus_unregister(&psd_bus_type);
}

module_init(psd_init);
module_exit(psd_exit);
