/*
    Marvell io device driver for Linux
    Copyright (C) 2015 Marvell International Ltd.

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

#include <linux/module.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/poll.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "io_device.h"
#include "portqueue.h"
#include "msocket.h"
#include "shm_share.h"

static struct class *io_device_class;
static int io_device_major;
/* will replace together with userspace
#define IO_DEVICE_NAME "io_device"
*/
#define IO_DEVICE_NAME "ssipc_misc"

#define SHMEM_RECV_LIMIT 2048
#define SHMEM_PORT_HDR sizeof(struct shm_skhdr)
#define SHMEM_WHOLE_HEADER_SIZE (SHMEM_PORT_HDR + SHM_HEADER_SIZE)
#define SHMEM_PAYLOAD_LIMIT (SHMEM_RECV_LIMIT - SHMEM_WHOLE_HEADER_SIZE)

static const char const *modem_state_str[] = {
	[STATE_OFFLINE]		= "OFFLINE",
	[STATE_CRASH_RESET]	= "CRASH_RESET",
	[STATE_CRASH_EXIT]	= "CRASH_EXIT",
	[STATE_BOOTING]		= "BOOTING",
	[STATE_ONLINE]		= "ONLINE",
	[STATE_NV_REBUILDING]	= "NV_REBUILDING",
	[STATE_LOADER_DONE]	= "LOADER_DONE",
	[STATE_SIM_ATTACH]	= "SIM_ATTACH",
	[STATE_SIM_DETACH]	= "SIM_DETACH",
};

const char *get_modem_state_str(int state)
{
	return modem_state_str[state];
}

int if_msocket_connect(void)
{
	return cp_is_synced;
}

int get_modem_state(struct io_device *iod)
{
	if (!iod->port)
		return if_msocket_connect() ? STATE_ONLINE : STATE_OFFLINE;

	else
		return iod->channel_status;
}

static DEFINE_MUTEX(io_device_mtx);
static LIST_HEAD(io_device_list);

static void io_device_recv_callback(struct sk_buff *skb, void *arg);

#define MAX_IOD_RXQ_LEN 2000
#define MAX_IOD_RXQ_HI_WM 1000
#define MAX_IOD_RXQ_LOW_WM 500
/* check if rx queue is below low water-mark */
static inline int rxlist_below_lo_wm(struct io_device *iod)
{
	return skb_queue_len(&iod->sk_rx_q) < MAX_IOD_RXQ_LOW_WM;
}

/* check if rx queue is above high water-mark */
static inline int rxlist_above_hi_wm(struct io_device *iod)
{
	return skb_queue_len(&iod->sk_rx_q) >= MAX_IOD_RXQ_HI_WM;
}

static int io_device_open(struct inode *inode, struct file *filp)
{
	int minor = iminor(inode);
	struct io_device *c = NULL;
	struct io_device *iod = NULL;
	int ref_cnt;

	list_for_each_entry(c, &io_device_list, list) {
		if (minor == c->minor) {
			iod = c;
			break;
		}
	}

	if (iod == NULL) {
		pr_err("%s invlid minor detected", __func__);
		return -EINVAL;
	}

	filp->private_data = (void *)iod;
	ref_cnt = atomic_inc_return(&iod->opened);

	pr_info("%s (opened %d)\n", iod->name, ref_cnt);

	return 0;
}

static int io_device_release(struct inode *inode, struct file *filp)
{
	struct io_device *iod = (struct io_device *)filp->private_data;
	int ref_cnt;

	skb_queue_purge(&iod->sk_rx_q);
	ref_cnt = atomic_dec_return(&iod->opened);

	pr_info("%s (opened %d)\n", iod->name, ref_cnt);

	return 0;
}

/* default skb tx_fixup
 * tx list only contain one skb */
static ssize_t tx_fixup_def(struct io_device *iod,
		const char __user *data, size_t count,
		struct sk_buff_head *txq, u16 hdr_reserved)
{
	struct sk_buff *skb;

	skb = alloc_skb(count + hdr_reserved, GFP_KERNEL);
	if (!skb) {
		pr_err("Data_channel: %s: out of memory.\n", __func__);
		return -ENOMEM;
	}

	skb_reserve(skb, hdr_reserved);
	if (copy_from_user(skb_put(skb, count), data, count)) {
		kfree_skb(skb);
		pr_err("%s: %s: copy_from_user failed.\n",
		       __func__, iod->name);
		return -EFAULT;
	}

	skb_queue_tail(txq, skb);
	return count;
}

static ssize_t io_device_write(struct file *filp, const char __user *data,
			size_t count, loff_t *fpos)
{
	struct io_device *iod = (struct io_device *)filp->private_data;
	struct sk_buff *skb;
	struct sk_buff_head txq;
	ShmApiMsg *pshm;

	if (get_modem_state(iod) != STATE_ONLINE) {
		pr_debug_ratelimited("%s: channel(%s) is not ready\n",
				__func__, iod->name);
		return -EAGAIN;
	}

	if (count > SHMEM_PAYLOAD_LIMIT) {
		pr_err_ratelimited("%s: DATA size bigger than buffer size\n", __func__);
		return -ENOMEM;
	}

	skb_queue_head_init(&txq);
	count = iod->tx_fixup(iod, data, count, &txq, SHMEM_WHOLE_HEADER_SIZE);

	while (!skb_queue_empty(&txq)) {
		skb = skb_dequeue(&txq);
		pshm = (ShmApiMsg *)skb_push(skb, SHM_HEADER_SIZE);
		pshm->msglen = skb->len - SHM_HEADER_SIZE;
		pshm->procId = iod->data_id;
		pshm->svcId = iod->port;
		msendskb(iod->port, skb, skb->len, MSOCKET_KERNEL);
	}

	return count;
}

static ssize_t io_device_read(struct file *filp, char *buf, size_t count,
			loff_t *fpos)
{
	struct io_device *iod = (struct io_device *)filp->private_data;
	struct sk_buff_head *rxq = &iod->sk_rx_q;
	struct sk_buff *skb;
	int copied = 0;

	if (skb_queue_empty(rxq) && filp->f_flags & O_NONBLOCK) {
		pr_info("%s: ERR! no data in rxq\n", iod->name);
		return -EAGAIN;
	}

	while (skb_queue_empty(rxq)) {
		if (wait_event_interruptible(iod->wq,
			(!skb_queue_empty(rxq) ||
			 (get_modem_state(iod) != STATE_ONLINE)))) {
			return -ERESTARTSYS;
		}
		if (get_modem_state(iod) != STATE_ONLINE) {
			pr_debug_ratelimited("%s: channel(%s) is not ready\n",
					__func__, iod->name);
			return 0;
		}
	}

	skb = skb_dequeue(rxq);
	if (rxlist_below_lo_wm(iod))
		msocket_recv_unthrottled(iod->sock_fd);

	copied = skb->len > count ? count : skb->len;

	if (copy_to_user(buf, skb->data, copied)) {
		pr_err("%s: ERR! copy_to_user fail\n", iod->name);
		dev_kfree_skb_any(skb);
		return -EFAULT;
	}

	pr_debug("%s: data:%d copied:%d qlen:%d\n",
		iod->name, skb->len, copied, rxq->qlen);

	if (skb->len > count) {
		skb_pull(skb, count);
		skb_queue_head(rxq, skb);
	} else {
		dev_kfree_skb_any(skb);
	}

	return copied;
}

static long io_device_ioctl(struct file *filp,
				unsigned int cmd, unsigned long arg)
{
	struct io_device *iod = (struct io_device *)filp->private_data;

	if (iod->ioctl_hook)
		return iod->ioctl_hook(iod, cmd, arg);

	return 0;
}

static unsigned int io_device_poll(struct file *filp,
						struct poll_table_struct *wait)
{
	struct io_device *iod = (struct io_device *)filp->private_data;
	int p_state = get_modem_state(iod);

	poll_wait(filp, &iod->wq, wait);

	if (!skb_queue_empty(&iod->sk_rx_q) && p_state != STATE_OFFLINE)
		return POLLIN | POLLRDNORM;

	if (p_state == STATE_CRASH_RESET
	    || p_state == STATE_CRASH_EXIT) {
		return POLLHUP;
	} else {
		return 0;
	}
	return 0;
}

static void init_work(struct work_struct *work)
{
	struct io_device *iod = container_of(work,
				struct io_device, init_work.work);
	ShmApiMsg shm_msg_hdr;
	int succ = 0;

	if (!if_msocket_connect()) {
		pr_debug("%s: channel of %s fail & close\n",
				__func__, iod->name);
		goto out;
	}

	if (iod->sock_fd == -1) {
		iod->sock_fd = msocket_with_cb(iod->port,
				(void *)io_device_recv_callback, (void *)iod);
		if (iod->sock_fd < 0) {
			pr_err("%s: sock fd of %s opened fail\n",
					__func__, iod->name);
			iod->sock_fd = -1;
			goto out;
		}
		pr_info("%s:io->port:%d opened\n", __func__, iod->port);
	}

	if (!iod->channel_inited) {
		shm_msg_hdr.svcId = iod->port;
		shm_msg_hdr.msglen = 0;
		shm_msg_hdr.procId = iod->start_id;

		msend(iod->sock_fd, (u8 *)&shm_msg_hdr,
				SHM_HEADER_SIZE, MSOCKET_ATOMIC);
		pr_debug_ratelimited("%s: port:%d, send_handshake: %d!\n",
				iod->name,
				iod->port,
				iod->channel_inited);
	} else
		succ = 1;

out:
	if (!succ)
		queue_delayed_work(iod->workq, &iod->init_work, HZ);
}

static inline int queue_skb_to_iod(struct sk_buff *skb, struct io_device *iod)
{
	struct sk_buff_head *rxq = &iod->sk_rx_q;
	struct sk_buff *victim;

	skb_queue_tail(rxq, skb);

	if (rxlist_above_hi_wm(iod))
		msocket_recv_throttled(iod->sock_fd);
	if (rxq->qlen > MAX_IOD_RXQ_LEN) {
		pr_err_ratelimited("%s: %s application may be dead (rxq->qlen %d > %d)\n",
			iod->name, iod->app ? iod->app : "corresponding",
			rxq->qlen, MAX_IOD_RXQ_LEN);
		victim = skb_dequeue(rxq);
		if (victim)
			dev_kfree_skb_any(victim);
		return -ENOSPC;
	} else {
		pr_debug("%s: rxq->qlen = %d\n", iod->name, rxq->qlen);
		return 0;
	}
}

int rx_fixup_def(struct sk_buff *skb)
{
	return 1;
}

/* return 1 means complete packet,
 * return 0 means incomplete or error packet*/
int packet_complete(struct sk_buff **skb_out, struct io_device *iod)
{
	int ret = 0;
	if (iod->long_packet_enable) {
		struct sk_buff *skb = *skb_out;
		struct _long_packet_header *header;
		u8 header_len = sizeof(struct _long_packet_header);
		u16 msg_len;
		u16 cur_seq;
		u16 total_len;
		pr_debug("%s: long packet!!!(skb_len, %d)\n",
				__func__, skb->len);
		if (skb->len <= header_len) {
			pr_err("%s: error long packet detected, too small.\n",
					__func__);
			goto error_out;
		}
		header = (struct _long_packet_header *)skb->data;
		msg_len = skb->len - header_len;
		total_len = header->total_len;
		cur_seq = header->seq;
		pr_debug("%s: msg_len: %d, total_len:%d, seq:%d\n", __func__,
					msg_len, total_len, cur_seq);
		if (!iod->long_packet) {
			if (msg_len == total_len) {
				ret = 1;
				skb_pull(skb, header_len);
				goto out;
			}
			iod->long_packet = kzalloc(sizeof(struct _long_packet),
						GFP_KERNEL);
			if (!iod->long_packet) {
				pr_err("%s: alloc long_packet error\n",
						__func__);
				goto error_out;
			}
			iod->long_packet->long_skb =
					alloc_skb(total_len, GFP_KERNEL);
			if (!iod->long_packet->long_skb) {
				pr_err("%s: alloc long_packet skb error.\n",
						__func__);
				goto error_out;
			}
			iod->long_packet->total_len = total_len;
		} else {
			pr_debug("%s: lp->cur: %d, lp->total:%d, lp->seq:%d\n",
					__func__,
					iod->long_packet->cur_len,
					iod->long_packet->total_len,
					iod->long_packet->cur_seq);
			if (cur_seq != iod->long_packet->cur_seq + 1) {
				pr_err("%s: error long packet detected, seq error.\n",
					__func__);
				goto error_out;
			} else if (iod->long_packet->cur_len + msg_len >
					iod->long_packet->total_len) {
				pr_err("%s: error long packet detected, lens error.\n",
					__func__);
				goto error_out;
			}
		}
		skb_pull(skb, header_len);
		memcpy(skb_put(iod->long_packet->long_skb, msg_len),
				skb->data, skb->len);
		kfree_skb(skb);

		iod->long_packet->cur_len += msg_len;
		iod->long_packet->cur_seq = cur_seq;

		if (iod->long_packet->cur_len ==
				iod->long_packet->total_len) {
			*skb_out = iod->long_packet->long_skb;
			iod->long_packet->long_skb = NULL;
			kfree(iod->long_packet);
			iod->long_packet = NULL;
			ret = 1;
		}
		goto out;

error_out:
		kfree_skb(skb);
		skb = NULL;
		if (iod->long_packet) {
			if (iod->long_packet->long_skb) {
				kfree_skb(iod->long_packet->long_skb);
				iod->long_packet->long_skb = NULL;
			}
			kfree(iod->long_packet);
			iod->long_packet = NULL;
		}
	} else
		ret = 1;
out:
	return ret;
}

static int rx_raw_misc(struct sk_buff *skb, struct io_device *iod)
{
	/* Remove the msocket header */
	skb_pull(skb, SHM_HEADER_SIZE);

	if (packet_complete(&skb, iod))
		if (iod->rx_fixup && iod->rx_fixup(skb)) {
			queue_skb_to_iod(skb, iod);
			wake_up_interruptible(&iod->wq);
		}

	return 0;
}

static int event_handler(struct sk_buff *skb, struct io_device *iod)
{
	ShmApiMsg *shm_msg_hdr;
	u8 *rxmsg = skb->data;
	int handled = 1;

	shm_msg_hdr = (ShmApiMsg *) rxmsg;
	if (shm_msg_hdr->svcId != iod->port) {
		pr_err("%s, svcId(%d) is incorrect, expect %d",
			__func__, shm_msg_hdr->svcId, iod->port);
		return handled;
	}

	pr_debug("%s,srvId=%d, procId=%d, len=%d\n",
		__func__,
		shm_msg_hdr->svcId,
		shm_msg_hdr->procId,
		shm_msg_hdr->msglen);

	if (shm_msg_hdr->procId == iod->start_id) {
		iod->channel_inited = 1;
		iod->channel_status = STATE_ONLINE;
		pr_info("%s: port:%d, init: %d!\n",
				iod->name, iod->port, iod->channel_inited);
	} else if (shm_msg_hdr->procId == iod->data_id) {
		if (atomic_read(&iod->opened) <= 0
				&& !iod->buffer_offline_enable)
			goto out;
		if (iod->channel_inited) {
			rx_raw_misc(skb, iod);
			handled = 0;
		}
	} else if (shm_msg_hdr->procId == iod->linkdown_id) {
		iod->channel_inited = 0;
		if (read_ee_config_b_cp_reset() == 1)
			iod->channel_status = STATE_CRASH_RESET;
		else
			iod->channel_status = STATE_CRASH_EXIT;
		wake_up_interruptible(&iod->wq);
		cancel_delayed_work_sync(&iod->init_work);
		pr_info("%s: %s: received  MsocketLinkdownProcId!\n",
				__func__, iod->name);
	} else if (shm_msg_hdr->procId == iod->linkup_id) {
		iod->channel_status = STATE_OFFLINE;
		skb_queue_purge(&iod->sk_rx_q);
		queue_delayed_work(iod->workq, &iod->init_work, 0);
		pr_info("%s: %s: received  MsocketLinkupProcId!\n",
				__func__, iod->name);
	}

out:
	return handled;
}

static void io_device_recv_callback(struct sk_buff *skb, void *arg)
{
	struct io_device *iod = (struct io_device *)arg;
	int handled = 0;

	if (!skb || !arg) {
		pr_err("%s: channel of %s got invalid parameters\n",
				__func__, iod->name);
		return;
	}

	handled = event_handler(skb, iod);
	if (handled) {
		kfree_skb(skb);
		skb = NULL;
	}
}

static const struct file_operations io_device_fops = {
	.owner = THIS_MODULE,
	.open = io_device_open,
	.release = io_device_release,
	.poll = io_device_poll,
	.unlocked_ioctl = io_device_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = io_device_ioctl,
#endif
	.write = io_device_write,
	.read = io_device_read,
};

void io_channel_init(struct io_device *iod)
{
	iod->channel_status = STATE_OFFLINE;
	iod->sock_fd = -1;

	if (!iod->port)
		return;

	queue_delayed_work(iod->workq, &iod->init_work, 0);
}
EXPORT_SYMBOL(io_channel_init);

void io_channel_deinit(struct io_device *iod)
{
	if (iod->sock_fd != -1)
		mclose(iod->sock_fd);
	iod->sock_fd = -1;

	cancel_delayed_work_sync(&iod->init_work);
}
EXPORT_SYMBOL(io_channel_deinit);

static int init_io_device(struct io_device *iod)
{
	int ret = 0;
	char workq_name[50] = {0};

	/* init io device */
	atomic_set(&iod->opened, 0);

	init_waitqueue_head(&iod->wq);
	skb_queue_head_init(&iod->sk_rx_q);
	iod->channel_status = STATE_OFFLINE;
	iod->sock_fd = -1;

	/* init def tx, rx fixup hook */
	if (!iod->tx_fixup)
		iod->tx_fixup = tx_fixup_def;
	if (!iod->rx_fixup)
		iod->rx_fixup = rx_fixup_def;

	sprintf(workq_name, "init_wq(%s)", iod->name);
	INIT_DELAYED_WORK(&iod->init_work, init_work);
	iod->workq = create_workqueue(workq_name);
	if (iod->workq == NULL) {
		pr_err("%s:Can't create work queue!\n", __func__);
		return -1;
	}

	/* register char device */
	iod->dev = device_create(io_device_class, NULL,
				MKDEV(io_device_major, iod->minor),
				iod, "%s", iod->name);
	if (IS_ERR(iod->dev)) {
		pr_err("%s: ERR! device_create failed\n", iod->name);
		if (iod->workq) {
			destroy_workqueue(iod->workq);
			iod->workq = NULL;
		}
		return -1;
	}

	pr_info("%s is created\n", iod->name);

	/* init hook */
	if (iod->init_hook)
		iod->init_hook(iod);

	return ret;
}

static void deinit_io_device(struct io_device *iod)
{

	/* deinit hook */
	if (iod->deinit_hook)
		iod->deinit_hook(iod);

	io_channel_deinit(iod);

	/* release io device */
	device_destroy(io_device_class, MKDEV(io_device_major, iod->minor));

	if (iod->workq) {
		destroy_workqueue(iod->workq);
		iod->workq = NULL;
	}

	pr_info("%s is released\n", iod->name);
}

int io_device_register(struct io_device *iod)
{
	int err = 0;
	struct io_device *c;

	INIT_LIST_HEAD(&iod->list);

	mutex_lock(&io_device_mtx);

	iod->minor = iod->port;
	list_for_each_entry(c, &io_device_list, list) {
		if (c->minor == iod->minor) {
			pr_err("%s: device(%s) already existed\n",
					__func__, c->name);
			err = -EBUSY;
			goto out;
		}
	}

	init_io_device(iod);

	list_add(&iod->list, &io_device_list);

out:
	mutex_unlock(&io_device_mtx);
	return err;
}
EXPORT_SYMBOL(io_device_register);

int io_device_deregister(struct io_device *iod)
{
	deinit_io_device(iod);

	if (WARN_ON(list_empty(&iod->list)))
		return -EINVAL;

	mutex_lock(&io_device_mtx);
	list_del(&iod->list);
	device_destroy(io_device_class, MKDEV(io_device_major, iod->minor));
	mutex_unlock(&io_device_mtx);
	return 0;
}
EXPORT_SYMBOL(io_device_deregister);

/* module initialization */
static int __init io_device_init(void)
{
	int ret = 0;

	io_device_class = class_create(THIS_MODULE, IO_DEVICE_NAME);
	ret = PTR_ERR(io_device_class);
	if (IS_ERR(io_device_class)) {
		pr_err("%s: create %s class failed\n", __func__,
			IO_DEVICE_NAME);
		goto io_device_class_fail;
	}

	io_device_major = register_chrdev(0, IO_DEVICE_NAME, &io_device_fops);
	if (io_device_major < 0) {
		pr_err("%s: register chrdev failed\n", __func__);
		ret = io_device_major;
		goto chrdev_fail;
	}

	return ret;

chrdev_fail:
	class_destroy(io_device_class);
io_device_class_fail:
	return ret;
}

/* module exit */
static void __exit io_device_exit(void)
{
	struct io_device *iod;

	/* deinit io deivces */
	list_for_each_entry(iod, &io_device_list, list)
		io_device_deregister(iod);

	unregister_chrdev(io_device_major, IO_DEVICE_NAME);
	class_destroy(io_device_class);
}

module_init(io_device_init);
module_exit(io_device_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION("Marvell IO Char Driver");
