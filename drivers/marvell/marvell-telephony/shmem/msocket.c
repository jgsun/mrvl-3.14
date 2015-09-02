/*
    msocket.c Created on: Aug 2, 2010, Jinhua Huang <jhhuang@marvell.com>

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

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/completion.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif
#include <linux/debugfs.h>
#include "shm.h"
#include "shm_share.h"
#include "portqueue.h"
#include "msocket.h"
#include "pxa_cp_load.h"
#include "debugfs.h"
#include "shm_map.h"

#define CMSOCKDEV_NR_DEVS PORTQ_NUM_MAX


static struct dentry *tel_debugfs_root_dir;
struct dentry *msocket_debugfs_root_dir;

static int cmsockdev_major;
static int cmsockdev_minor;
static int cmsockdev_nr_devs = CMSOCKDEV_NR_DEVS;

struct cmsockdev_dev {
	struct cdev cdev;	/* Char device structure */
};

struct cmsockdev_dev *cmsockdev_devices;
static struct class *cmsockdev_class;

static struct portq_group *portq_grp[portq_grp_cnt] = {
	[portq_grp_cp_main] = &pgrp_cp,
	[portq_grp_m3] = &pgrp_m3
};

/* open a msocket in kernel */
int msocket(int port)
{
	return msocket_with_cb(port, NULL, NULL);
}
EXPORT_SYMBOL(msocket);

/* open a msocket with receive callback in kernel */
int msocket_with_cb(int port,
		void (*clbk)(struct sk_buff *, void *), void *arg)
{
	struct portq *portq;

	portq = portq_open_with_cb(port, clbk, arg);
	if (IS_ERR(portq)) {
		pr_err("MSOCK: can't open queue port %d\n", port);
		return -1;
	}

	return port;
}
EXPORT_SYMBOL(msocket_with_cb);

/* close a msocket */
int mclose(int sock)
{
	struct portq *portq;

	portq = (struct portq *)portq_get(sock);

	if (!portq) {
		pr_err("MSOCK: closed socket %d failed\n", sock);
		return -1;
	}

	portq_close(portq);

	return 0;
}
EXPORT_SYMBOL(mclose);

/* send packet to msocket */
int msend(int sock, const void *buf, int len, int flags)
{
	struct portq *portq;
	struct sk_buff *skb;
	struct shm_skhdr *hdr;
	bool block = flags == MSOCKET_KERNEL;

	portq = (struct portq *)portq_get(sock);
	if (!portq) {
		pr_err("MSOCK: %s: sock %d not opened!\n",
		       __func__, sock);
		return -1;
	}

	/* check the len first */
	if (len > (portq->grp->rbctl->tx_skbuf_size - sizeof(*hdr))) {
		pr_err("MSOCK: %s: port %d, len is %d!!\n",
		       __func__, portq->port, len);
		portq->stat_tx_drop++;
		return -1;
	}

	/* alloc space */
	if (block)
		skb = alloc_skb(len + sizeof(*hdr), GFP_KERNEL);
	else
		skb = alloc_skb(len + sizeof(*hdr), GFP_ATOMIC);

	if (!skb) {
		pr_err("MSOCK: %s: out of memory.\n", __func__);
		return -ENOMEM;
	}
	skb_reserve(skb, sizeof(*hdr));	/* reserve header space */

	memcpy(skb_put(skb, len), buf, len);

	/* push header back */
	hdr = (struct shm_skhdr *)skb_push(skb, sizeof(*hdr));

	hdr->address = 0;
	hdr->port = portq->port;
	hdr->checksum = 0;
	hdr->length = len;

	if (!portq->grp->ops->is_synced() || portq_xmit(portq, skb, block) < 0) {
		kfree_skb(skb);
		pr_err("MSOCK: %s: port %d xmit error.\n",
		       __func__, portq->port);
		return -1;
	}

	return len;
}
EXPORT_SYMBOL(msend);

/* send sk_buf packet to msocket */
int msendskb(int sock, struct sk_buff *skb, int len, int flags)
{
	struct portq *portq;
	struct shm_skhdr *hdr;
	int length;
	bool block = flags == MSOCKET_KERNEL;
	if (NULL == skb) {
		pr_err("MSOCK:%s:skb buff is NULL!\n", __func__);
		return -1;
	}
	portq = (struct portq *)portq_get(sock);
	if (!portq) {
		pr_err("MSOCK: %s: sock %d not opened!\n",
		       __func__, sock);
		kfree_skb(skb);
		return -1;
	}

	length = skb->len;
	if (length > (portq->grp->rbctl->tx_skbuf_size - sizeof(*hdr))) {
		pr_err(
		       "MSOCK: %s: port %d, len is %d larger than tx_skbuf_size\n",
		       __func__, portq->port, len);
		kfree_skb(skb);
		portq->stat_tx_drop++;
		return -1;
	}

	hdr = (struct shm_skhdr *)skb_push(skb, sizeof(*hdr));
	hdr->address = 0;
	hdr->port = portq->port;
	hdr->checksum = 0;
	hdr->length = len;

	if (!portq->grp->ops->is_synced() || portq_xmit(portq, skb, block) < 0) {
		kfree_skb(skb);
		pr_err("MSOCK: %s: port %d xmit error.\n",
		       __func__, portq->port);
		return -1;
	}
	return 0;
}
EXPORT_SYMBOL(msendskb);

/* receive packet from msocket */
int mrecv(int sock, void *buf, int len, int flags)
{
	struct portq *portq;
	struct sk_buff *skb;
	struct shm_skhdr *hdr;
	int packet_len;
	bool block = flags == MSOCKET_KERNEL;

	portq = (struct portq *)portq_get(sock);
	if (!portq) {
		pr_err("MSOCK: %s: sock %d not opened!\n",
		       __func__, sock);
		return -1;
	}

	skb = portq_recv(portq, block);
	if (IS_ERR(skb)) {
		pr_debug("MSOCK: %s: portq_recv returns %p\n",
		       __func__, skb);
		return -1;
	}

	if (!skb)
		return 0;

	hdr = (struct shm_skhdr *)skb->data;
	packet_len = hdr->length;
	if (packet_len > len) {
		pr_err("MSOCK: %s: error: no enough space.\n",
		       __func__);
		kfree_skb(skb);
		return -1;	/* error */
	}

	memcpy(buf, skb_pull(skb, sizeof(*hdr)), hdr->length);

	kfree_skb(skb);

	return packet_len;
}
EXPORT_SYMBOL(mrecv);

struct sk_buff *mrecvskb(int sock, int len, int flags)
{
	struct portq *portq;
	struct sk_buff *skb;
	struct shm_skhdr *hdr;
	bool block = flags == MSOCKET_KERNEL;

	portq = (struct portq *)portq_get(sock);
	if (!portq) {
		pr_err("MSOCK: %s: sock %d not opened!\n",
		       __func__, sock);
		return NULL;
	}

	skb = portq_recv(portq, block);
	if (IS_ERR(skb)) {
		pr_debug("MSOCK: %s: portq_recv returns %p\n",
		       __func__, skb);
		return NULL;
	}

	if (!skb)
		return NULL;

	hdr = (struct shm_skhdr *)skb->data;
	if (hdr->length > len) {
		pr_err("MSOCK: %s: error: no enough space.\n",
		       __func__);
		kfree_skb(skb);
		return NULL;	/* error */
	}
	skb_pull(skb, sizeof(*hdr));
	return skb;
}
EXPORT_SYMBOL(mrecvskb);

void msocket_recv_throttled(int sock)
{
	struct portq *portq;
	portq = (struct portq *)portq_get(sock);
	if (!portq) {
		pr_err("MSOCK: %s: sock %d not opened!\n",
		       __func__, sock);
		return;
	}

	portq_recv_throttle(portq);
}
EXPORT_SYMBOL(msocket_recv_throttled);

/* unthrottle portq receive by msocket */
void msocket_recv_unthrottled(int sock)
{
	struct portq *portq;
	portq = (struct portq *)portq_get(sock);
	if (!portq) {
		pr_err("MSOCK: %s: sock %d not opened!\n",
		       __func__, sock);
		return;
	}

	portq_recv_unthrottle(portq);
}
EXPORT_SYMBOL(msocket_recv_unthrottled);


/*
 * msocket device driver <-------------------------------------->
 */

#define PROC_CP_FILE_NAME		"driver/msocket_cp"
#define PROC_M3_FILE_NAME		"driver/msocket_m3"

/*
 * This function is called at the beginning of a sequence.
 */
static void *msocket_seq_start(struct seq_file *s, loff_t *pos)
{
	void *v;
	struct portq_group *pgrp = (struct portq_group *)s->private;

	if (pgrp)
		spin_lock_irq(&pgrp->list_lock);
	else
		return NULL;

	v = (void *)(*pos + SEQ_START_TOKEN);

	/* return a non null value to begin the sequence */
	return v;
}

/*
 * This function is called after the beginning of a sequence.
 * It's called until the return is NULL (this ends the sequence).
 */
static void *msocket_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct portq_group *pgrp = (struct portq_group *)s->private;

	if (*pos < pgrp->port_cnt)
		++*pos;
	else
		return NULL;

	v = (void *)(*pos + SEQ_START_TOKEN);

	/* return a non null value to step the sequence */
	return v;
}

/*
 * This function is called at the end of a sequence
 */
static void msocket_seq_stop(struct seq_file *s, void *v)
{
	struct portq_group *pgrp = (struct portq_group *)s->private;
	if (pgrp)
		spin_unlock_irq(&pgrp->list_lock);
}

/*
 * This function is called for each "step" of a sequence
 */
static int msocket_seq_show(struct seq_file *s, void *v)
{
	long pos = (long)v - (long)SEQ_START_TOKEN;
	struct portq_group *pgrp = (struct portq_group *)s->private;

	if (pgrp) {
		struct portq *portq;

		if (!pgrp->is_open || pos >= pgrp->port_cnt)
			return 0;

		portq = pgrp->port_list[pos];

		if (!pos) {
			struct shm_rbctl *rbctl = pgrp->rbctl;

			seq_printf(s, "group name: %s\n", pgrp->name);
			seq_printf(s, "shm_is_local_xmit_stopped: %d\n",
				rbctl->is_ap_xmit_stopped);
			seq_printf(s, "shm_is_remote_xmit_stopped: %d\n",
				rbctl->is_cp_xmit_stopped);
			seq_printf(s, "acipc_local_stopped_num:   %ld\n",
				rbctl->ap_stopped_num);
			seq_printf(s, "acipc_local_resumed_num:   %ld\n",
				rbctl->ap_resumed_num);
			seq_printf(s, "acipc_remote_stopped_num:   %ld\n",
				rbctl->cp_stopped_num);
			seq_printf(s, "acipc_remote_resumed_num:   %ld\n",
				rbctl->cp_resumed_num);
			seq_printf(s, "tx_socket_total:        %d\n",
				rbctl->tx_skbuf_num);
			seq_printf(s, "tx_socket_free:         %d\n",
				shm_free_tx_skbuf_safe(rbctl));
			seq_printf(s, "rx_socket_total:        %d\n",
				rbctl->rx_skbuf_num);
			seq_printf(s, "rx_socket_free:         %d\n",
				shm_free_rx_skbuf_safe(rbctl));

			seq_printf(s, "rx_workq_sched_num:   %u\n",
				pgrp->rx_workq_sched_num);

			seq_puts(s, "\nport  ");
			seq_puts(s,
				"tx_current  tx_request"
				"  tx_sent  tx_drop  tx_queue_max"
				"  rx_current  rx_indicate "
				"  rx_got  rx_queue_max"
				"  local_throttle  local_unthrottle"
				"  remote_throttle  remote_unthrottle\n");
		}

		if (portq) {
			spin_lock(&portq->lock);
			seq_printf(s, "%4d", portq->port);
			seq_printf(s, "%12d", skb_queue_len(&portq->tx_q));
			seq_printf(s, "%12ld", portq->stat_tx_request);
			seq_printf(s, "%9ld", portq->stat_tx_sent);
			seq_printf(s, "%9ld", portq->stat_tx_drop);
			seq_printf(s, "%14ld", portq->stat_tx_queue_max);
			seq_printf(s, "%12d", skb_queue_len(&portq->rx_q));
			seq_printf(s, "%13ld", portq->stat_rx_indicate);
			seq_printf(s, "%9ld", portq->stat_rx_got);
			seq_printf(s, "%14ld", portq->stat_rx_queue_max);
			seq_printf(s, "%16ld", portq->stat_fc_ap_throttle_cp);
			seq_printf(s, "%18ld", portq->stat_fc_ap_unthrottle_cp);
			seq_printf(s, "%16ld", portq->stat_fc_cp_throttle_ap);
			seq_printf(s, "%18ld\n",
				portq->stat_fc_cp_unthrottle_ap);
			spin_unlock(&portq->lock);
		}
	}

	return 0;
}

/**
 * This structure gather "function" to manage the sequence
 *
 */
static const struct seq_operations msocket_seq_ops = {
	.start = msocket_seq_start,
	.next = msocket_seq_next,
	.stop = msocket_seq_stop,
	.show = msocket_seq_show
};

/**
 * This function is called when the /proc file is open.
 *
 */
static int msocket_cp_seq_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &msocket_seq_ops);
	if (!ret)
		((struct seq_file *)file->private_data)->private = &pgrp_cp;
	return ret;
};

static int msocket_m3_seq_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &msocket_seq_ops);
	if (!ret)
		((struct seq_file *)file->private_data)->private = &pgrp_m3;
	return ret;
};

/**
 * This structure gather "function" that manage the /proc file
 *
 */
static const struct file_operations msocket_cp_proc_fops = {
	.owner = THIS_MODULE,
	.open = msocket_cp_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

static const struct file_operations msocket_m3_proc_fops = {
	.owner = THIS_MODULE,
	.open = msocket_m3_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

/* open msocket */
static int msocket_open(struct inode *inode, struct file *filp)
{
	/*
	 * explicit set private_data to NULL, we'll use this pointer to
	 * associate file and portq
	 */
	filp->private_data = NULL;

	return 0;
}

/* open msocket */
static int msockdev_open(struct inode *inode, struct file *filp)
{
	struct portq *portq;
	int port;
	struct cmsockdev_dev *dev;	/* device information */

	dev = container_of(inode->i_cdev, struct cmsockdev_dev, cdev);
	/* Extract Minor Number */
	port = MINOR(dev->cdev.dev);

	portq = portq_open(port);
	if (IS_ERR(portq)) {
		pr_info("MSOCK: binding port %d error, %ld\n",
		       port, PTR_ERR(portq));
		return PTR_ERR(portq);
	} else {
		filp->private_data = portq;
		pr_info("MSOCK: binding port %d, success.\n", port);
		pr_info("MSOCK: port %d is opened by process id:%d (\"%s\")\n",
		       port, current->tgid, current->comm);
		return 0;
	}
	return 0;
}

/* close msocket */
static int msocket_close(struct inode *inode, struct file *filp)
{
	struct portq *portq = filp->private_data;

	int port;
	struct cmsockdev_dev *dev;	/* device information */

	dev = container_of(inode->i_cdev, struct cmsockdev_dev, cdev);
	/* Extract Minor Number */
	port = MINOR(dev->cdev.dev);
	if (portq) {		/* file already bind to portq */
		pr_info(
		       "MSOCK: port %d is closed by process id:%d (\"%s\")\n",
		       portq->port, current->tgid, current->comm);
		portq_close(portq);
	}

	return 0;
}

/* read from msocket */
static ssize_t
msocket_read(struct file *filp, char __user *buf, size_t len, loff_t *f_pos)
{
	struct portq *portq;
	struct sk_buff *skb;
	struct shm_skhdr *hdr;
	int rc = -EFAULT;

	portq = (struct portq *)filp->private_data;
	if (!portq) {
		pr_err("MSOCK: %s: port not bind.\n", __func__);
		return rc;
	}

	skb = portq_recv(portq, true);

	if (IS_ERR(skb)) {
		pr_debug("MSOCK: %s: portq_recv returns %p\n",
		       __func__, skb);
		return PTR_ERR(skb);
	}

	hdr = (struct shm_skhdr *)skb->data;
	if (hdr->length > len) {
		pr_err("MSOCK: %s: error: no enough space.\n",
		       __func__);
		goto err_exit;
	}

	if (copy_to_user(buf, skb_pull(skb, sizeof(*hdr)), hdr->length))
		pr_err("MSOCK: %s: copy_to_user failed.\n", __func__);
	else
		rc = hdr->length;

err_exit:
	kfree_skb(skb);
	return rc;
}

static unsigned int msocket_poll(struct file *filp, poll_table *wait)
{
	struct portq *portq;

	portq = (struct portq *)filp->private_data;

	if (!portq) {
		pr_err("MSOCK: %s: port not bind.\n", __func__);
		return 0;
	}

	return portq_poll(portq, filp, wait);
}

/* write to msocket */
static ssize_t
msocket_write(struct file *filp, const char __user *buf, size_t len,
	      loff_t *f_pos)
{
	struct portq *portq;
	struct sk_buff *skb;
	struct shm_skhdr *hdr;
	int rc = -EFAULT;

	portq = (struct portq *)filp->private_data;
	if (!portq) {
		pr_err("MSOCK: %s: port not bind.\n", __func__);
		return rc;
	}

	if (len > (portq->grp->rbctl->tx_skbuf_size - sizeof(*hdr))) {
		pr_err("MSOCK: %s: port %d, len is %d!!\n",
		       __func__, portq->port, (int)len);
		return rc;
	}

	skb = alloc_skb(len + sizeof(*hdr), GFP_KERNEL);
	if (!skb) {
		pr_err("MSOCK: %s: out of memory.\n", __func__);
		return -ENOMEM;
	}
	skb_reserve(skb, sizeof(*hdr));	/* reserve header space */

	if (copy_from_user(skb_put(skb, len), buf, len)) {
		kfree_skb(skb);
		pr_err("MSOCK: %s: copy_from_user failed.\n",
		       __func__);
		return rc;
	}

	skb_push(skb, sizeof(*hdr));
	hdr = (struct shm_skhdr *)skb->data;
	hdr->address = 0;
	hdr->port = portq->port;
	hdr->checksum = 0;
	hdr->length = len;

	if (!portq->grp->ops->is_synced() || portq_xmit(portq, skb, true) < 0) {
		kfree_skb(skb);
		pr_err("MSOCK: %s: portq xmit error.\n", __func__);
		return -1;
	}

	return len;
}

/*  the ioctl() implementation */
static long msocket_ioctl(struct file *filp,
			  unsigned int cmd, unsigned long arg)
{
	struct portq *portq;
	int port, type = _IOC_TYPE(cmd);

	switch (type) {
	case MSOCKET_IOC_MAGIC:
		if (cmd == MSOCKET_IOC_BIND) {
			port = arg;

			portq = portq_open(port);
			if (IS_ERR(portq)) {
				pr_info("MSOCK: binding port %d error, %p\n",
				       port, portq);
				return (long)portq;
			} else {
				filp->private_data = portq;
				pr_info("MSOCK: binding port %d, success.\n",
				       port);
				pr_info("MSOCK: port %d is opened by process id:%d (\"%s\")\n",
				       port, current->tgid, current->comm);
				return 0;
			}
		} else
			return -ENOIOCTLCMD;
	case MSOCKET_IOC_CP_MAGIC:
		if (cp_is_aponly())
			return -ENODEV;
		else
			return cp_ioctl_handler(cmd, arg);
	case MSOCKET_IOC_M3_MAGIC:
		return m3_ioctl_handler(cmd, arg);
	default:
		return -ENOIOCTLCMD;
	}
}

/* driver methods */
static const struct file_operations msocket_fops = {
	.owner = THIS_MODULE,
	.open = msocket_open,
	.release = msocket_close,
	.read = msocket_read,
	.write = msocket_write,
	.unlocked_ioctl = msocket_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = msocket_ioctl,
#endif
};

/* driver methods */
static const struct file_operations msockdev_fops = {
	.owner = THIS_MODULE,
	.open = msockdev_open,
	.release = msocket_close,
	.read = msocket_read,
	.write = msocket_write,
	.poll = msocket_poll,
	.unlocked_ioctl = msocket_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = msocket_ioctl,
#endif
};

/* misc structure */
static struct miscdevice msocket_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "msocket",
	.fops = &msocket_fops
};

static int msocketDump_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int msocketDump_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t msocketDump_read(struct file *filp, char __user *buf,
				size_t len, loff_t *f_pos)
{
	char temp[256];
	unsigned flag = pgrp_cp.dump_flag;

	sprintf(temp, "0x%08x", flag);
	if (copy_to_user(buf, (void *)&temp, strlen(temp) + 1)) {
		pr_err("MSOCKDUMP: %s: copy_to_user failed.\n",
		       __func__);
		return -EFAULT;
	}
	pr_info("msocketDump:get flag :%s\n", temp);
	return 0;
}

static ssize_t msocketDump_write(struct file *filp, const char __user *buf,
				 size_t len, loff_t *f_pos)
{
	unsigned flag = 0;

	if (kstrtouint_from_user(buf, len, 10, &flag) < 0) {
		pr_err("MSOCKDUMP: %s: kstrtoint error.\n",
			__func__);
		return -EFAULT;
	}
	pr_info("msocketDump:set flag :%08x\n", flag);
	pgrp_cp.dump_flag = flag;
	return len;
}

static const struct file_operations msocketDump_fops = {
	.owner = THIS_MODULE,
	.open = msocketDump_open,
	.release = msocketDump_close,
	.read = msocketDump_read,
	.write = msocketDump_write
};

static struct miscdevice msocketDump_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "msocket_dump",
	.fops = &msocketDump_fops
};

static int cmsockdev_setup_cdev(struct cmsockdev_dev *dev, int index)
{
	int err = 0;
	int devno = MKDEV(cmsockdev_major, cmsockdev_minor + index);

	cdev_init(&dev->cdev, &msockdev_fops);
	dev->cdev.owner = THIS_MODULE;
	err = cdev_add(&dev->cdev, devno, 1);
	/* Fail gracefully if need be */
	if (err)
		pr_notice("Error %d adding cmsockdev%d", err, index);
	return err;
}

/*@cmsockdev_added: the number of successfully added cmsockt devices.
*/
void cmsockdev_cleanup_module(int cmsockdev_added)
{
	int i;
	dev_t devno = MKDEV(cmsockdev_major, cmsockdev_minor);

	/* Get rid of our char dev entries */
	if (cmsockdev_devices) {
		for (i = 0; i < cmsockdev_added; i++) {
			cdev_del(&cmsockdev_devices[i].cdev);
			device_destroy(cmsockdev_class,
				       MKDEV(cmsockdev_major,
					     cmsockdev_minor + i));
		}
		kfree(cmsockdev_devices);
	}

	class_destroy(cmsockdev_class);

	/* cleanup_module is never called if registering failed */
	unregister_chrdev_region(devno, cmsockdev_nr_devs);

}

int cmsockdev_init_module(void)
{
	int result, i = 0;
	dev_t dev = 0;
	char name[256];

	/*
	 * Get a range of minor numbers to work with, asking for a dynamic
	 * major unless directed otherwise at load time.
	 */
	if (cmsockdev_major) {
		dev = MKDEV(cmsockdev_major, cmsockdev_minor);
		result =
		    register_chrdev_region(dev, cmsockdev_nr_devs, "cmsockdev");
	} else {
		result =
		    alloc_chrdev_region(&dev, cmsockdev_minor,
					cmsockdev_nr_devs, "cmsockdev");
		cmsockdev_major = MAJOR(dev);
	}

	if (result < 0) {
		pr_warn("cmsockdev: can't get major %d\n",
		       cmsockdev_major);
		return result;
	}

	/*
	 * allocate the devices -- we can't have them static, as the number
	 * can be specified at load time
	 */
	cmsockdev_devices =
	    kzalloc(cmsockdev_nr_devs * sizeof(struct cmsockdev_dev),
		    GFP_KERNEL);
	if (!cmsockdev_devices) {
		result = -ENOMEM;
		goto fail;
	}

	/* Initialize each device. */
	cmsockdev_class = class_create(THIS_MODULE, "cmsockdev");
	for (i = 0; i < cmsockdev_nr_devs; i++) {
		sprintf(name, "%s%d", "cmsockdev", cmsockdev_minor + i);
		device_create(cmsockdev_class, NULL,
			      MKDEV(cmsockdev_major, cmsockdev_minor + i), NULL,
			      name);
		result = cmsockdev_setup_cdev(&cmsockdev_devices[i], i);
		if (result < 0)
			goto fail;

	}

	/* At this point call the init function for any friend device */

	return 0;		/* succeed */

fail:
	cmsockdev_cleanup_module(i);

	return result;
}

static int msocket_debugfs_init(void)
{
	tel_debugfs_root_dir = tel_debugfs_get();
	if (!tel_debugfs_root_dir)
		return -1;

	msocket_debugfs_root_dir = debugfs_create_dir("msocket",
		tel_debugfs_root_dir);
	if (IS_ERR_OR_NULL(msocket_debugfs_root_dir))
		goto put_rootfs;

	return 0;

put_rootfs:
	tel_debugfs_put(tel_debugfs_root_dir);
	tel_debugfs_root_dir = NULL;

	return -1;
}

static void msocket_debugfs_exit(void)
{
	debugfs_remove(msocket_debugfs_root_dir);
	msocket_debugfs_root_dir = NULL;
	tel_debugfs_put(tel_debugfs_root_dir);
	tel_debugfs_root_dir = NULL;
}


/* module initialization */
static int __init msocket_init(void)
{
	int rc;

	rc = msocket_debugfs_init();
	if (rc < 0) {
		pr_err("%s: msocket debugfs init failed\n", __func__);
		goto exit;
	}

	/* create proc file */
	if (!proc_create(PROC_CP_FILE_NAME, 0644, NULL, &msocket_cp_proc_fops)) {
		pr_err("%s: create proc failed\n", __func__);
		rc = -1;
		goto proc_err;
	}

	if (!proc_create(PROC_M3_FILE_NAME, 0644, NULL, &msocket_m3_proc_fops)) {
		pr_err("%s: create proc failed\n", __func__);
		rc = -1;
		remove_proc_entry(PROC_CP_FILE_NAME, NULL);
		goto proc_err;
	}

	/* port queue init */
	rc = portq_init(portq_grp, ARRAY_SIZE(portq_grp));
	if (rc < 0) {
		pr_err("%s: portq init failed %d\n",
			__func__, rc);
		goto portq_err;
	}

	/* register misc device */
	rc = misc_register(&msocket_dev);
	if (rc < 0) {
		pr_err("%s: register msock driver failed %d\n",
			__func__, rc);
		goto misc_err;
	}

	rc = misc_register(&msocketDump_dev);
	if (rc < 0) {
		pr_err("%s: register msock dump driver failed %d\n",
			__func__, rc);
		goto msocketDump_err;
	}

	rc = cmsockdev_init_module();
	if (rc < 0) {
		pr_err("%s: init cmoskdev failed %d\n",
			__func__, rc);
		goto cmsock_err;
	}

	return 0;

cmsock_err:
	misc_deregister(&msocketDump_dev);
msocketDump_err:
	misc_deregister(&msocket_dev);
misc_err:
	portq_exit();
portq_err:
	remove_proc_entry(PROC_CP_FILE_NAME, NULL);
	remove_proc_entry(PROC_M3_FILE_NAME, NULL);
proc_err:
	msocket_debugfs_exit();
exit:
	return rc;
}

/* module exit */
static void __exit msocket_exit(void)
{
	portq_exit();
	cmsockdev_cleanup_module(cmsockdev_nr_devs);
	misc_deregister(&msocketDump_dev);
	misc_deregister(&msocket_dev);
	remove_proc_entry(PROC_CP_FILE_NAME, NULL);
	remove_proc_entry(PROC_M3_FILE_NAME, NULL);
	msocket_debugfs_exit();
}

module_init(msocket_init);
module_exit(msocket_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION("Marvell MSocket Driver");
