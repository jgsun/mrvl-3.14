/*
    Marvell PXA9XX ACIPC-MSOCKET driver for Linux
    Copyright (C) 2012 Marvell International Ltd.

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

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/workqueue.h>
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/pxa9xx_acipc.h>

#include "msocket.h"
#include "shm.h"
#include "shm_share.h"
#include "tel_trace.h"
#include "pxa_cp_load.h"
#include "pxa_cp_load_ioctl.h"

#define RX_ENQUEUE_RATELIMIT (8192)
/* max diag rx queue length, in byte */
static uint32_t max_rx_q_size = 4 * 1024 * 1024;
module_param_named(diag_max_rx_q_size, max_rx_q_size, uint, S_IWUSR | S_IRUGO);

struct direct_rbctl direct_rbctl;
static dev_t dev_nr;
static int direct_dump_flag;

struct buffer_item {
	struct list_head entry;
	unsigned len;
	char buf[];
};

struct direct_rbctl {
	int refcount;
	struct cdev dev;
	struct class *rbclass;
	struct shm_rbctl *rbctl;
	bool is_ap_recv_empty;

	struct list_head rx_q;	/* rx packet queue */
	unsigned rx_q_size;
	unsigned max_rx_q_size;

	struct workqueue_struct *rx_wq; /* rx workqueue */
	struct work_struct rx_work; /* rx work */

	/*
	 * wait queue and lock
	 */
	wait_queue_head_t rb_rx_wq;
	spinlock_t rb_rx_lock;

	unsigned long stat_tx_sent;
	unsigned long stat_tx_drop;
	unsigned long stat_rx_fail;
	unsigned long stat_rx_drop;
	unsigned long stat_rx_got;
	unsigned long stat_interrupt;
	unsigned long stat_broadcast_msg;
};

struct diagheader {
	u16 seqNo;
	u16 packetlen;
	u32 msgType;
};/* don't change the definition. variable definition order sensitive */

struct diagmsgheader {
	struct diagheader diagHeader;
	unsigned procId;
};

/* DIAG share memory socket header structure */
struct direct_rb_skhdr {
	unsigned int length;		/* payload length */
};

/* notify cp diag that new packet available in the socket buffer */
static inline void acipc_notify_diag_packet_sent(void)
{
	acipc_event_set(ACIPC_SHM_DIAG_PACKET_NOTIFY);
}

static inline bool direct_rb_schedule_rx(struct direct_rbctl *dir_ctl)
{
	bool ret = false;
	unsigned long flags;

	spin_lock_irqsave(&dir_ctl->rb_rx_lock, flags);
	if (dir_ctl->refcount) {
		queue_work(dir_ctl->rx_wq, &dir_ctl->rx_work);
		ret = true;
	}
	spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);

	return ret;
}

static inline struct buffer_item *alloc_buffer_item(unsigned len, gfp_t flags)
{
	struct buffer_item *item = kmalloc(sizeof(*item) + len, flags);
	if (!item)
		return NULL;

	item->len = len;
	INIT_LIST_HEAD(&item->entry);
	return item;
}

static inline bool rx_enqueue(struct direct_rbctl *dir_ctl,
	struct buffer_item *item, bool force)
{
	bool ret = false;

	/*
	 * with force flag, we do not need to check the queue
	 * length, to make sure we can enqueue control messages
	 * in every case
	 */
	if (!force && dir_ctl->rx_q_size > dir_ctl->max_rx_q_size) {
		if (dir_ctl->stat_rx_drop++ % RX_ENQUEUE_RATELIMIT == 0)
			pr_err("%s: rx queue is full %lu times\n",
				__func__, dir_ctl->stat_rx_drop);
		ret = false;
	} else {
		/* add to rx queue */
		list_add_tail(&item->entry, &dir_ctl->rx_q);
		dir_ctl->rx_q_size += item->len;
		ret = true;
	}

	return ret;
}

static inline struct buffer_item *rx_dequeue(struct direct_rbctl *dir_ctl)
{
	/* delete message from queue */
	struct buffer_item *item =
		list_first_entry(&dir_ctl->rx_q, struct buffer_item, entry);
	list_del(&item->entry);
	dir_ctl->rx_q_size -= item->len;
	return item;
}

static int msocketDirectDump_open(struct inode *inode, struct file *filp)
{
	filp->private_data = (void *)(long)direct_dump_flag;
	return 0;
}

static int msocketDirectDump_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t msocketDirectDump_read(struct file *filp, char __user *buf,
				      size_t len, loff_t *f_pos)
{
	char temp[256];
	int flag = direct_dump_flag;

	sprintf(temp, "0x%08x", flag);
	if (copy_to_user(buf, (void *)&temp, strlen(temp) + 1)) {
		pr_err("%s: copy_to_user failed.\n", __func__);
		return -EFAULT;
	}
	pr_info("%s: get flag :%s\n", __func__, temp);

	return 0;
}

static ssize_t msocketDirectDump_write(struct file *filp,
				       const char __user *buf, size_t len,
				       loff_t *f_pos)
{
	int flag = 0;
	int flagSave;

	if (kstrtoint_from_user(buf, len, 10, &flag) < 0) {
		pr_err("%s: kstrtoint error\n", __func__);
		return -EFAULT;
	}

	flagSave = flag;
	pr_info("%s: set flag :0x%08x\n", __func__, flag);

	if (flag & 0x1) {
		struct direct_rbctl *drbctl = &direct_rbctl;

		if (direct_rb_schedule_rx(drbctl)) {
			pr_info("%s: cp_wptr=%d, ap_rptr=%d\n",
				__func__,
				drbctl->rbctl->skctl_va->cp_wptr,
				drbctl->rbctl->skctl_va->ap_rptr);
		}
	}

	direct_dump_flag = flagSave;

	return len;
}

static const struct file_operations msocketDirectDump_fops = {
	.owner = THIS_MODULE,
	.open = msocketDirectDump_open,
	.release = msocketDirectDump_close,
	.read = msocketDirectDump_read,
	.write = msocketDirectDump_write
};

static struct miscdevice msocketDirectDump_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "diag_dump",
	.fops = &msocketDirectDump_fops
};

static size_t diag_get_packet_length(const unsigned char *hdr)
{
	struct direct_rb_skhdr *skhdr = (struct direct_rb_skhdr *)hdr;
	return skhdr->length + sizeof(*skhdr);
}

struct shm_callback diag_shm_cb = {
	.get_packet_length = diag_get_packet_length,
};

struct shm_rbctl diag_rbctl = {
	.name = "cp-diag",
	.cbs = &diag_shm_cb,
	.priv = &direct_rbctl,
	.va_lock = __MUTEX_INITIALIZER(diag_rbctl.va_lock),
};

static void direct_rb_rx_worker(struct work_struct *work)
{
	struct direct_rbctl *dir_ctl = (struct direct_rbctl *)
		container_of(work, struct direct_rbctl, rx_work);
	struct shm_rbctl *rbctl = dir_ctl->rbctl;
	struct shm_skctl *skctl = rbctl->skctl_va;
	struct direct_rb_skhdr *hdr;
	struct buffer_item *item;
	int slot;
	unsigned long flags;
	int packet_count;
	int count;

	packet_count = 0;

	while (cp_is_synced) {
		if (shm_is_recv_empty(rbctl))
			break;

		slot = shm_get_next_rx_slot(rbctl, skctl->ap_rptr);

		hdr = (struct direct_rb_skhdr *)
			SHM_PACKET_PTR(rbctl->rx_va, slot,
			rbctl->rx_skbuf_size);

		shm_invalidate_dcache(rbctl->rx_cacheable, hdr,
			rbctl->rx_skbuf_size);

		count = hdr->length + sizeof(*hdr);

		if (count > rbctl->rx_skbuf_size) {
			pr_emerg("%s: invalid packet slot = %d, count = %d\n",
				__func__, slot, count);
			dir_ctl->stat_rx_fail++;
			goto error_length;
		}

		item = alloc_buffer_item(hdr->length, GFP_KERNEL);
		if (!item) {
			/* don't known how to do better, just return */
			pr_err_ratelimited("%s: out of memory.\n", __func__);
			break;
		}
		memcpy(item->buf, (char *)hdr + sizeof(*hdr), hdr->length);

		spin_lock_irqsave(&dir_ctl->rb_rx_lock, flags);
		if (!rx_enqueue(dir_ctl, item, false)) {
			/*
			 * OK, our rx queue is already full
			 * break out, and wait cp to interrupt again?
			 */
			spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);
			kfree(item);
			break;
		}

		/* wake up user space asap */
		if (dir_ctl->is_ap_recv_empty) {
			dir_ctl->is_ap_recv_empty = false;
			wake_up_interruptible(&(dir_ctl->rb_rx_wq));
		}

		spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);

error_length:
		/* advance reader pointer */
		skctl->ap_rptr = slot;
		packet_count++;
	}

	spin_lock_irqsave(&dir_ctl->rb_rx_lock, flags);
	if (packet_count && dir_ctl->is_ap_recv_empty) {
		dir_ctl->is_ap_recv_empty = false;
		wake_up_interruptible(&(dir_ctl->rb_rx_wq));
	}
	spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);
}

static int direct_rb_open(struct inode *inode, struct file *filp)
{
	unsigned long flags;
	struct direct_rbctl *dir_ctl = &direct_rbctl;

	spin_lock_irqsave(&dir_ctl->rb_rx_lock, flags);
	if (dir_ctl->refcount > 0) {
		dir_ctl->refcount++;
		goto exit;
	}
	dir_ctl->refcount++;
	dir_ctl->stat_tx_sent = 0;
	dir_ctl->stat_tx_drop = 0;
	dir_ctl->stat_rx_fail = 0;
	dir_ctl->stat_rx_got = 0;
	dir_ctl->stat_rx_drop = 0;
	dir_ctl->stat_interrupt = 0;
	dir_ctl->stat_broadcast_msg = 0;
	dir_ctl->rx_q_size = 0;
	dir_ctl->max_rx_q_size = max_rx_q_size;
	INIT_LIST_HEAD(&dir_ctl->rx_q);
exit:
	spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);
	return 0;
}

static int direct_rb_close(struct inode *inode, struct file *filp)
{
	unsigned long flags;
	struct direct_rbctl *rbctl = &direct_rbctl;

	spin_lock_irqsave(&rbctl->rb_rx_lock, flags);
	if (rbctl->refcount > 0)
		rbctl->refcount--;
	if (rbctl->refcount == 0) {
		struct buffer_item *item;
		while (!list_empty(&rbctl->rx_q)) {
			item = rx_dequeue(rbctl);
			kfree(item);
		}
	}
	spin_unlock_irqrestore(&rbctl->rb_rx_lock, flags);
	return 0;
}

#define DIAG_TX_RETRY_DELAY_MS 10
static ssize_t direct_rb_write(struct file *file, const char __user *buf,
		       size_t len, loff_t *ppos)
{
	struct direct_rbctl *dir_ctl = &direct_rbctl;
	struct direct_rb_skhdr *hdr;
	struct shm_skctl *skctl;
	int slot;

	if (!cp_is_synced)
		return -EPIPE;

	skctl = dir_ctl->rbctl->skctl_va;

	if (len > dir_ctl->rbctl->tx_skbuf_size - sizeof(*hdr)) {
		pr_err("%s: len is %zu larger than tx_skbuf_size\n",
		       __func__, len);
		dir_ctl->stat_tx_drop++;
		return -EINVAL;
	}

	/* as no flow control for the diag ring-buffer, just delay
	 * the tx in case the ring buffer is full and then check again
	 */
	/* if ring buffer is full */
	while (shm_is_xmit_full(dir_ctl->rbctl))
		msleep(DIAG_TX_RETRY_DELAY_MS);

	slot = shm_get_next_tx_slot(dir_ctl->rbctl, skctl->ap_wptr);

	hdr =
	    (struct direct_rb_skhdr *)SHM_PACKET_PTR(
			    dir_ctl->rbctl->tx_va, slot,
			    dir_ctl->rbctl->tx_skbuf_size);
	hdr->length = len;
	if (copy_from_user((char *)hdr + sizeof(*hdr), buf, len)) {
		pr_err("MSOCK: %s: copy_from_user failed.\n", __func__);
		dir_ctl->stat_tx_drop++;
		return -EFAULT;
	}
	trace_drb_xmit(sizeof(*hdr) + len);

	shm_flush_dcache(dir_ctl->rbctl->tx_cacheable, hdr, sizeof(*hdr) + len);
	dir_ctl->stat_tx_sent++;
	skctl->ap_wptr = slot;	/* advance pointer index */

	acipc_notify_diag_packet_sent();
	return len;
}

static ssize_t direct_rb_read(struct file *file, char __user *buf,
		       size_t len, loff_t *ppos)
{
	struct direct_rbctl *dir_ctl = &direct_rbctl;
	struct buffer_item *item;
	int rc = -EFAULT;
	unsigned long flags;
	ssize_t packet_len;

	spin_lock_irqsave(&dir_ctl->rb_rx_lock, flags);

	while (list_empty(&dir_ctl->rx_q)) {
		dir_ctl->is_ap_recv_empty = true;

		/* release the lock before wait */
		spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);

		if (wait_event_interruptible(dir_ctl->rb_rx_wq,
					     !dir_ctl->is_ap_recv_empty)) {
			/* signal: tell the fs layer to handle it */
			return -ERESTARTSYS;
		}

		/* otherwise loop, but first reacquire the lock */
		spin_lock_irqsave(&dir_ctl->rb_rx_lock, flags);
	}

	/* delete message from queue */
	item = rx_dequeue(dir_ctl);

	/* release the lock */
	spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);

	if (copy_to_user(buf, item->buf, item->len)) {
		pr_err("%s: copy_to_user failed.\n", __func__);
		dir_ctl->stat_rx_fail++;
		/* push back the packet? */
		kfree(item);
		return rc;
	}

	/* save packet length before advancing reader pointer */
	packet_len = item->len;
	trace_drb_recv(item->len);

	kfree(item);

	dir_ctl->stat_rx_got++;

	return packet_len;
}

static unsigned int direct_rb_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;
	struct direct_rbctl *dir_ctl = &direct_rbctl;

	poll_wait(filp, &dir_ctl->rb_rx_wq, wait);

	if (!list_empty(&dir_ctl->rx_q))
		mask |= POLLIN | POLLRDNORM;

	if (cp_is_synced && !shm_is_xmit_full(dir_ctl->rbctl))
		mask |= POLLOUT | POLLWRNORM;

	return mask;
}

static void msocket_dump_direct_rb(void)
{
	struct direct_rbctl *dir_ctl = &direct_rbctl;

	pr_err("diag buffer tx_sent: %lu, tx_drop: %lu;"
		" rx_got: %lu, rx_fail: %lu, rx_drop: %lu;"
		" interrupt: %lu, broadcast_msg: %lu\n",
		dir_ctl->stat_tx_sent, dir_ctl->stat_tx_drop,
		dir_ctl->stat_rx_got, dir_ctl->stat_rx_fail,
		dir_ctl->stat_rx_drop, dir_ctl->stat_interrupt,
		dir_ctl->stat_broadcast_msg);
}

static void direct_rb_broadcast_msg(unsigned proc)
{
	struct direct_rbctl *dir_ctl = &direct_rbctl;
	unsigned long flags;

	struct buffer_item *item;
	int msg_size;

	struct diagmsgheader *pDiagMsgHeader;

	spin_lock_irqsave(&dir_ctl->rb_rx_lock, flags);
	if (dir_ctl->refcount == 0) {
		spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);
		return;
	}

	msg_size = sizeof(struct diagmsgheader);

	item = alloc_buffer_item(msg_size, GFP_ATOMIC);

	if (!item) {
		pr_err("%s: alloc_skb error\n", __func__);
		spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);
		return;
	}

	pDiagMsgHeader = (struct diagmsgheader *)item->buf;
	pDiagMsgHeader->diagHeader.packetlen =
		sizeof(pDiagMsgHeader->procId);
	pDiagMsgHeader->diagHeader.seqNo = 0;
	pDiagMsgHeader->diagHeader.msgType = proc;
	pDiagMsgHeader->procId = proc;

	rx_enqueue(dir_ctl, item, true);

	if (dir_ctl->is_ap_recv_empty) {
		dir_ctl->is_ap_recv_empty = false;
		wake_up_interruptible(&(dir_ctl->rb_rx_wq));
	}

	spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);

	dir_ctl->stat_broadcast_msg++;

	if (proc == MsocketLinkupProcId) {
		/*
		 * Now both AP and CP will not send packet to
		 * ring buffer or receive packet from ring
		 * buffer, so cleanup any packet in ring buffer
		 * and initialize some key data structure to the
		 * beginning state otherwise user space process
		 * may occur error
		 */
		shm_rb_data_init(dir_ctl->rbctl);
	} else if (proc == MsocketLinkdownProcId) {
		/*
		 * flush workqueue here to make sure all the work
		 * is done after link down
		 */
		flush_workqueue(dir_ctl->rx_wq);
		msocket_dump_direct_rb();
	}
}

/* diag new packet arrival interrupt */
static u32 acipc_cb_diag_cb(u32 status)
{
	if (direct_rb_schedule_rx(&direct_rbctl)) {
		__pm_wakeup_event(&acipc_wakeup, 2000);
		direct_rbctl.stat_interrupt++;
	}
	return 0;
}

/* acipc_init is used to register interrupt call-back function */
static inline void diag_acipc_init(void)
{
	/* we do not check any return value */
	acipc_event_bind(ACIPC_SHM_DIAG_PACKET_NOTIFY, acipc_cb_diag_cb,
		       ACIPC_CB_NORMAL, NULL);
}

/* acipc_exit used to unregister interrupt call-back function */
static inline void diag_acipc_exit(void)
{
	acipc_event_unbind(ACIPC_SHM_DIAG_PACKET_NOTIFY);
}

static int cp_link_status_notifier_func(struct notifier_block *this,
	unsigned long code, void *cmd)
{
	direct_rb_broadcast_msg(code);
	return 0;
}

static struct notifier_block cp_link_status_notifier = {
	.notifier_call = cp_link_status_notifier_func,
};

#define SHM_SKBUF_SIZE		2048	/* maximum packet size */
static int shm_param_init(const struct cpload_cp_addr *addr)
{
	if (!addr)
		return -1;

	/* diag ring buffer */
	diag_rbctl.skctl_pa = addr->diag_skctl_pa;

	diag_rbctl.tx_skbuf_size = SHM_SKBUF_SIZE;
	diag_rbctl.rx_skbuf_size = SHM_SKBUF_SIZE;

	diag_rbctl.tx_pa = addr->diag_tx_pa;
	diag_rbctl.rx_pa = addr->diag_rx_pa;

	diag_rbctl.tx_total_size = addr->diag_tx_total_size;
	diag_rbctl.rx_total_size = addr->diag_rx_total_size;

	diag_rbctl.tx_skbuf_num =
		diag_rbctl.tx_total_size /
		diag_rbctl.tx_skbuf_size;
	diag_rbctl.rx_skbuf_num =
		diag_rbctl.rx_total_size /
		diag_rbctl.rx_skbuf_size;

	diag_rbctl.tx_skbuf_low_wm =
		(diag_rbctl.tx_skbuf_num + 1) / 4;
	diag_rbctl.rx_skbuf_low_wm =
		(diag_rbctl.rx_skbuf_num + 1) / 4;

	return 0;
}

static int cp_mem_set_notifier_func(struct notifier_block *this,
	unsigned long code, void *cmd)
{
	struct cpload_cp_addr *addr = (struct cpload_cp_addr *)cmd;

	if (!addr->first_boot)
		shm_rb_exit(direct_rbctl.rbctl);

	shm_param_init(addr);
	if (shm_rb_init(direct_rbctl.rbctl,
			msocket_debugfs_root_dir) < 0)
		pr_err("%s: init diag rbctl failed\n", __func__);

	return 0;
}

static struct notifier_block cp_mem_set_notifier = {
	.notifier_call = cp_mem_set_notifier_func,
};

static const struct file_operations direct_rb_fops = {
	.owner = THIS_MODULE,
	.open = direct_rb_open,
	.release = direct_rb_close,
	.read = direct_rb_read,
	.write = direct_rb_write,
	.poll = direct_rb_poll
};

static int diag_setup_cdev(struct direct_rbctl *dir_ctl)
{
	int rc;
	struct device *dev;

	rc = alloc_chrdev_region(&dev_nr, 0, 1, "diagdev");
	if (rc < 0)
		return rc;
	cdev_init(&dir_ctl->dev, &direct_rb_fops);
	dir_ctl->dev.owner = THIS_MODULE;
	rc = cdev_add(&dir_ctl->dev, dev_nr, 1);
	if (rc < 0)
		goto exit_cdev;
	dir_ctl->rbclass = class_create(THIS_MODULE, "diagdev");
	if (IS_ERR(dir_ctl->rbclass)) {
		rc = PTR_ERR(dir_ctl->rbclass);
		goto exit_class;
	}
	dev = device_create(dir_ctl->rbclass, NULL, dev_nr, NULL, "diagdev");
	if (IS_ERR(dev)) {
		rc = PTR_ERR(dev);
		goto exit_dev;
	}
	return 0;

exit_dev:
	class_destroy(dir_ctl->rbclass);
exit_class:
	cdev_del(&dir_ctl->dev);
exit_cdev:
	unregister_chrdev_region(dev_nr, 1);
	return rc;
}

/* direct_rb_init */
static int __init direct_rb_init(void)
{
	int rc = -1;
	struct direct_rbctl *dir_ctl = &direct_rbctl;

	dir_ctl->rbctl = &diag_rbctl;
	init_waitqueue_head(&(dir_ctl->rb_rx_wq));
	spin_lock_init(&dir_ctl->rb_rx_lock);
	dir_ctl->refcount = 0;
	dir_ctl->is_ap_recv_empty = true;

	INIT_WORK(&dir_ctl->rx_work, direct_rb_rx_worker);
	dir_ctl->rx_wq = create_singlethread_workqueue("diag_wq");

	rc = misc_register(&msocketDirectDump_dev);
	if (rc < 0)
		goto exit;

	register_cp_link_status_notifier(&cp_link_status_notifier);
	register_cp_mem_set_notifier(&cp_mem_set_notifier);
	diag_acipc_init();
	rc = diag_setup_cdev(dir_ctl);
	if (rc < 0) {
		diag_acipc_exit();
		unregister_cp_link_status_notifier(&cp_link_status_notifier);
		unregister_cp_mem_set_notifier(&cp_mem_set_notifier);
		misc_deregister(&msocketDirectDump_dev);
		goto exit;
	}

	return 0;

exit:
	destroy_workqueue(dir_ctl->rx_wq);
	return rc;
}

/* direct_rb_exit */
static void __exit direct_rb_exit(void)
{
	unsigned long flags;
	struct direct_rbctl *dir_ctl = &direct_rbctl;

	destroy_workqueue(dir_ctl->rx_wq);
	spin_lock_irqsave(&dir_ctl->rb_rx_lock, flags);
	dir_ctl->refcount = 0;
	spin_unlock_irqrestore(&dir_ctl->rb_rx_lock, flags);

	diag_acipc_exit();
	unregister_cp_link_status_notifier(&cp_link_status_notifier);
	unregister_cp_mem_set_notifier(&cp_mem_set_notifier);
	misc_deregister(&msocketDirectDump_dev);
	device_destroy(dir_ctl->rbclass, dev_nr);
	class_destroy(dir_ctl->rbclass);
	cdev_del(&dir_ctl->dev);
	unregister_chrdev_region(dev_nr, 1);
}

module_init(direct_rb_init);
module_exit(direct_rb_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION("Marvell Diag Buffer");
