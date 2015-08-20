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

#include <linux/types.h>
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
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <linux/cache.h>
#include <linux/llist.h>
#include <linux/pxa9xx_acipc.h>
#include <linux/compiler.h>
#include <linux/static_key.h>
#include "tel_trace.h"
#include "debugfs.h"
#include "pxa_cp_load.h"
#include "pxa_cp_load_ioctl.h"
#include "data_path_common.h"
#include "psdatastub.h"
#include "psd_shm_v2.h"
#include "psd_rb_v2.h"
#include "allocator.h"

#define CP_DATA_ALIGN_SIZE 64
#define CP_UL_HEADROOM 64
/* cache line aligned */
#define DATA_ALIGN_SIZE max(SMP_CACHE_BYTES, CP_DATA_ALIGN_SIZE)

#define QUEUE_OFFSET 1

#define MAX_PENDING_RECLAIM_REQ 32

#define RX_DIRECT_FREE

/*
 * the default channel length for UL
 * total number is 2 * PSD_UL_CH_CNT * 512
 */
const u16 ul_defl_chan_len[PSD_UL_CH_CNT] = {
	1024, 1024, 512, 512, 256, 256, 256, 256
};
const u16 ul_high_chan_len[PSD_UL_CH_CNT] = {
	1024, 1024, 512, 512, 256, 256, 256, 256
};

/* 0x10 */
#define ACIPC_PS_BUFFER_LWM_INT ACIPC_RINGBUF_PSD_TX_STOP
/* 0x20 */
#define ACIPC_PS_CHAN_STATUS_INT ACIPC_RINGBUF_PSD_TX_RESUME
/* 0x40 */
#define ACIPC_PS_DATA_START_INT ACIPC_SHM_PSD_PACKET_NOTIFY

struct data_path_stat {
	u32 rx_bytes;
	u32 rx_packets;
	u32 rx_interrupts;
	u32 rx_sched_cnt;

	u32 tx_bytes;
	u32 tx_packets[PSD_QUEUE_CNT];
	u32 tx_interrupts;
};

struct data_path {
	atomic_t state;

	const char *name;
	struct dentry *dentry;

	struct psd_rbctl *rbctl;

	struct tmem_allocator *allocator;

	struct tasklet_struct rx_tl;

	/* reclaim workqueue to reclaim tx memory */
	struct workqueue_struct *reclaim_wq;
	struct work_struct reclaim_work;
	int pending_reclaim_req;
	u32 max_pending_reclaim_req;

	/* free workqueue to free rx memory */
	struct workqueue_struct *free_wq;
	struct work_struct free_work;
	struct llist_head free_list;

	struct mutex rx_copy_lock;
	struct static_key rx_copy;
	bool copy_on_rx;

	/* stat */
	struct data_path_stat stat;
};

struct free_entry {
	struct llist_node llnode;
	struct free_descriptor desc;
	struct data_path *dp;
};

enum data_path_state {
	dp_state_idle,
	dp_state_opening,
	dp_state_opened,
	dp_state_closing,
};

/*
 * as we do rx in interrupt context, we should avoid lock up the box
 */
#define MAX_RX_SHOTS 32

static struct wakeup_source dp_rx_wakeup;
static struct wakeup_source dp_acipc_wakeup;
static struct data_path data_path;

static inline void notify_data_start(void)
{
	acipc_event_set(ACIPC_PS_DATA_START_INT);
}

static inline void notify_cp_chan_status_changed(void)
{
	pr_warn_ratelimited("PSD: %s!!!\n", __func__);
	acipc_event_set(ACIPC_PS_CHAN_STATUS_INT);
}

static inline void notify_cp_buffer_lwm(void)
{
	pr_warn_ratelimited("PSD: %s!!!\n", __func__);
	acipc_event_set(ACIPC_PS_BUFFER_LWM_INT);
}

static inline void dp_schedule_rx(struct data_path *dp)
{
	if (dp && atomic_read(&dp->state) == dp_state_opened)
		tasklet_schedule(&dp->rx_tl);
}

static inline void schedule_reclaim(struct data_path *dp)
{
	if (likely(atomic_read(&dp->state) == dp_state_opened))
		queue_work(dp->reclaim_wq, &dp->reclaim_work);
}

static inline void schedule_free(struct data_path *dp)
{
	if (likely(atomic_read(&dp->state) == dp_state_opened))
		queue_work(dp->free_wq, &dp->free_work);
}

/* to copy from/to free_descriptor */
static inline void *memcpy_free_desc(void *dst, const void *src,
	size_t len)
{
	BUG_ON(len != 8);

	*(u64 *)dst = *(u64 *)src;

	return dst;
}

/* copy dl_descriptor/ul_descriptor to share memory */
static inline void *memcpy_desc_to_shm(void *dst, const void *src,
	size_t len)
{
	BUG_ON(len != 12);

	if ((long)dst & 7) {
		*(u32 *)dst = *(u32 *)src;
		*(u64 *)(dst + 4) = *(u64 *)(src + 4);
	} else {
		*(u64 *)dst = *(u64 *)src;
		*(u32 *)(dst + 8) = *(u32 *)(src + 8);
	}

	return dst;
}

/* copy dl_descriptor/ul_descriptor from share memory */
static inline void *memcpy_desc_from_shm(void *dst, const void *src,
	size_t len)
{
	BUG_ON(len != 12);

	if ((long)src & 7) {
		*(u32 *)dst = *(u32 *)src;
		*(u64 *)(dst + 4) = *(u64 *)(src + 4);
	} else {
		*(u64 *)dst = *(u64 *)src;
		*(u32 *)(dst + 8) = *(u32 *)(src + 8);
	}

	return dst;
}

static inline bool get_next_free_queue_slot(struct data_path *dp,
	int wptr, int *slot)
{
	int new_wptr = __shm_get_next_slot(PSD_DF_CH_TOTAL_LEN, wptr);

	if (atomic_cmpxchg(&dp->rbctl->local_dl_free_wptr, wptr, new_wptr)
		== wptr) {
		*slot = new_wptr;
		return true;
	}

	return false;
}

static inline void put_next_free_queue_slot(struct data_path *dp,
	int __maybe_unused slot)
{
	struct psd_rbctl *rbctl = dp->rbctl;
	volatile struct psd_skctl *skctl = rbctl->skctl_va;

	int wptr, new_cwptr, cwptr;
	int distance;

	/* update the committed number */
	do {
		cwptr = atomic_read(&rbctl->local_committed_dl_free_wptr);
		new_cwptr = __shm_get_next_slot(PSD_DF_CH_TOTAL_LEN, cwptr);
	} while (atomic_cmpxchg(&rbctl->local_committed_dl_free_wptr,
			cwptr, new_cwptr) != cwptr);

	wptr = atomic_read(&rbctl->local_dl_free_wptr);

	distance = __shm_free_slot(wptr, skctl->ds.free_wptr,
		PSD_DF_CH_TOTAL_LEN);
	/*
	 * compare the committed wtpr and current wptr, if they are equal,
	 * means we do not have any slot held by other one, commit the
	 * value to shm to let CP know
	 */
	if (wptr == new_cwptr) {
		/*
		 * we may be interrupted by someone
		 * double confirm we are still in the front of wptr
		 */
		if (distance < 64)
			skctl->ds.free_wptr = wptr;
	} else {
		/*
		 * sometimes, we may not have chance to update the wptr in
		 * share memory, process all the pending slot here
		 * this is the slow path, should not happen!!!
		 */
		if (unlikely(distance > 32 && distance < 64)) {
			unsigned long flags;

			pr_warn_ratelimited("%s: so many free slots are pending\n",
				__func__);
			if (spin_trylock_irqsave(&rbctl->free_lock, flags)) {
				int i = skctl->ds.free_wptr;

				while (1) {
					i = __shm_get_next_slot(PSD_DF_CH_TOTAL_LEN, i);
					if (*(u32 *)(skctl->ds.free_desc[i].buffer_offset
							+ rbctl->rx_va) != SLOT_FREE_FLAG)
						break;
					skctl->ds.free_wptr = i;
				}
				spin_unlock_irqrestore(&rbctl->free_lock, flags);
			}
		}
	}
}

static bool __free_memory(struct data_path *dp,
	const struct free_descriptor *desc)
{
	volatile struct psd_skctl *skctl = dp->rbctl->skctl_va;

	int rptr;
	int wptr;
	int slot;

again:
	wptr = atomic_read(&dp->rbctl->local_dl_free_wptr);
	rptr = skctl->ds.free_rptr;

	if (likely(!__shm_is_full(PSD_DF_CH_TOTAL_LEN, wptr, rptr))) {
		if (unlikely(!get_next_free_queue_slot(dp, wptr, &slot)))
			goto again;
		memcpy_free_desc((void *)&skctl->ds.free_desc[slot],
			desc, sizeof(*desc));

		/* write one free flag to each slot */
		*(u32 *)(desc->buffer_offset + dp->rbctl->rx_va) = SLOT_FREE_FLAG;

		/* flush the cache before scheduling free */
		shm_flush_dcache(dp->rbctl->rx_cacheable, desc->buffer_offset +
			dp->rbctl->rx_va, desc->length);

		/* must ensure the descriptor is ready first */
		barrier();
		put_next_free_queue_slot(dp, slot);
		return true;
	} else {
		pr_warn_ratelimited("%s: dl free queue is full\n", __func__);
	}

	return false;
}

static bool __maybe_unused free_memory(struct data_path *dp,
	const struct free_descriptor *desc)
{
	bool ret;

	preempt_disable();
	ret = __free_memory(dp, desc);
	preempt_enable();

	return ret;
}

static void free_worker(struct work_struct *work)
{
	struct data_path *dp = (struct data_path *)
		container_of(work, struct data_path, free_work);

	struct llist_node *llnode;
	int retry = 3;

	for (; retry > 0; retry--) {
		if (llist_empty(&dp->free_list))
			return;

		llnode = llist_del_all(&dp->free_list);
		while (llnode) {
			struct free_entry *entry =
				llist_entry(llnode, struct free_entry, llnode);
			struct llist_node *llnext = llist_next(llnode);

			if (unlikely(!free_memory(dp, &entry->desc))) {
				pr_err_ratelimited("%s: free memory failed\n",
					__func__);
				goto pushback;
			}
			llnode = llnext;
		}
	}

	return;

pushback:
	/* push back the packet and wait next schedule */
	while (llnode) {
		struct llist_node *tmp = llist_next(llnode);

		llist_add(llnode, &dp->free_list);
		llnode = tmp;
	}
}

static inline void free_rx_memory(struct data_path *dp, void *p, size_t length)
{
	struct free_entry *entry = p;

	entry->dp = dp;
	entry->desc.buffer_offset = (u32)((unsigned long)p -
		(unsigned long)dp->rbctl->rx_va);
	entry->desc.length = (u16)length;

#ifdef RX_DIRECT_FREE
	if (likely(free_memory(dp, &entry->desc)))
		return;

	pr_err_ratelimited("%s: free memory failed\n",
		__func__);
#endif

	llist_add(&entry->llnode, &dp->free_list);
	schedule_free(dp);
}

static inline void clean_free_list(struct data_path *dp)
{
	llist_del_all(&dp->free_list);
}

static void rx_free_cb(void *p, void *ptr, size_t len)
{
	struct data_path *dp = p;

	free_rx_memory(dp, ptr, len);
}

static inline int dp_data_rx(struct data_path *dp,
	struct dl_descriptor *desc)
{
	struct psd_rbctl *rbctl = dp->rbctl;
	unsigned char *p;
	size_t total_length;
	struct sk_buff *skb = NULL;
	size_t headroom;

	p = rbctl->rx_va + desc->buffer_offset;
	total_length = desc->exhdr_length +
		desc->packet_offset + desc->packet_length;

	shm_invalidate_dcache(rbctl->rx_cacheable, p, total_length);

	dp->stat.rx_bytes += total_length;
	dp->stat.rx_packets++;

	if (static_key_true(&data_path.rx_copy)) {
		headroom = psd_get_headroom(desc->cid);
		skb = dev_alloc_skb(desc->packet_length + headroom);
		if (likely(skb)) {
			skb_reserve(skb, headroom);
			memcpy(skb_put(skb, desc->packet_length),
				p + desc->exhdr_length + desc->packet_offset,
				desc->packet_length);

			/* push to upper layer */
			psd_data_rx(desc->cid, skb);
		} else {
			pr_err_ratelimited(
				"low mem, packet dropped\n");
		}
		/* free rx memory */
		free_rx_memory(dp, p, total_length);
	} else {
		skb = alloc_skb_p(p, total_length, rx_free_cb,
			dp, GFP_ATOMIC);

		if (likely(skb)) {
			skb_reserve(skb, desc->exhdr_length +
				desc->packet_offset);
			skb_put(skb, desc->packet_length);

			/* push to upper layer */
			psd_data_rx(desc->cid, skb);
		} else {
			pr_err_ratelimited(
				"low mem, packet dropped\n");
			/* free rx memory */
			free_rx_memory(dp, p, total_length);
		}
	}

	return 0;
}

static void dp_rx_func(unsigned long arg)
{
	struct data_path *dp = (struct data_path *)arg;
	struct psd_rbctl *rbctl = dp->rbctl;
	volatile struct psd_skctl *skctl = rbctl->skctl_va;

	int slot;
	int i;

	struct dl_descriptor desc;
	int wptr;
	bool retry = false;

	dp->stat.rx_sched_cnt++;

	/* tell CP we are receiving */
	skctl->ds.active = 1;
	/* make sure active is set before receiving */
	barrier();

	wptr = skctl->ds.wptr;
	for (i = 0; i < MAX_RX_SHOTS; i++) {
		if (unlikely(!psd_is_link_up())) {
			/* if not sync, just return */
			break;
		}

retry:
		if (__shm_is_empty(wptr, rbctl->local_dl_rptr)) {
			if (retry) {
				wptr = skctl->ds.wptr;
				retry = false;
				goto retry;
			}
			break;
		}
		retry = true;

		slot = __shm_get_next_slot(PSD_DL_CH_TOTAL_LEN, rbctl->local_dl_rptr);
		memcpy_desc_from_shm(&desc, (void *)&skctl->ds.desc[slot],
			sizeof(desc));
		dp_data_rx(dp, &desc);

		rbctl->local_dl_rptr = slot;
	}

	/* let CP know this slot */
	skctl->ds.rptr = rbctl->local_dl_rptr;

	if (i == MAX_RX_SHOTS) {
		dp_schedule_rx(dp);
	} else {
		/* we will stop */
		skctl->ds.active = 0;
		/* make sure active is set before double checking */
		barrier();

		/* double check the ring buffer */
		wptr = skctl->ds.wptr;
		if (!__shm_is_empty(wptr, rbctl->local_dl_rptr))
			dp_schedule_rx(dp);
	}
}

static inline void reclaim_one_slot(struct data_path *dp,
	const struct free_descriptor *desc)
{
	tmem_free(dp->allocator, desc->buffer_offset + dp->rbctl->tx_va,
		desc->length);
}

static void reclaim_memory(struct data_path *dp, size_t freed_bytes)
{
	struct psd_rbctl *rbctl = dp->rbctl;
	volatile struct psd_skctl *skctl = rbctl->skctl_va;

	struct free_descriptor desc;
	int wptr;
	int slot;
	size_t bytes = 0;
	unsigned long flags;

	spin_lock_irqsave(&rbctl->reclaim_lock, flags);

	rbctl->local_ul_free_rptr = skctl->us.free_rptr;

	while (bytes < freed_bytes) {
		wptr = skctl->us.free_wptr;

		if (__shm_is_empty(wptr, rbctl->local_ul_free_rptr))
			break;

		slot = __shm_get_next_slot(PSD_UF_CH_TOTAL_LEN, rbctl->local_ul_free_rptr);
		memcpy_free_desc(&desc, (void *)&skctl->us.free_desc[slot],
			sizeof(desc));
		reclaim_one_slot(dp, &desc);
		bytes += desc.length;
		rbctl->local_ul_free_rptr = slot;
	}

	skctl->us.free_rptr = rbctl->local_ul_free_rptr;
	spin_unlock_irqrestore(&rbctl->reclaim_lock, flags);
}

static void reclaim_worker(struct work_struct *work)
{
	struct data_path *dp = (struct data_path *)
		container_of(work, struct data_path, reclaim_work);

	reclaim_memory(dp, 0xffffffff);
}

static inline void dp_broadcast_msg(struct data_path *dp, int status)
{
	if (atomic_read(&dp->state) == dp_state_opened) {
		if (status == PSD_LINK_DOWN) {
			/*
			 * synchornize to ensure all the data_tx is finished
			 * data_tx is protected by rcu read lock in psd_data_tx
			 */
			synchronize_net();
			/* ensure reclaim work is finished */
			flush_workqueue(dp->reclaim_wq);
			/* free all the tx memory */
			tmem_free_all(dp->allocator);

			/* stop rx tasklet */
			tasklet_disable(&dp->rx_tl);
			tasklet_enable(&dp->rx_tl);
			/* ensure free work is finished */
			flush_workqueue(dp->free_wq);

			clean_free_list(dp);
		} else if (status == PSD_LINK_UP) {
			/*
			 * Now both AP and CP will not send packet
			 * to ring buffer or receive packet from ring
			 * buffer, so cleanup any packet in ring buffer
			 * and initialize some key data structure to
			 * the beginning state otherwise user space
			 * process and CP may occur error
			 */
			psd_rb_data_init(dp->rbctl);
		}
	}
}

static ssize_t read_stat(struct file *file, char __user *ubuf,
	size_t count, loff_t *ppos)
{
	struct data_path *dp = file->private_data;
	struct page *page;
	char *buf;
	char *p;
	int ret;
	int len;
	int i;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		pr_err("%s: cannot get memory\n", __func__);
		return -ENOMEM;
	}

	buf = page_address(page);
	p = buf;
	p += sprintf(p, "rx_bytes\t: %lu\n",
		(unsigned long)dp->stat.rx_bytes);
	p += sprintf(p, "rx_packets\t: %lu\n",
		(unsigned long)dp->stat.rx_packets);
	p += sprintf(p, "rx_interrupts\t: %lu\n",
		(unsigned long)dp->stat.rx_interrupts);
	p += sprintf(p, "rx_sched_cnt\t: %lu\n",
		(unsigned long)dp->stat.rx_sched_cnt);

	p += sprintf(p, "tx_bytes\t: %lu\n",
		(unsigned long)dp->stat.tx_bytes);

	p += sprintf(p, "tx_packets\t:");
	for (i = 0; i < PSD_QUEUE_CNT; ++i)
		p += sprintf(p, " %lu",
			(unsigned long)dp->stat.tx_packets[i]);
	p += sprintf(p, "\n");

	p += sprintf(p, "tx_interrupts\t: %lu\n",
		(unsigned long)dp->stat.tx_interrupts);

	len = strlen(buf);
	buf[len] = '\n';

	ret = simple_read_from_buffer(ubuf, count, ppos, buf, len + 1);

	__free_page(page);

	return ret;
}

static ssize_t write_stat(struct file *file, const char __user *ubuf,
	size_t count, loff_t *ppos)
{
	struct data_path *dp = file->private_data;
	unsigned val;
	int ret;

	ret = kstrtouint_from_user(ubuf, count, 0, &val);
	if (ret)
		return ret;

	if (!val)
		memset(&dp->stat, 0, sizeof(dp->stat));

	return count;
}

static const struct file_operations fops_stat = {
	.read =		read_stat,
	.write =	write_stat,
	.open =		simple_open,
	.llseek =	default_llseek,
};

static ssize_t read_copy_on_rx(struct file *file, char __user *ubuf,
	size_t count, loff_t *ppos)
{
	struct data_path *dp = file->private_data;
	char buf[3];

	if (dp->copy_on_rx)
		buf[0] = 'Y';
	else
		buf[0] = 'N';
	buf[1] = '\n';
	buf[2] = 0x00;
	return simple_read_from_buffer(ubuf, count, ppos, buf, 2);
}

static ssize_t write_copy_on_rx(struct file *file, const char __user *ubuf,
	size_t count, loff_t *ppos)
{
	struct data_path *dp = file->private_data;

	char buf[32];
	size_t buf_size;
	bool bv;

	buf_size = min(count, (sizeof(buf)-1));
	if (copy_from_user(buf, ubuf, buf_size))
		return -EFAULT;

	buf[buf_size] = '\0';
	mutex_lock(&dp->rx_copy_lock);
	if (strtobool(buf, &bv) == 0) {
		if (bv != dp->copy_on_rx) {
			if (bv)
				static_key_slow_inc(&data_path.rx_copy);
			else
				static_key_slow_dec(&data_path.rx_copy);
			dp->copy_on_rx = bv;
		}
	}
	mutex_unlock(&dp->rx_copy_lock);

	return count;
}

static const struct file_operations fops_copy_on_rx = {
	.read =		read_copy_on_rx,
	.write =	write_copy_on_rx,
	.open =		simple_open,
	.llseek =	default_llseek,
};

static int dp_debugfs_init(struct data_path *dp)
{
	dp->dentry = debugfs_create_dir(dp->name ? dp->name : "data_path",
		psd_debugfs_root_dir);
	if (!dp->dentry)
		return -ENOMEM;

	if (IS_ERR_OR_NULL(debugfs_create_file(
				"stat", S_IRUGO, dp->dentry,
				dp, &fops_stat)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_u32(
				"max_pending_reclaim_req", S_IRUGO | S_IWUSR,
				dp->dentry, &dp->max_pending_reclaim_req)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_file("copy_on_rx",
				S_IRUGO | S_IWUSR,
				dp->dentry, dp,
				&fops_copy_on_rx)))
		goto error;

	return 0;

error:
	debugfs_remove_recursive(dp->dentry);
	dp->dentry = NULL;
	return -1;
}

static int dp_debugfs_exit(struct data_path *dp)
{
	debugfs_remove_recursive(dp->dentry);
	dp->dentry = NULL;
	return 0;
}

static u32 psd_buffer_lwm_cb(u32 status)
{
	struct data_path *dp = &data_path;

	__pm_wakeup_event(&dp_acipc_wakeup, 2000);
	pr_warn("PSD: %s!!!\n", __func__);

	if (atomic_read(&dp->state) == dp_state_opened)
		schedule_free(dp);

	return 0;
}

static u32 psd_chan_status_changed_cb(u32 status __maybe_unused)
{
	return 0;
}

static u32 psd_data_start_cb(u32 status)
{
	struct data_path *dp = &data_path;
	static unsigned long last_time = INITIAL_JIFFIES;

	/*
	 * hold 2s wakeup source for user space
	 * do not try to hold again if it is already held in last 0.5s
	 */
	if (time_after(jiffies, last_time + HZ / 2)) {
		__pm_wakeup_event(&dp_rx_wakeup, 2000);
		last_time = jiffies;
	}

	dp->stat.rx_interrupts++;

	dp_schedule_rx(dp);

	return 0;
}

static int dp_acipc_init(void)
{
	/* we do not check any return value */
	acipc_event_bind(ACIPC_PS_BUFFER_LWM_INT, psd_buffer_lwm_cb,
		ACIPC_CB_NORMAL, NULL);
	acipc_event_bind(ACIPC_PS_CHAN_STATUS_INT, psd_chan_status_changed_cb,
		ACIPC_CB_NORMAL, NULL);
	acipc_event_bind(ACIPC_PS_DATA_START_INT, psd_data_start_cb,
		ACIPC_CB_NORMAL, NULL);

	return 0;
}

static void dp_acipc_exit(void)
{
	acipc_event_unbind(ACIPC_PS_BUFFER_LWM_INT);
	acipc_event_unbind(ACIPC_PS_CHAN_STATUS_INT);
	acipc_event_unbind(ACIPC_PS_DATA_START_INT);
}

static int dp_init(void *priv)
{
	struct data_path *dp = (struct data_path *)priv;

	if (atomic_cmpxchg(&dp->state, dp_state_idle,
			   dp_state_opening) != dp_state_idle) {
		pr_err("%s: path is already opened(state %d)\n",
			 __func__, atomic_read(&dp->state));
		return -1;
	}

	memset(&dp->stat, 0, sizeof(dp->stat));

	tasklet_init(&dp->rx_tl, dp_rx_func,
		     (unsigned long)dp);

	INIT_WORK(&dp->reclaim_work, reclaim_worker);
	dp->reclaim_wq = create_singlethread_workqueue("psd-reclaim-wq");

	if (!dp->reclaim_wq) {
		pr_err("%s: create reclaim workqueue failed\n", __func__);
		goto reset_state;
	}

	INIT_WORK(&dp->free_work, free_worker);
	dp->free_wq = create_singlethread_workqueue("psd-free-wq");

	if (!dp->free_wq) {
		pr_err("%s: create free workqueue failed\n", __func__);
		goto destroy_reclaimwq;
	}

	if (dp_debugfs_init(dp) < 0) {
		pr_err("%s: debugfs failed\n", __func__);
		goto destroy_freewq;
	}

	if (dp_acipc_init() < 0) {
		pr_err("%s: init acipc callback failed\n",
			__func__);
		goto exit_debugfs;
	}

	wakeup_source_init(&dp_acipc_wakeup, "dp_acipc_wakeup");
	wakeup_source_init(&dp_rx_wakeup, "dp_rx_wakeups");

	atomic_set(&dp->state, dp_state_opened);

	return 0;

exit_debugfs:
	dp_debugfs_exit(dp);
destroy_freewq:
	destroy_workqueue(dp->free_wq);
destroy_reclaimwq:
	destroy_workqueue(dp->reclaim_wq);
reset_state:
	atomic_set(&dp->state, dp_state_idle);
	return -1;
}

static void dp_exit(void *priv)
{
	struct data_path *dp = (struct data_path *)priv;

	if (atomic_cmpxchg(&dp->state, dp_state_opened,
			   dp_state_closing) != dp_state_opened) {
		pr_err("%s: path is already opened(state %d)\n",
			 __func__, atomic_read(&dp->state));
		return;
	}

	wakeup_source_trash(&dp_rx_wakeup);
	wakeup_source_trash(&dp_acipc_wakeup);
	dp_acipc_exit();
	dp_debugfs_exit(dp);
	destroy_workqueue(dp->free_wq);
	destroy_workqueue(dp->reclaim_wq);
	tasklet_kill(&dp->rx_tl);

	atomic_set(&dp->state, dp_state_idle);
}

static int dp_data_tx(void *priv, int cid, int simid, int prio,
	struct sk_buff *skb, void *queue)
{
	struct data_path *dp = (struct data_path *)priv;
	struct ul_descriptor desc;
	unsigned len;
	int qidx;
	void *buf;
	int retry = 3;

	struct psd_rbctl *rbctl = dp->rbctl;
	volatile struct psd_skctl *skctl = rbctl->skctl_va;
	struct chan_info *ci;

	int rptr;
	int wptr;
	int slot;
	int *local_wptr;

	if (unlikely(!dp || atomic_read(&dp->state) != dp_state_opened)) {
		pr_err("%s: data path is not open!\n", __func__);
		goto drop;
	}

	if (unlikely(!psd_is_link_up())) {
		pr_err("%s: link down, packet dropped\n", __func__);
		goto drop;
	}

	if (unlikely(!queue)) {
		pr_err("%s: queue is not initialized\n", __func__);
		goto drop;
	}

	qidx = (unsigned long)queue - QUEUE_OFFSET;

	if (unlikely(qidx >= PSD_UL_CH_CNT)) {
		pr_err("%s: invalid queue %d!\n", __func__, qidx);
		goto drop;
	}

	if (prio == PSD_QUEUE_HIGH) {
		local_wptr = &rbctl->local_ul_high_wptr[qidx];
		ci = rbctl->ul_high_chan + qidx;
	} else {
		local_wptr = &rbctl->local_ul_defl_wptr[qidx];
		ci = rbctl->ul_defl_chan + qidx;
	}

	wptr = *local_wptr;
	rptr = *ci->rptr;

	if (__shm_is_full(ci->count, wptr, rptr)) {
		pr_err_ratelimited("%s: tx queue is full!!!\n", __func__);
		return PSD_DATA_SEND_BUSY;
	}

	len = CP_UL_HEADROOM + skb->len;
	for (; retry > 0; retry--) {
		buf = tmem_alloc(dp->allocator, len, 0);
		if (buf)
			break;
		else
			reclaim_memory(dp, len);
	}

	if (unlikely(!buf)) {
		pr_err_ratelimited("%s: no buffer left!!!\n", __func__);
		notify_cp_buffer_lwm();
		dp->pending_reclaim_req = 0;
		schedule_reclaim(dp);
		return PSD_DATA_SEND_BUSY;
	}

	memcpy(buf + CP_UL_HEADROOM, skb->data, skb->len);
	shm_flush_dcache(dp->rbctl->tx_cacheable, buf, len);

	desc.buffer_offset = (u32)(unsigned long)(buf - dp->rbctl->tx_va);
	desc.exhdr_length = 0;
	desc.packet_offset = CP_UL_HEADROOM;
	desc.packet_length = skb->len;
	desc.simid = simid;
	desc.cid = cid;

	slot = __shm_get_next_slot(ci->count, wptr);
	memcpy_desc_to_shm((void *)((struct ul_descriptor *)ci->desc + slot),
		&desc, sizeof(desc));
	*ci->wptr = *local_wptr = slot;
	dp->stat.tx_packets[prio]++;
	dp->stat.tx_bytes += len;

	/* make sure the sequence: update pointer -> check active */
	barrier();
	if (!skctl->us.active) {
		dp->stat.tx_interrupts++;
		notify_data_start();
	}
	dp->pending_reclaim_req++;
	if (dp->pending_reclaim_req > dp->max_pending_reclaim_req) {
		schedule_reclaim(dp);
		dp->pending_reclaim_req = 0;
	}
	dev_kfree_skb_any(skb);
	return PSD_DATA_SEND_OK;
drop:
	dev_kfree_skb_any(skb);
	return PSD_DATA_SEND_DROP;
}

static void dp_link_status_changed(void *priv, int status)
{
	dp_broadcast_msg((struct data_path *)priv, status);
}

static void *dp_alloc_queue(void *priv, int cid)
{
	struct data_path *dp = (struct data_path *)priv;
	struct psd_rbctl *rbctl = dp->rbctl;
	volatile struct psd_skctl *skctl = rbctl->skctl_va;
	int qidx;
	void *ret = NULL;

	spin_lock(&rbctl->queue_lock);
	qidx = ffz(rbctl->ap_chan_status);
	if (likely(qidx < PSD_UL_CH_CNT)) {
		set_bit(qidx, &rbctl->ap_chan_status);
		skctl->ci.ap_chan_status = (u16)rbctl->ap_chan_status;
		skctl->ci.chan_cid[qidx] = cid;
		/* make sure all the changes synced before interrupting */
		barrier();
		notify_cp_chan_status_changed();
		ret = (void *)(unsigned long)(qidx + QUEUE_OFFSET);
		pr_info("%s: allocated queue %d for cid %d\n",
			__func__, qidx, cid);
	} else {
		pr_err("%s: no free queue exist, returned idx %d\n",
			__func__, qidx);
	}
	spin_unlock(&rbctl->queue_lock);

	return ret;
}

static void dp_free_queue(void *priv, void *queue)
{
	struct data_path *dp = (struct data_path *)priv;
	struct psd_rbctl *rbctl = dp->rbctl;
	volatile struct psd_skctl *skctl = rbctl->skctl_va;
	int qidx;
	int cid;

	if (!queue)
		return;

	qidx = (unsigned long)queue - QUEUE_OFFSET;
	spin_lock(&rbctl->queue_lock);
	if (likely(qidx < PSD_UL_CH_CNT)) {
		clear_bit(qidx, &rbctl->ap_chan_status);
		skctl->ci.ap_chan_status = (u16)rbctl->ap_chan_status;
		cid = skctl->ci.chan_cid[qidx];
		skctl->ci.chan_cid[qidx] = INVALID_CID;
		/* make sure all the changes synced before interrupting */
		barrier();
		notify_cp_chan_status_changed();
		pr_info("%s: freed queue %d for cid %d\n",
			__func__, qidx, cid);
	} else {
		pr_err("%s: try to free invalid queue\n",
			__func__);
	}
	spin_unlock(&rbctl->queue_lock);
}

static int psd_param_init(struct psd_rbctl *rbctl,
	const struct cpload_cp_addr *addr)
{
	if (!addr)
		return -1;

	/* psd dedicated ring buffer */
	rbctl->skctl_pa = addr->psd_skctl_pa;

	rbctl->tx_pa = addr->psd_tx_pa;
	rbctl->rx_pa = addr->psd_rx_pa;

	rbctl->tx_total_size = addr->psd_tx_total_size;
	rbctl->rx_total_size = addr->psd_rx_total_size;

	memcpy(rbctl->ul_defl_chan_len, ul_defl_chan_len,
		sizeof(ul_defl_chan_len));
	memcpy(rbctl->ul_high_chan_len, ul_high_chan_len,
		sizeof(ul_high_chan_len));

	return 0;
}

static int dp_set_addr(void *priv, const struct cpload_cp_addr *addr)
{
	struct data_path *dp = (struct data_path *)priv;

	if (!addr->first_boot) {
		tmem_destroy(dp->allocator);
		psd_rb_exit(dp->rbctl);
	}

	psd_param_init(dp->rbctl, addr);
	if (psd_rb_init(dp->rbctl, psd_debugfs_root_dir) < 0) {
		pr_err("%s: init psd rbctl failed\n", __func__);
		return 0;
	}

	dp->allocator = tmem_create(dp->rbctl->tx_va,
		dp->rbctl->tx_total_size, DATA_ALIGN_SIZE);

	if (!dp->allocator) {
		pr_err("%s: create memory pool failed\n", __func__);
		return 0;
	}

	return 0;
}

static bool dp_is_tx_stopped(void *priv)
{
	return false;
}

static struct psd_rbctl psd_rbctl = {
	.name = "cp-psd",
	.queue_lock = __SPIN_LOCK_UNLOCKED(psd_rbctl.queue_lock),
	.va_lock = __MUTEX_INITIALIZER(psd_rbctl.va_lock),
	.free_lock = __SPIN_LOCK_UNLOCKED(psd_rbctl.free_lock),
	.reclaim_lock = __SPIN_LOCK_UNLOCKED(psd_rbctl.reclaim_lock),
	.local_dl_free_wptr = ATOMIC_INIT(0),
	.local_committed_dl_free_wptr = ATOMIC_INIT(0),
};

static struct data_path data_path = {
	.state = ATOMIC_INIT(dp_state_idle),
	.name = "data-pathv2",
	.rbctl = &psd_rbctl,
	.free_list = LLIST_HEAD_INIT(data_path.free_list),
	.max_pending_reclaim_req = MAX_PENDING_RECLAIM_REQ,
	.rx_copy_lock = __MUTEX_INITIALIZER(data_path.rx_copy_lock),
	.rx_copy = STATIC_KEY_INIT_TRUE,
	.copy_on_rx = true,
};

static struct psd_driver dp_drvier = {
	.name = "data-pathv2",
	.init = dp_init,
	.exit = dp_exit,
	.set_addr = dp_set_addr,
	.data_tx = dp_data_tx,
	.is_tx_stopped = dp_is_tx_stopped,
	.link_status_changed = dp_link_status_changed,
	.alloc_queue = dp_alloc_queue,
	.free_queue = dp_free_queue,
	.version = 2,
	.priv = &data_path,
};

static int __init data_path_init(void)
{
	register_psd_driver(&dp_drvier);
	return 0;
}

static void __exit data_path_exit(void)
{
	unregister_psd_driver(&dp_drvier);
}

module_init(data_path_init);
module_exit(data_path_exit);
