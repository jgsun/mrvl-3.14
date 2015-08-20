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
#include <linux/pxa9xx_acipc.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <asm/byteorder.h>
#include <linux/static_key.h>
#include "shm.h"
#include "tel_trace.h"
#include "debugfs.h"
#include "pxa_cp_load.h"
#include "pxa_cp_load_ioctl.h"
#include "data_path_common.h"
#include "psdatastub.h"
#include "skb_llist.h"

#define DATA_ALIGN_SIZE 8

#define RX_SLOT_PTR(b, n, sz) SHM_PACKET_PTR(b, n, sz)

struct data_path_stat {
	u32 rx_bytes;
	u32 rx_packets; /* unused */
	u32 rx_slots;
	u32 rx_interrupts;
	u32 rx_used_bytes;
	u32 rx_free_bytes;
	u32 rx_sched_cnt;
	u32 rx_resched_cnt;

	u32 tx_bytes;
	u32 tx_packets[PSD_QUEUE_CNT];
	u64 tx_packets_delay[PSD_QUEUE_CNT];
	u32 tx_q_bytes;
	u32 tx_q_packets[PSD_QUEUE_CNT];
	u32 tx_slots;
	u32 tx_interrupts;
	u32 tx_used_bytes;
	u32 tx_free_bytes;
	u32 tx_sched_cnt;
	u32 tx_resched_cnt;
	u32 tx_force_sched_cnt;
	u32 tx_sched_q_len;
};

struct rx_slot {
	/* all packets sent, slot can be marked as freed for cp side */
	bool done;
	/* number of packets in slot that are still used */
	struct kref refcnt;
};

struct data_path {
	atomic_t state;

	const char *name;
	struct dentry *dentry;

	struct shm_rbctl *rbctl;

	struct tasklet_struct tx_tl;
	struct tasklet_struct rx_tl;

	struct timer_list tx_sched_timer;

	u32 tx_q_max_len;
	struct skb_llist tx_q[PSD_QUEUE_CNT];
	u32 is_tx_stopped;

	int tx_wm[PSD_QUEUE_CNT];
	u32 enable_piggyback;

	u16 max_tx_shots;
	u16 max_rx_shots;

	u16 tx_sched_delay_in_ms;
	u16 tx_q_min_sched_len;

	struct mutex rx_copy_lock;
	struct static_key rx_copy;
	bool copy_on_rx;

	spinlock_t ap_rptr_lock;
	int local_ap_rptr;
	struct rx_slot *rxs;

	/* stat */
	struct data_path_stat stat;
};

/* PSD share memory socket header structure */
struct shm_psd_skhdr {
	unsigned short length;		/* payload length */
	unsigned short reserved;	/* not used */
};

struct pduhdr {
	__be16 length;
	__u8 offset;
	__u8 reserved;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u32 cid:31;
	u32 simid:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u32 simid:1;
	u32 cid:31;
#else
#error "incorrect endian"
#endif
} __packed;

enum data_path_state {
	dp_state_idle,
	dp_state_opening,
	dp_state_opened,
	dp_state_closing,
};

/*
 * as we do tx/rx in interrupt context, we should avoid lock up the box
 */
#define MAX_TX_SHOTS 32
#define MAX_RX_SHOTS 32

/*
 * max tx q length
 */
#define MAX_TX_Q_LEN 2048

/*
 * tx schedule delay
 */
#define TX_SCHED_DELAY 2

/*
 * tx q schedule length
 */
#define TX_MIN_SCHED_LEN 0

static struct wakeup_source dp_rx_wakeup;
static struct wakeup_source dp_acipc_wakeup;
static struct data_path data_path;

/* notify cp psd that new packet available in the socket buffer */
static inline void acipc_notify_psd_packet_sent(void)
{
	acipc_event_set(ACIPC_SHM_PSD_PACKET_NOTIFY);
}

/* notify cp psd that cp can continue transmission */
static inline void acipc_notify_cp_psd_tx_resume(void)
{
	pr_warn_ratelimited(
		"MSOCK: acipc_notify_cp_psd_tx_resume!!!\n");
	acipc_event_set(ACIPC_RINGBUF_PSD_TX_RESUME);
}

/*notify cp psd that ap transmission is stopped, please resume me later */
static inline void acipc_notify_ap_psd_tx_stopped(void)
{
	pr_warn_ratelimited(
		"MSOCK: acipc_notify_ap_psd_tx_stopped!!!\n");
	acipc_event_set(ACIPC_RINGBUF_PSD_TX_STOP);
}

static inline int tx_q_length(struct data_path *dp)
{
	int len = 0;
	int i;

	for (i = 0; i < PSD_QUEUE_CNT; i++)
		len += skb_llist_len(&dp->tx_q[i]);

	return len;
}

static inline bool data_path_is_tx_q_full(struct data_path *dp)
{
	return tx_q_length(dp) > dp->tx_q_max_len;
}

static inline bool data_path_is_rx_stopped(struct data_path *dp)
{
	return dp->rbctl->is_cp_xmit_stopped;
}

static inline void tx_q_enqueue(struct data_path *dp, struct sk_buff *skb,
				int prio)
{
	dp->stat.tx_q_bytes += skb->len;
	dp->stat.tx_q_packets[prio]++;
	skb_llist_enqueue(&dp->tx_q[prio], skb);
}

static inline void tx_q_queue_head(struct data_path *dp, struct sk_buff *skb,
				int prio)
{
	skb_llist_queue_head(&dp->tx_q[prio], skb);
}

static inline struct sk_buff *tx_q_peek(struct data_path *dp, int *prio)
{
	struct sk_buff *skb = NULL;
	int i;

	for (i = 0; i < PSD_QUEUE_CNT; i++) {
		skb = skb_llist_peek(&dp->tx_q[i]);
		if (skb) {
			if (prio)
				*prio = i;
			break;
		}
	}

	return skb;
}

static inline struct sk_buff *tx_q_dequeue(struct data_path *dp, int *prio)
{
	struct sk_buff *skb = NULL;
	int i;

	for (i = 0; i < PSD_QUEUE_CNT; i++) {
		skb = skb_llist_dequeue(&dp->tx_q[i]);
		if (skb) {
			if (prio)
				*prio = i;
			break;
		}
	}

	return skb;
}

static inline void tx_q_init(struct data_path *dp)
{
	int i;
	for (i = 0; i < PSD_QUEUE_CNT; i++)
		skb_llist_init(&dp->tx_q[i]);
}

static inline void tx_q_clean(struct data_path *dp)
{
	int i;
	for (i = 0; i < PSD_QUEUE_CNT; i++)
		skb_llist_clean(&dp->tx_q[i]);
}

static inline bool has_enough_free_tx_slot(const struct data_path *dp,
	int free_slots, int prio)
{
	return free_slots > dp->tx_wm[prio];
}

static inline int tx_q_avail_length(struct data_path *dp, int free_slots)
{
	int len = 0;
	int i;

	for (i = 0; i < PSD_QUEUE_CNT; i++)
		if (has_enough_free_tx_slot(dp, free_slots, i))
			len += skb_llist_len(&dp->tx_q[i]);

	return len;
}

static void tx_sched_timeout(unsigned long data)
{
	struct data_path *dp = (struct data_path *)data;

	if (dp && atomic_read(&dp->state) == dp_state_opened)
		tasklet_schedule(&dp->tx_tl);
}

/*
 * force_delay: delay the schedule forcibly, for the high watermark case
 */
static void __data_path_schedule_tx(struct data_path *dp, bool force_delay)
{
	if (dp && atomic_read(&dp->state) == dp_state_opened) {
		int free_slots = shm_free_tx_skbuf(dp->rbctl);
		int len = tx_q_avail_length(dp, free_slots);

		/*
		 * ok, we have enough packet in queue, fire the work immediately
		 */
		if (!force_delay && len > dp->tx_q_min_sched_len) {
			tasklet_schedule(&dp->tx_tl);
			del_timer(&dp->tx_sched_timer);
		} else {
			if (!timer_pending(&dp->tx_sched_timer)) {
				unsigned long expires = jiffies +
					msecs_to_jiffies
					(dp->tx_sched_delay_in_ms);
				mod_timer(&dp->tx_sched_timer, expires);
			}
		}
	}
}

static inline void data_path_schedule_tx(struct data_path *dp)
{
	__data_path_schedule_tx(dp, false);
}

static inline void data_path_schedule_rx(struct data_path *dp)
{
	if (dp && atomic_read(&dp->state) == dp_state_opened)
		tasklet_schedule(&dp->rx_tl);
}

static inline int data_path_max_payload(struct data_path *dp)
{
	struct shm_rbctl *rbctl = dp->rbctl;
	return rbctl->tx_skbuf_size - sizeof(struct shm_psd_skhdr);
}

static int data_path_xmit(struct data_path *dp,
				     struct sk_buff *skb, int prio)
{
	int ret = -1;

	if (dp && atomic_read(&dp->state) == dp_state_opened) {
		tx_q_enqueue(dp, skb, prio);
		data_path_schedule_tx(dp);
		ret = 0;
	}

	return ret;
}

static inline void data_path_advance_rptr(struct data_path *dp)
{
	int slot;
	struct rx_slot *rxs;
	unsigned long flags;
	struct shm_rbctl *rbctl = dp->rbctl;
	int counter = 0;

	spin_lock_irqsave(&dp->ap_rptr_lock, flags);

	slot = shm_get_next_rx_slot(rbctl, rbctl->skctl_va->ap_rptr);
	rxs = (struct rx_slot *)RX_SLOT_PTR(dp->rxs, slot,
							sizeof(struct rx_slot));
	if (unlikely(!rxs->done))
		goto out;

	do {
		counter++;
		rxs->done = false;
		shm_flush_dcache(rbctl->rx_cacheable,
			SHM_PACKET_PTR(rbctl->rx_va, slot,
				rbctl->rx_skbuf_size),
			rbctl->rx_skbuf_size);

		slot = shm_get_next_rx_slot(rbctl, slot);
		rxs = (struct rx_slot *)RX_SLOT_PTR(dp->rxs, slot,
					sizeof(struct rx_slot));
	} while (rxs->done);

	BUG_ON(counter >= rbctl->rx_skbuf_num);

	/* advance read pointer on shmem*/
	rbctl->skctl_va->ap_rptr = slot ? slot - 1 : rbctl->rx_skbuf_num - 1;

out:
	spin_unlock_irqrestore(&dp->ap_rptr_lock, flags);

	/* process share memory socket buffer flow control */
	if (!__shm_is_empty(rbctl->skctl_va->cp_wptr, dp->local_ap_rptr) ||
		rbctl->is_cp_xmit_stopped)
		data_path_schedule_rx(dp);
}

static inline void data_path_rxs_done(struct kref *ref)
{
	struct rx_slot *rxs = container_of(ref, struct rx_slot, refcnt);
	rxs->done = true;
}

static inline void data_path_rxs_put(struct data_path *dp, struct rx_slot *rxs)
{
	if (kref_put(&rxs->refcnt, data_path_rxs_done))
		data_path_advance_rptr(dp);
}

static inline void data_path_rxs_hold(struct rx_slot *rxs)
{
	kref_get(&rxs->refcnt);
}

static inline void data_path_rxs_init(struct rx_slot *rxs)
{
	kref_init(&rxs->refcnt);
	rxs->done = false;
}

static void data_path_free_cb(void *rxs_p, void *ptr __maybe_unused,
	size_t len __maybe_unused)
{
	data_path_rxs_put(&data_path, (struct rx_slot *)rxs_p);
}

static int dp_data_rx(struct data_path *dp, unsigned char *data,
	unsigned int length, struct rx_slot *rxs)
{
	unsigned char *p = data;
	unsigned int remains = length;

	while (remains > 0) {
		struct pduhdr	*hdr = (void *)p;
		u32				iplen, offset_len;
		u32				tailpad;
		u32				total_len;
		struct			sk_buff *skb;
		size_t			headroom;

		total_len = be16_to_cpu(hdr->length);
		offset_len = hdr->offset;

		if (unlikely(total_len < offset_len)) {
			pr_err("%s: packet error\n", __func__);
			return -1;
		}

		iplen = total_len - offset_len;
		tailpad = padding_size(sizeof(*hdr) + iplen + offset_len,
			DATA_ALIGN_SIZE);

		if (unlikely(remains < (iplen + offset_len
					+ sizeof(*hdr) + tailpad))) {
			pr_err("%s: packet length error\n", __func__);
			return -1;
		}

		/* offset domain data */
		p += sizeof(*hdr);
		remains -= sizeof(*hdr);

		/* ip payload */
		p += offset_len;
		remains -= offset_len;

		if (static_key_true(&data_path.rx_copy)) {
			headroom = psd_get_headroom(hdr->cid);
			skb = dev_alloc_skb(iplen + headroom);
			if (likely(skb)) {
				skb_reserve(skb, headroom);
				memcpy(skb_put(skb, iplen), p, iplen);
			} else {
				pr_err_ratelimited(
					"low mem, packet dropped\n");
				return -1;
			}
		} else {
			skb = alloc_skb_p(hdr,
					  iplen + offset_len + sizeof(*hdr),
					  data_path_free_cb, rxs, GFP_ATOMIC);
			if (likely(skb)) {
				skb_reserve(skb, offset_len + sizeof(*hdr));
				skb_put(skb, iplen);
				data_path_rxs_hold(rxs);
			} else {
				pr_err_ratelimited(
					"low mem, packet dropped\n");
				return -1;
			}
		}

		psd_data_rx(hdr->cid, skb);

		p += iplen + tailpad;
		remains -= iplen + tailpad;
	}
	return 0;
}

static void data_path_tx_func(unsigned long arg)
{
	struct data_path *dp = (struct data_path *)arg;
	struct shm_rbctl *rbctl = dp->rbctl;
	struct shm_skctl *skctl = rbctl->skctl_va;
	struct shm_psd_skhdr *skhdr;
	struct sk_buff *packet;
	int slot = 0;
	int pending_slot;
	int free_slots;
	int prio;
	int remain_bytes;
	int used_bytes;
	int consumed_slot = 0;
	int consumed_packets = 0;
	int start_q_len;
	int max_tx_shots = dp->max_tx_shots;

	pending_slot = -1;
	remain_bytes = rbctl->tx_skbuf_size - sizeof(struct shm_psd_skhdr);
	used_bytes = 0;

	start_q_len = tx_q_length(dp);

	dp->stat.tx_sched_cnt++;

	while (consumed_slot < max_tx_shots) {
		if (!psd_is_link_up()) {
			tx_q_clean(dp);
			break;
		}

		free_slots = shm_free_tx_skbuf(rbctl);
		if (free_slots == 0) {
			/*
			 * notify cp only if we still have packets in queue
			 * otherwise, simply break
			 * also check current fc status, if tx_stopped is
			 * already sent to cp, do not try to interrupt cp again
			 * it is useless, and just make cp busier
			 * BTW:
			 * this may have race condition here, but as cp side
			 * have a watermark for resume interrupt,
			 * we can assume it is safe
			 */
			if (tx_q_length(dp) && !rbctl->is_ap_xmit_stopped) {
				shm_notify_ap_tx_stopped(rbctl);
				acipc_notify_ap_psd_tx_stopped();
			}
			break;
		} else if (free_slots == 1 && pending_slot != -1) {
			/*
			 * the only left slot is our pending slot
			 * check if we still have enough space in this
			 * pending slot
			 */
			packet = tx_q_peek(dp, NULL);
			if (!packet)
				break;

			/* packet is too large, notify cp and break */
			if (padded_size(packet->len, DATA_ALIGN_SIZE) >
				remain_bytes &&
				!rbctl->is_ap_xmit_stopped) {
				shm_notify_ap_tx_stopped(rbctl);
				acipc_notify_ap_psd_tx_stopped();
				break;
			}
		}

		packet = tx_q_dequeue(dp, &prio);

		if (!packet)
			break;

		/* push to ring buffer */

		/* we have one slot pending */
		if (pending_slot != -1) {
			/*
			 * the packet is too large for the pending slot
			 * send out the pending slot firstly
			 */
			if (padded_size(packet->len, DATA_ALIGN_SIZE) >
				remain_bytes) {
				shm_flush_dcache(rbctl->tx_cacheable,
						SHM_PACKET_PTR(rbctl->tx_va,
							pending_slot,
							rbctl->tx_skbuf_size),
						used_bytes + sizeof(struct shm_psd_skhdr));
				skctl->ap_wptr = pending_slot;
				pending_slot = -1;
				consumed_slot++;
				dp->stat.tx_slots++;
				dp->stat.tx_free_bytes += remain_bytes;
				dp->stat.tx_used_bytes += used_bytes;
			} else
				slot = pending_slot;
		}

		/*
		 * each priority has one hard limit to guarantee higher priority
		 * packet is not affected by lower priority packet
		 * if we reach this limit, we can only send higher priority
		 * packets
		 * but in the other hand, if this packet can be filled into our
		 * pending slot, allow it anyway
		 */
		if (!has_enough_free_tx_slot(dp, free_slots, prio) &&
			((pending_slot == -1) || !dp->enable_piggyback)) {
			/* push back the packets and schedule delayed tx */
			tx_q_queue_head(dp, packet, prio);
			__data_path_schedule_tx(dp, true);
			dp->stat.tx_force_sched_cnt++;
			break;
		}

		/* get a new slot from ring buffer */
		if (pending_slot == -1) {
			slot = shm_get_next_tx_slot(dp->rbctl, skctl->ap_wptr);

			remain_bytes =
				rbctl->tx_skbuf_size
				- sizeof(struct shm_psd_skhdr);
			used_bytes = 0;

			pending_slot = slot;
		}

		consumed_packets++;

		dp->stat.tx_packets[prio]++;
		dp->stat.tx_bytes += packet->len;

		skhdr = (struct shm_psd_skhdr *)
			SHM_PACKET_PTR(rbctl->tx_va,
				slot,
				rbctl->tx_skbuf_size);

		/* we are sure our remains is enough for current packet */
		skhdr->length = used_bytes + padded_size(packet->len,
			DATA_ALIGN_SIZE);
		memcpy((unsigned char *)(skhdr + 1) + used_bytes,
			packet->data, packet->len);

		used_bytes += padded_size(packet->len, DATA_ALIGN_SIZE);
		remain_bytes -= padded_size(packet->len, DATA_ALIGN_SIZE);

		trace_psd_xmit(packet, slot);

		dp->stat.tx_packets_delay[prio] +=
			ktime_to_ns(net_timedelta(skb_get_ktime(packet)));

		dev_kfree_skb_any(packet);
	}

	/* send out the pending slot */
	if (pending_slot != -1) {
		shm_flush_dcache(rbctl->tx_cacheable,
			SHM_PACKET_PTR(rbctl->tx_va,
				pending_slot,
				rbctl->tx_skbuf_size),
			used_bytes + sizeof(struct shm_psd_skhdr));
		skctl->ap_wptr = pending_slot;
		pending_slot = -1;
		consumed_slot++;
		dp->stat.tx_slots++;
		dp->stat.tx_free_bytes += remain_bytes;
		dp->stat.tx_used_bytes += used_bytes;
	}

	if (consumed_slot > 0) {
		acipc_notify_psd_packet_sent();
		dp->stat.tx_interrupts++;
		dp->stat.tx_sched_q_len += start_q_len;
	}

	if (consumed_slot >= max_tx_shots) {
		data_path_schedule_tx(dp);
		dp->stat.tx_resched_cnt++;
	}

	/*
	 * ring buffer is stopped, just notify upper layer
	 * do not need to check is_tx_stopped here, as we need to handle
	 * following situation:
	 * a new on-demand PDP is activated after tx_stop is called
	 */
	if (rbctl->is_ap_xmit_stopped) {
		if (!dp->is_tx_stopped)
			pr_err("%s tx stop\n", __func__);

		dp->is_tx_stopped = true;

		/* notify upper layer tx stopped */
		psd_tx_stop();

		/* reschedule tx to polling the ring buffer */
		if (tx_q_length(dp))
			__data_path_schedule_tx(dp, true);
	}

	/*
	 * ring buffer is resumed and the remain packets
	 * in queue is also sent out
	 */
	if (!rbctl->is_ap_xmit_stopped && dp->is_tx_stopped
		&& tx_q_length(dp) == 0) {
		pr_err("%s tx resume\n", __func__);

		/* notify upper layer tx resumed */
		psd_tx_resume();

		dp->is_tx_stopped = false;
	}
}

static void data_path_rx_func(unsigned long arg)
{
	struct data_path *dp = (struct data_path *)arg;
	struct shm_rbctl *rbctl = dp->rbctl;
	struct rx_slot *rxs;
	struct shm_psd_skhdr *skhdr;
	int slot;
	int count;
	int i;
	int max_rx_shots = dp->max_rx_shots;

	dp->stat.rx_sched_cnt++;
	slot = dp->local_ap_rptr;

	for (i = 0; i < max_rx_shots; i++) {
		if (!psd_is_link_up()) {
			/* if not sync, just return */
			break;
		}

		/* process share memory socket buffer flow control */
		if (rbctl->is_cp_xmit_stopped
		    && shm_has_enough_free_rx_skbuf(rbctl)) {
			shm_notify_cp_tx_resume(rbctl);
			acipc_notify_cp_psd_tx_resume();
		}

		if (__shm_is_empty(rbctl->skctl_va->cp_wptr, slot))
			break;

		slot = shm_get_next_rx_slot(rbctl, slot);

		skhdr =
		    (struct shm_psd_skhdr *)SHM_PACKET_PTR(rbctl->rx_va, slot,
							   rbctl->
							   rx_skbuf_size);
		rxs =
		    (struct rx_slot *)RX_SLOT_PTR(dp->rxs, slot,
							sizeof(struct rx_slot));


		shm_invalidate_dcache(rbctl->rx_cacheable, skhdr,
			rbctl->rx_skbuf_size);

		count = skhdr->length + sizeof(*skhdr);

		if (count > rbctl->rx_skbuf_size) {
			pr_err(
				 "%s: slot = %d, count = %d\n", __func__, slot,
				 count);
			goto error_length;
		}

		trace_psd_recv(slot);

		dp->stat.rx_slots++;
		dp->stat.rx_bytes += count - sizeof(*skhdr);
		dp->stat.rx_used_bytes += count;
		dp->stat.rx_free_bytes += rbctl->rx_skbuf_size - count;

		data_path_rxs_init(rxs);
		dp_data_rx(dp, (unsigned char *)(skhdr + 1), skhdr->length,
			   rxs);
		data_path_rxs_put(dp, rxs);

error_length:
		dp->local_ap_rptr = slot;
	}

	if (i == max_rx_shots) {
		dp->stat.rx_sched_cnt++;
		data_path_schedule_rx(dp);
	}
}

static void data_path_broadcast_msg(struct data_path *dp, int status)
{
	if (atomic_read(&dp->state) == dp_state_opened) {
		if (status == PSD_LINK_DOWN) {
			/* make sure tx/rx tasklet is stopped */
			tasklet_disable(&dp->tx_tl);
			/*
			 * tx tasklet is completely stopped
			 * purge the skb list
			 */
			tx_q_clean(dp);
			tasklet_enable(&dp->tx_tl);

			tasklet_disable(&dp->rx_tl);
			tasklet_enable(&dp->rx_tl);
		} else if (status == PSD_LINK_UP) {
			/*
			 * Now both AP and CP will not send packet
			 * to ring buffer or receive packet from ring
			 * buffer, so cleanup any packet in ring buffer
			 * and initialize some key data structure to
			 * the beginning state otherwise user space
			 * process and CP may occur error
			 */
			shm_rb_data_init(dp->rbctl);
		}
	}
}

static int debugfs_show_tx_q(struct seq_file *s, void *data)
{
	struct data_path *dp = s->private;
	int ret = 0;
	int i;

	ret += seq_puts(s, "len :");
	for (i = 0; i < PSD_QUEUE_CNT; i++)
		ret += seq_printf(s, " %d",
			skb_llist_len(&dp->tx_q[i]));
	ret += seq_puts(s, "\n");

	return ret;
}

static int debugfs_show_stat(struct seq_file *s, void *data)
{
	struct data_path *dp = s->private;
	int ret = 0;
	int i;

	ret += seq_printf(s, "rx_bytes\t: %lu\n",
		(unsigned long)dp->stat.rx_bytes);
	ret += seq_printf(s, "rx_packets\t: %lu\n",
		(unsigned long)dp->stat.rx_packets);
	ret += seq_printf(s, "rx_slots\t: %lu\n",
		(unsigned long)dp->stat.rx_slots);
	ret += seq_printf(s, "rx_interrupts\t: %lu\n",
		(unsigned long)dp->stat.rx_interrupts);
	ret += seq_printf(s, "rx_used_bytes\t: %lu\n",
		(unsigned long)dp->stat.rx_used_bytes);
	ret += seq_printf(s, "rx_free_bytes\t: %lu\n",
		(unsigned long)dp->stat.rx_free_bytes);
	ret += seq_printf(s, "rx_sched_cnt\t: %lu\n",
		(unsigned long)dp->stat.rx_sched_cnt);
	ret += seq_printf(s, "rx_resched_cnt\t: %lu\n",
		(unsigned long)dp->stat.rx_resched_cnt);

	ret += seq_printf(s, "tx_bytes\t: %lu\n",
		(unsigned long)dp->stat.tx_bytes);

	ret += seq_puts(s, "tx_packets\t:");
	for (i = 0; i < PSD_QUEUE_CNT; ++i)
		ret += seq_printf(s, " %lu",
			(unsigned long)dp->stat.tx_packets[i]);
	ret += seq_puts(s, "\n");

	ret += seq_puts(s, "tx_packets_delay\t:");
	for (i = 0; i < PSD_QUEUE_CNT; ++i)
		ret += seq_printf(s, " %llu",
			(unsigned long long)dp->stat.tx_packets_delay[i]);
	ret += seq_puts(s, "\n");

	ret += seq_printf(s, "tx_q_bytes\t: %lu\n",
		(unsigned long)dp->stat.tx_q_bytes);

	ret += seq_puts(s, "tx_q_packets\t:");
	for (i = 0; i < PSD_QUEUE_CNT; ++i)
		ret += seq_printf(s, " %lu",
			(unsigned long)dp->stat.tx_q_packets[i]);
	ret += seq_puts(s, "\n");

	ret += seq_printf(s, "tx_slots\t: %lu\n",
		(unsigned long)dp->stat.tx_slots);
	ret += seq_printf(s, "tx_interrupts\t: %lu\n",
		(unsigned long)dp->stat.tx_interrupts);
	ret += seq_printf(s, "tx_used_bytes\t: %lu\n",
		(unsigned long)dp->stat.tx_used_bytes);
	ret += seq_printf(s, "tx_free_bytes\t: %lu\n",
		(unsigned long)dp->stat.tx_free_bytes);
	ret += seq_printf(s, "tx_sched_cnt\t: %lu\n",
		(unsigned long)dp->stat.tx_sched_cnt);
	ret += seq_printf(s, "tx_resched_cnt\t: %lu\n",
		(unsigned long)dp->stat.tx_resched_cnt);
	ret += seq_printf(s, "tx_force_sched_cnt\t: %lu\n",
		(unsigned long)dp->stat.tx_force_sched_cnt);
	ret += seq_printf(s, "tx_sched_q_len\t: %lu\n",
		(unsigned long)dp->stat.tx_sched_q_len);

	return ret;
}

TEL_DEBUG_ENTRY(tx_q);
TEL_DEBUG_ENTRY(stat);

static ssize_t read_wm(struct file *file, char __user *user_buf,
	size_t count, loff_t *ppos)
{
	struct data_path *dp = file->private_data;
	char buf[PSD_QUEUE_CNT * 8 + 1];
	int *wm = dp->tx_wm;
	char *p, *pend;
	int i;

	p = buf;
	pend = buf + sizeof(buf) - 1;
	p[0] = '\0';

	for (i = 0; i < PSD_QUEUE_CNT; ++i)
		p += snprintf(p, pend - p, "%d ", wm[i]);

	buf[strlen(buf) - 1] = '\n';

	return simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
}

static ssize_t write_wm(struct file *file, const char __user *user_buf,
	size_t count, loff_t *ppos)
{
	struct data_path *dp = file->private_data;
	char buf[PSD_QUEUE_CNT * 8 + 1];
	int *wm = dp->tx_wm;
	char *p, *tok;
	const char delim[] = " \t";
	int i;
	int tmp;

	if (count > sizeof(buf) - 1) {
		pr_err("%s: user_buf is too large(%zu), expect less than %zu\n",
			__func__, count, sizeof(buf) - 1);
		return -EFAULT;
	}
	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;

	buf[count] = '\0';

	p = buf;

	for (i = 0; i < PSD_QUEUE_CNT; ++i) {
		while (p && *p && isspace(*p))
			++p;

		tok = strsep(&p, delim);
		if (!tok)
			break;

		if (kstrtoint(tok, 10, &tmp) < 0) {
			pr_err("%s: set wm[%d] error\n", __func__, i);
			break;
		}

		if (tmp >= dp->rbctl->tx_skbuf_num) {
			pr_err("%s: set wm[%d] error, ",
				__func__, i);
			pr_err("val %d exceed tx_skbuf_num %d\n",
				tmp, dp->rbctl->tx_skbuf_num);
			return -EFAULT;
		}

		wm[i] = tmp;
	}

	if (wm[0])
		pr_err("%s: wm[0] is set to non-zero!!\n", __func__);

	for (i = 0; i < PSD_QUEUE_CNT - 1; ++i) {
		if (wm[i] > wm[i + 1]) {
			pr_err("%s: wm[%d] is larger than wm[%d], reset wm[%d]\n",
				__func__, i, i + i, i + 1);
			wm[i + 1] = wm[i];
		}
	}
	return count;
}

static const struct file_operations fops_wm = {
	.read =		read_wm,
	.write =	write_wm,
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
				"tx_q", S_IRUGO, dp->dentry,
				dp, &fops_tx_q)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_file(
				"stat", S_IRUGO, dp->dentry,
				dp, &fops_stat)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_file(
				"wm", S_IRUGO | S_IWUSR, dp->dentry,
				dp, &fops_wm)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_bool(
				"enable_piggyback", S_IRUGO | S_IWUSR,
				dp->dentry, &dp->enable_piggyback)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_bool(
				"is_tx_stopped", S_IRUGO | S_IWUSR,
				dp->dentry, &dp->is_tx_stopped)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_u32(
				"tx_q_max_len", S_IRUGO | S_IWUSR,
				dp->dentry, &dp->tx_q_max_len)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_u16(
				"max_tx_shots", S_IRUGO | S_IWUSR,
				dp->dentry, &dp->max_tx_shots)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_u16(
				"max_rx_shots", S_IRUGO | S_IWUSR,
				dp->dentry, &dp->max_rx_shots)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_u16(
				"tx_sched_delay_in_ms", S_IRUGO | S_IWUSR,
				dp->dentry, &dp->tx_sched_delay_in_ms)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_u16(
				"tx_q_min_sched_len", S_IRUGO | S_IWUSR,
				dp->dentry, &dp->tx_q_min_sched_len)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_file(
				"copy_on_rx", S_IRUGO | S_IWUSR,
				dp->dentry, dp, &fops_copy_on_rx)))
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

/* cp psd xmit stopped notify interrupt */
static u32 acipc_cb_psd_rb_stop(u32 status)
{
	struct data_path *dp = &data_path;
	struct shm_rbctl *rbctl = dp->rbctl;

	__pm_wakeup_event(&dp_acipc_wakeup, 5000);
	pr_warn("MSOCK: %s!!!\n", __func__);

	shm_rb_stop(rbctl);

	if (atomic_read(&dp->state) == dp_state_opened) {
		psd_rx_stop();
		data_path_schedule_rx(dp);
	}

	return 0;
}

/* cp psd wakeup ap xmit interrupt */
static u32 acipc_cb_psd_rb_resume(u32 status)
{
	struct data_path *dp = &data_path;
	struct shm_rbctl *rbctl = dp->rbctl;

	__pm_wakeup_event(&dp_acipc_wakeup, 2000);
	pr_warn("MSOCK: %s!!!\n", __func__);

	shm_rb_resume(rbctl);

	if (atomic_read(&dp->state) == dp_state_opened) {
		/* do not need to check queue length,
		 * as we need to resume upper layer in tx_func */
		data_path_schedule_tx(dp);
	}

	return 0;
}

/* psd new packet arrival interrupt */
static u32 acipc_cb_psd_cb(u32 status)
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

	data_path_schedule_rx(dp);

	return 0;
}

static int dp_acipc_init(void)
{
	/* we do not check any return value */
	acipc_event_bind(ACIPC_RINGBUF_PSD_TX_STOP, acipc_cb_psd_rb_stop,
		ACIPC_CB_NORMAL, NULL);
	acipc_event_bind(ACIPC_RINGBUF_PSD_TX_RESUME, acipc_cb_psd_rb_resume,
		ACIPC_CB_NORMAL, NULL);
	acipc_event_bind(ACIPC_SHM_PSD_PACKET_NOTIFY, acipc_cb_psd_cb,
		ACIPC_CB_NORMAL, NULL);

	return 0;
}

static void dp_acipc_exit(void)
{
	acipc_event_unbind(ACIPC_SHM_PSD_PACKET_NOTIFY);
	acipc_event_unbind(ACIPC_RINGBUF_PSD_TX_RESUME);
	acipc_event_unbind(ACIPC_RINGBUF_PSD_TX_STOP);
}

static int dp_init_rxs_array(struct data_path *dp)
{
	kfree(dp->rxs);

	dp->rxs = kzalloc(dp->rbctl->rx_skbuf_num * sizeof(struct rx_slot),
			  GFP_KERNEL);
	if (!dp->rxs)
		return -1;
	return 0;
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

	spin_lock_init(&dp->ap_rptr_lock);

	tx_q_init(dp);

	memset(&dp->stat, 0, sizeof(dp->stat));

	tasklet_init(&dp->tx_tl, data_path_tx_func,
		     (unsigned long)dp);
	tasklet_init(&dp->rx_tl, data_path_rx_func,
		     (unsigned long)dp);

	init_timer(&dp->tx_sched_timer);
	dp->tx_sched_timer.function = tx_sched_timeout;
	dp->tx_sched_timer.data =
		(unsigned long)dp;

	if (dp_debugfs_init(dp) < 0) {
		pr_err("%s: debugfs failed\n", __func__);
		atomic_set(&dp->state, dp_state_idle);
		return -1;
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

	dp->tx_q_max_len = 0;
	dp->is_tx_stopped = false;
	tx_q_clean(dp);

	del_timer_sync(&dp->tx_sched_timer);

	tasklet_kill(&dp->tx_tl);
	tasklet_kill(&dp->rx_tl);

	kfree(dp->rxs);
	dp->rxs = NULL;

	atomic_set(&dp->state, dp_state_idle);
}

static int dp_data_tx(void *priv, int cid, int simid, int prio,
	struct sk_buff *skb, void *queue __attribute__((__unused__)))
{
	struct data_path *dp = (struct data_path *)priv;
	struct pduhdr *hdr;
	struct sk_buff *skb2;
	unsigned len;
	unsigned tailpad;

	/* data path is not open, drop the packet and return */
	if (!dp || atomic_read(&dp->state) != dp_state_opened) {
		pr_err("%s: data path is not open!\n", __func__);
		goto drop;
	}

	len = skb->len;
	if (padded_size(sizeof(*hdr) + len, DATA_ALIGN_SIZE) >
			data_path_max_payload(dp)) {
		pr_err("%s: packet too large %d\n", __func__, len);
		goto drop;
	}

	tailpad = padding_size(sizeof(*hdr) + len, DATA_ALIGN_SIZE);

	if (likely(!skb_cloned(skb))) {
		int headroom = skb_headroom(skb);
		int tailroom = skb_tailroom(skb);

		/* enough room as-is? */
		if (likely(sizeof(*hdr) + tailpad <= headroom + tailroom)) {
			/* do not need to be readjusted */
			if (sizeof(*hdr) <= headroom && tailpad <= tailroom)
				goto fill;

			skb->data = memmove(skb->head + sizeof(*hdr),
					    skb->data, len);
			skb_set_tail_pointer(skb, len);
			goto fill;
		}
	}

	/* create a new skb, with the correct size (and tailpad) */
	skb2 = skb_copy_expand(skb, sizeof(*hdr), tailpad + 1, GFP_ATOMIC);
	if (skb2)
		trace_psd_xmit_skb_realloc(skb, skb2);
	if (unlikely(!skb2))
		return PSD_DATA_SEND_BUSY;
	dev_kfree_skb_any(skb);
	skb = skb2;

	/* fill out the pdu header */
fill:
	hdr = (void *)__skb_push(skb, sizeof(*hdr));
	memset(hdr, 0, sizeof(*hdr));
	hdr->length = cpu_to_be16(len);
	hdr->cid = cid;
	hdr->simid = simid;
	memset(skb_put(skb, tailpad), 0, tailpad);

	data_path_xmit(dp, skb, prio);
	return PSD_DATA_SEND_OK;
drop:
	dev_kfree_skb_any(skb);
	return PSD_DATA_SEND_DROP;
}

static void dp_link_status_changed(void *priv, int status)
{
	data_path_broadcast_msg((struct data_path *)priv, status);
}

#define SHM_PSD_TX_SKBUF_SIZE	2048	/* PSD tx maximum packet size */
#define SHM_PSD_RX_SKBUF_SIZE	16384	/* PSD rx maximum packet size */
static int shm_param_init(struct shm_rbctl *rbctl,
	const struct cpload_cp_addr *addr)
{
	if (!addr)
		return -1;

	/* psd dedicated ring buffer */
	rbctl->skctl_pa = addr->psd_skctl_pa;

	rbctl->tx_skbuf_size = SHM_PSD_TX_SKBUF_SIZE;
	rbctl->rx_skbuf_size = SHM_PSD_RX_SKBUF_SIZE;

	rbctl->tx_pa = addr->psd_tx_pa;
	rbctl->rx_pa = addr->psd_rx_pa;

	rbctl->tx_total_size = addr->psd_tx_total_size;
	rbctl->rx_total_size = addr->psd_rx_total_size;

	rbctl->tx_skbuf_num =
		rbctl->tx_total_size /
		rbctl->tx_skbuf_size;
	rbctl->rx_skbuf_num =
		rbctl->rx_total_size /
		rbctl->rx_skbuf_size;

	rbctl->tx_skbuf_low_wm =
		(rbctl->tx_skbuf_num + 1) / 4;
	rbctl->rx_skbuf_low_wm =
		(rbctl->rx_skbuf_num + 1) / 4;

	return 0;
}

static inline void dp_init_wm(struct data_path *dp)
{
	dp->tx_wm[PSD_QUEUE_HIGH] = 0;
	dp->tx_wm[PSD_QUEUE_DEFAULT]
		= dp->rbctl->tx_skbuf_num / 10;
}

static int dp_set_addr(void *priv, const struct cpload_cp_addr *addr)
{
	struct data_path *dp = (struct data_path *)priv;

	if (!addr->first_boot)
		shm_rb_exit(dp->rbctl);

	shm_param_init(dp->rbctl, addr);

	if (dp_init_rxs_array(dp)) {
		pr_err("%s: failed to allocate rxs array\n", __func__);
		return -1;
	}

	dp_init_wm(dp);
	if (shm_rb_init(dp->rbctl, psd_debugfs_root_dir) < 0)
		pr_err("%s: init psd rbctl failed\n", __func__);

	return 0;
}

static bool dp_is_tx_stopped(void *priv)
{
	struct data_path *dp = (struct data_path *)priv;
	return dp->is_tx_stopped;
}

static size_t dp_get_packet_length(const unsigned char *hdr)
{
	struct shm_psd_skhdr *skhdr = (struct shm_psd_skhdr *)hdr;
	return skhdr->length + sizeof(*skhdr);
}

static struct shm_callback dp_shm_cb = {
	.get_packet_length = dp_get_packet_length,
};

static struct shm_rbctl psd_rbctl = {
	.name = "cp-psd",
	.cbs = &dp_shm_cb,
	.va_lock = __MUTEX_INITIALIZER(psd_rbctl.va_lock),
};

static struct data_path data_path = {
	.state = ATOMIC_INIT(dp_state_idle),
	.name = "data-pathv1",
	.rbctl = &psd_rbctl,
	.tx_q_max_len = MAX_TX_Q_LEN,
	.is_tx_stopped = false,
	.enable_piggyback = true,
	.max_tx_shots = MAX_TX_SHOTS,
	.max_rx_shots = MAX_RX_SHOTS,
	.tx_sched_delay_in_ms = TX_SCHED_DELAY,
	.tx_q_min_sched_len = TX_MIN_SCHED_LEN,
	.rx_copy_lock = __MUTEX_INITIALIZER(data_path.rx_copy_lock),
	.rx_copy = STATIC_KEY_INIT_TRUE,
	.copy_on_rx = true,
	.local_ap_rptr = 0,
	.rxs = NULL,
};

static struct psd_driver dp_drvier = {
	.name = "data-pathv1",
	.init = dp_init,
	.exit = dp_exit,
	.set_addr = dp_set_addr,
	.data_tx = dp_data_tx,
	.is_tx_stopped = dp_is_tx_stopped,
	.link_status_changed = dp_link_status_changed,
	.version = 1,
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
