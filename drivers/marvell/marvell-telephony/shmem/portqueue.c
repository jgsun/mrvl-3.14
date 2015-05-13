/*
    portqueue.c Created on: Jul 29, 2010, Jinhua Huang <jhhuang@marvell.com>

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

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/pm_wakeup.h>
#include <linux/pxa9xx_acipc.h>
#include "shm_share.h"
#include "shm.h"
#include "portqueue.h"
#include "tel_trace.h"

static struct wakeup_source port_tx_wakeup;
static struct wakeup_source port_rx_wakeup;

/* forward static function prototype */
static void portq_tx_worker(struct work_struct *work);
static void portq_rx_worker(struct work_struct *work);

static struct portq_group **portq_grp;
static unsigned portq_group_num;

#define DUMP_PORT(x)	(1<<((x)+3))
#define DUMP_TX		(1<<0)
#define DUMP_RX		(1<<1)
#define DUMP_TX_SP (1<<2)
#define DUMP_RX_SP (1<<3)

#define DATA_TX		0
#define DATA_RX		1

static void data_dump(const unsigned char *data, unsigned int len, int port,
	       int direction, u32 dump_flag)
{
	if (direction == DATA_TX) {
		if ((dump_flag & DUMP_TX) && (dump_flag & DUMP_PORT(port))) {
			pr_info("portq TX: DUMP BEGIN port :%d, Length:%u --\n",
			     port, len);
			if (!(dump_flag & DUMP_TX_SP))
				print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
						data, len, 0);
		}
	} else if (direction == DATA_RX) {
		if ((dump_flag & DUMP_RX) && (dump_flag & DUMP_PORT(port))) {
			pr_info("portq RX: DUMP BEGIN port :%d, Length:%u --\n",
			     port, len);
			if (!(dump_flag & DUMP_RX_SP))
				print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
						data, len, 0);
		}
	}
	return;
}

/* check if tx queue is full */
static inline bool portq_is_tx_full(struct portq *portq)
{
	return skb_queue_len(&portq->tx_q) >= portq->tx_q_limit;
}

/* check if rx queue is empty */
static inline bool portq_is_rx_empty(struct portq *portq)
{
	return skb_queue_empty(&portq->rx_q);
}

/* check if rx queue is below low water-mark */
static inline bool portq_is_rx_below_lo_wm(struct portq *portq)
{
	return skb_queue_len(&portq->rx_q) < portq->rx_q_low_wm;
}

/* check if rx queue is above high water-mark */
static inline bool portq_is_rx_above_hi_wm(struct portq *portq)
{
	return skb_queue_len(&portq->rx_q) >= portq->rx_q_high_wm;
}

/* check if cp xmit has been throttled by ap */
static inline bool portq_is_cp_xmit_throttled(struct portq *portq)
{
	return (1 << portq->port) & portq->grp->portq_local_port_fc;
}

/* check if ap xmit has been throttled by cp */
static inline bool portq_is_ap_xmit_throttled(struct portq *portq)
{
	return (1 << portq->port) & portq->grp->portq_remote_port_fc;
}

/* schedule portq tx_work */
static inline void portq_schedule_tx(struct portq_group *pgrp)
{
	queue_work(pgrp->wq, &pgrp->tx_work);
}

/* schedule portq rx_work */
static inline void portq_schedule_rx(struct portq_group *pgrp)
{
	queue_work(pgrp->wq, &pgrp->rx_work.work);
}

void portq_recv_throttle(struct portq *portq)
{
	struct portq_group *pgrp = portq->grp;
	if (!portq_is_cp_xmit_throttled(portq)) {
		spin_lock(&pgrp->portq_local_port_fc_lock);
		pgrp->portq_local_port_fc |= (1 << portq->port);
		pgrp->rbctl->skctl_va->ap_port_fc = pgrp->portq_local_port_fc;
		portq->stat_fc_ap_throttle_cp++;
		pgrp->ops->notify_fc_change();
		pr_warn(
			   "MSOCK: port %d AP throttle CP!!!\n",
			   portq->port);
		spin_unlock(&pgrp->portq_local_port_fc_lock);
	}
}

void portq_recv_unthrottle(struct portq *portq)
{
	struct portq_group *pgrp = portq->grp;
	if (pgrp->ops->is_synced() &&
	    portq_is_cp_xmit_throttled(portq)) {
		unsigned long flags;
		spin_lock_irqsave(&pgrp->portq_local_port_fc_lock, flags);
		pgrp->portq_local_port_fc &= ~(1 << portq->port);
		pgrp->rbctl->skctl_va->ap_port_fc = pgrp->portq_local_port_fc;
		portq->stat_fc_ap_unthrottle_cp++;
		pgrp->ops->notify_fc_change();
		pr_warn("MSOCK: port %d AP unthrottle CP!!!\n",
		       portq->port);
		spin_unlock_irqrestore(&pgrp->portq_local_port_fc_lock, flags);
	}
}

void portq_packet_recv_cb(struct portq_group *pgrp)
{
	__pm_wakeup_event(pgrp->ipc_ws, 5000);
	spin_lock(&pgrp->rx_work_lock);
	if (!pgrp->is_rx_work_running) {
		pgrp->is_rx_work_running = true;
		portq_schedule_rx(pgrp);
	}
	spin_unlock(&pgrp->rx_work_lock);
}

void portq_port_fc_cb(struct portq_group *pgrp)
{
	int port = 0;
	struct portq *portq;
	unsigned int temp_cp_port_fc = pgrp->rbctl->skctl_va->cp_port_fc;
	unsigned int changed = pgrp->portq_remote_port_fc ^ temp_cp_port_fc;

	__pm_wakeup_event(pgrp->ipc_ws, 2000);
	spin_lock(&pgrp->list_lock);

	while ((changed >>= 1)) {
		port++;
		if (changed & 1) {
			portq = pgrp->port_list[port];
			if (!portq)
				continue;

			spin_lock(&portq->lock);
			if (temp_cp_port_fc & (1 << port)) {
				portq->stat_fc_cp_throttle_ap++;
				pr_warn(
				       "MSOCK: port %d is throttled by CP!!!\n",
				       port);
			} else {
				portq->stat_fc_cp_unthrottle_ap++;
				pr_warn(
				       "MSOCK: port %d is unthrottled by CP!!!\n",
				       port);
			}
			spin_unlock(&portq->lock);
		}
	}

	spin_unlock(&pgrp->list_lock);

	pgrp->portq_remote_port_fc = temp_cp_port_fc;

	/* schedule portq tx_worker to try potential transmission */
	portq_schedule_tx(pgrp);
}

void portq_rb_stop_cb(struct portq_group *pgrp)
{

	shm_rb_stop(pgrp->rbctl);

	__pm_wakeup_event(pgrp->ipc_ws, 5000);

	/*
	 * schedule portq rx_worker to try potential wakeup, since share memory
	 * maybe already empty when we acqiure this interrupt event
	 */
	pr_warn("MSOCK: portq_rb_stop_cb!!!\n");
	portq_schedule_rx(pgrp);
}

void portq_rb_resume_cb(struct portq_group *pgrp)
{
	shm_rb_resume(pgrp->rbctl);

	__pm_wakeup_event(pgrp->ipc_ws, 2000);

	/* schedule portq tx_worker to try potential transmission */
	pr_warn("MSOCK: portq_rb_resume_cb!!!\n");
	portq_schedule_tx(pgrp);
}

/* portq_init */
int portq_init(struct portq_group **group_list, unsigned num)
{
	int i, ret;

	wakeup_source_init(&port_tx_wakeup, "port_tx_wakeups");
	wakeup_source_init(&port_rx_wakeup, "port_rx_wakeups");
	for (i = 0; i < num; ++i) {
		INIT_LIST_HEAD(&group_list[i]->tx_head);
		INIT_WORK(&group_list[i]->tx_work, portq_tx_worker);
		INIT_DELAYED_WORK(&group_list[i]->rx_work, portq_rx_worker);
		spin_lock_init(&group_list[i]->tx_work_lock);
		spin_lock_init(&group_list[i]->rx_work_lock);
		spin_lock_init(&group_list[i]->list_lock);
		spin_lock_init(&group_list[i]->portq_local_port_fc_lock);

		ret = group_list[i]->ops->init();
		if (ret) {
			while (--i >= 0)
				group_list[i]->ops->exit();
			return ret;
		}
	}

	portq_grp = group_list;
	portq_group_num = num;

	return 0;
}

/* portq_exit */
void portq_exit(void)
{
	unsigned i;

	wakeup_source_trash(&port_tx_wakeup);
	wakeup_source_trash(&port_rx_wakeup);

	for (i = 0; i < portq_group_num; ++i)
		portq_grp[i]->ops->exit();

	portq_grp = NULL;
	portq_group_num = 0;
}

struct portq *portq_get(int port)
{
	struct portq_group *pgrp = portq_grp_by_port(port);
	struct portq *portq = NULL;

	if (pgrp) {
		spin_lock_irq(&pgrp->list_lock);
		portq = pgrp->port_list[port - pgrp->port_offset];
		spin_unlock_irq(&pgrp->list_lock);
	}

	return portq;
}

/* portq_open */
struct portq *portq_open(int port)
{
	return portq_open_with_cb(port, NULL, NULL);
}

/* portq_open with receive callback*/
struct portq *portq_open_with_cb(int port,
		void (*clbk)(struct sk_buff *, void *), void *arg)
{
	struct portq *portq;
	struct portq_group *pgrp;
	struct shm_rbctl *rbctl;

	pgrp = portq_grp_by_port(port);

	if (!pgrp || !pgrp->is_open)
		return ERR_PTR(-ENODEV);

	rbctl = pgrp->rbctl;

	spin_lock_irq(&pgrp->list_lock);
	if (pgrp->port_list[port - pgrp->port_offset]) {
		pgrp->port_list[port - pgrp->port_offset]->refcounts++;
		spin_unlock_irq(&pgrp->list_lock);
		return pgrp->port_list[port - pgrp->port_offset];
	}

	/* Allocate a new port structure */
	portq = kmalloc(sizeof(*portq), GFP_ATOMIC);
	if (!portq) {
		spin_unlock_irq(&pgrp->list_lock);
		return ERR_PTR(-ENOMEM);
	}

	/* port queue init */
	skb_queue_head_init(&portq->tx_q);
	skb_queue_head_init(&portq->rx_q);
	init_waitqueue_head(&portq->tx_wq);
	init_waitqueue_head(&portq->rx_wq);
	portq->port = port;
	portq->priority = pgrp->priority[port - pgrp->port_offset];
	portq->status = 0;
	portq->grp = pgrp;
	spin_lock_init(&portq->lock);

	portq->tx_q_limit = PORTQ_TX_MSG_NUM;
	portq->rx_q_low_wm = PORTQ_RX_MSG_LO_WM;
	portq->rx_q_high_wm = PORTQ_RX_MSG_HI_WM;
	switch (portq->port) {
	case CIDATASTUB_PORT:
		portq->tx_q_limit = PORTQ_TX_MSG_HUGE_NUM;
		portq->rx_q_low_wm =
		    max((rbctl->rx_skbuf_num >> 1),
			PORTQ_RX_MSG_HUGE_LO_WM);
		portq->rx_q_high_wm =
		    max((rbctl->rx_skbuf_num << 1),
			PORTQ_RX_MSG_HUGE_HI_WM);
		break;

	default:
		break;
	}

	portq->stat_tx_request = 0L;
	portq->stat_tx_sent = 0L;
	portq->stat_tx_drop = 0L;
	portq->stat_tx_queue_max = 0L;
	portq->stat_rx_indicate = 0L;
	portq->stat_rx_got = 0L;
	portq->stat_rx_queue_max = 0L;
	portq->stat_fc_ap_throttle_cp = 0L;
	portq->stat_fc_ap_unthrottle_cp = 0L;
	portq->stat_fc_cp_throttle_ap = 0L;
	portq->stat_fc_cp_unthrottle_ap = 0L;
	portq->recv_cb = clbk;
	portq->recv_arg = arg;

	/* add new portq to port array */
	pgrp->port_list[port - pgrp->port_offset] = portq;
	portq->refcounts = 1;
	spin_unlock_irq(&pgrp->list_lock);

	return portq;
}

/* portq_close */
void portq_close(struct portq *portq)
{
	struct portq_group *pgrp = portq->grp;
	int port = portq->port - pgrp->port_offset;

	spin_lock_irq(&pgrp->list_lock);

	pgrp->port_list[port]->refcounts--;

	if (pgrp->port_list[port]->refcounts > 0) {
		spin_unlock_irq(&pgrp->list_lock);
		return;
	}
	spin_lock(&portq->lock);
	if (portq->status & PORTQ_STATUS_XMIT_QUEUED)
		list_del(&portq->tx_list);

	portq->recv_cb = NULL;
	portq->recv_arg = NULL;

	/* clean pending packets */
	skb_queue_purge(&portq->tx_q);
	skb_queue_purge(&portq->rx_q);
	spin_unlock(&portq->lock);

	/* delete port from the portq array */
	pgrp->port_list[port] = NULL;

	spin_unlock_irq(&pgrp->list_lock);

	/* free memory */
	kfree(portq);
}

/* queue the packet to the xmit queue */
int portq_xmit(struct portq *portq, struct sk_buff *skb, bool block)
{
	struct list_head *list;
	unsigned long flags;
	struct portq_group *pgrp = portq->grp;

	spin_lock_irqsave(&portq->lock, flags);

	/* Make sure there's space to write */
	while (portq_is_tx_full(portq)) {
		if (block) {
			portq->status |= PORTQ_STATUS_XMIT_FULL;

			/* release the lock before wait */
			spin_unlock_irqrestore(&portq->lock, flags);

			if (wait_event_interruptible(portq->tx_wq,
					!(portq->status
						&
						PORTQ_STATUS_XMIT_FULL))) {
				/* signal: tell the fs layer to handle it */
				return -ERESTARTSYS;
			}

			/* otherwise loop, but first reacquire the lock */
			spin_lock_irqsave(&portq->lock, flags);

		} else {
			/* remove and free the first skb in queue */
			struct sk_buff *first = skb_dequeue(&portq->tx_q);
			portq->stat_tx_drop++;
			kfree_skb(first);
		}
	}

	if (!pgrp->ops->is_synced()) {
		spin_unlock_irqrestore(&portq->lock, flags);
		return -1;
	}

	/* add message to queue */
	skb_queue_tail(&portq->tx_q, skb);
	portq->stat_tx_request++;
	if (skb_queue_len(&portq->tx_q) > portq->stat_tx_queue_max)
		portq->stat_tx_queue_max = skb_queue_len(&portq->tx_q);

	if (!(portq->status & PORTQ_STATUS_XMIT_QUEUED)) {
		/* release the lock */
		spin_unlock_irqrestore(&portq->lock, flags);

		/*
		 * PORTQ_STATUS_XMIT_QUEUED set and tx_list add must
		 * be atomic
		 */
		spin_lock_irqsave(&pgrp->list_lock, flags);
		spin_lock(&portq->lock);

		/*
		 * double confirm PORTQ_STATUS_XMIT_QUEUED is not set
		 * and the queue is not empty
		 */
		if (!(portq->status & PORTQ_STATUS_XMIT_QUEUED) &&
			skb_queue_len(&portq->tx_q)) {
			portq->status |= PORTQ_STATUS_XMIT_QUEUED;

			list_for_each(list, &pgrp->tx_head) {
				struct portq *next =
					list_entry(list, struct portq, tx_list);
				if (next->priority > portq->priority)
					break;
			}
			list_add_tail(&portq->tx_list, list);
		}
		/* release the lock */
		spin_unlock(&portq->lock);
		spin_unlock_irqrestore(&pgrp->list_lock, flags);
	} else {
		/* release the lock */
		spin_unlock_irqrestore(&portq->lock, flags);
	}

	/* if necessarily, schedule tx_work to send packet */
	spin_lock_irqsave(&pgrp->tx_work_lock, flags);
	if (!pgrp->is_tx_work_running) {
		pgrp->is_tx_work_running = true;
		portq_schedule_tx(pgrp);
	}
	spin_unlock_irqrestore(&pgrp->tx_work_lock, flags);

	return 0;
}

/* get a new packet from rx queue */
struct sk_buff *portq_recv(struct portq *portq, bool block)
{
	struct sk_buff *skb;
	unsigned long flags;

	spin_lock_irqsave(&portq->lock, flags);

	/* Make sure there's packet to be read */
	while (block && portq_is_rx_empty(portq)) {

		portq->status |= PORTQ_STATUS_RECV_EMPTY;

		/* release the lock before wait */
		spin_unlock_irqrestore(&portq->lock, flags);

		if (wait_event_interruptible(portq->rx_wq,
					     !(portq->status &
					       PORTQ_STATUS_RECV_EMPTY))) {
			/* signal: tell the fs layer to handle it */
			return ERR_PTR(-ERESTARTSYS);
		}

		/* otherwise loop, but first reacquire the lock */
		spin_lock_irqsave(&portq->lock, flags);
	}

	/* delete message from queue */
	skb = skb_dequeue(&portq->rx_q);
	portq->stat_rx_got++;

	if (skb && portq_is_rx_below_lo_wm(portq))
		portq_recv_unthrottle(portq);

	/* release the lock */
	spin_unlock_irqrestore(&portq->lock, flags);

	return skb;
}

unsigned int portq_poll(struct portq *portq, struct file *filp,
			poll_table *wait)
{
	unsigned int mask = 0;
	unsigned long flags;

	poll_wait(filp, &portq->rx_wq, wait);
	poll_wait(filp, &portq->tx_wq, wait);

	spin_lock_irqsave(&portq->lock, flags);

	if (portq_is_rx_empty(portq)) {
		/* must set this,
		 * otherwise rx_worker will not wakeup polling thread */
		portq->status |= PORTQ_STATUS_RECV_EMPTY;
	} else {
		mask |= POLLIN | POLLRDNORM;
	}

	if (portq_is_tx_full(portq)) {
		/* must set this,
		 * otherwise tx_worker will not wakeup polling thread */
		portq->status |= PORTQ_STATUS_XMIT_FULL;
	} else {
		mask |= POLLOUT | POLLWRNORM;
	}
	spin_unlock_irqrestore(&portq->lock, flags);

	return mask;
}

/* broadcast the linkdown/linkup messages to all the port */
void portq_broadcast_msg(u8 grp_type, int proc)
{
	struct portq_group *pgrp = portq_grp[grp_type];
	struct portq *portq;
	struct shm_skhdr *hdr;
	int i;
	unsigned long flags;
	ShmApiMsg *msg;

	spin_lock_irqsave(&pgrp->list_lock, flags);

	for (i = 0; i < pgrp->port_cnt; i++) {
		struct sk_buff *skb;

		portq = pgrp->port_list[i];
		if (!portq)
			continue;

		if (portq->port == AUDIOSTUB_PORT)
			continue; /* audiostub monitors link status itself */
		/*
		 * allocate sk_buff first, the size = 32 is enough
		 * to hold all kind of broadcasting messages
		 */
		skb = alloc_skb(32, GFP_ATOMIC);
		if (!skb) {
			/* don't known how to do better, just return */
			pr_err("MSOCK: %s: out of memory.\n",
			       __func__);
			spin_unlock_irqrestore(&pgrp->list_lock, flags);
			return;
		}

		/* reserve port header space */
		skb_reserve(skb, sizeof(*hdr));
		msg = (ShmApiMsg *) skb_put(skb, sizeof(*msg));
		msg->svcId = portq->port;	/* svcId == port */
		msg->procId = proc;
		msg->msglen = 0;

		/* reuse the port header */
		hdr = (struct shm_skhdr *)skb_push(skb, sizeof(*hdr));

		/* fill in shm header */
		hdr->address = 0;
		hdr->port = portq->port;
		hdr->checksum = 0;
		hdr->length = sizeof(*msg);

		spin_lock(&portq->lock);

		if (portq->recv_cb) {
			void (*cb)(struct sk_buff *, void *);
			cb = portq->recv_cb;
			skb_pull(skb, sizeof(struct shm_skhdr));
			portq->stat_rx_indicate++;
			portq->stat_rx_got++;
			spin_unlock(&portq->lock);
			spin_unlock_irqrestore(&pgrp->list_lock, flags);
			cb(skb, portq->recv_arg);
			spin_lock_irqsave(&pgrp->list_lock, flags);
			continue;
		}

		/* add to port rx queue */
		skb_queue_tail(&portq->rx_q, skb);
		portq->stat_rx_indicate++;

		/* notify upper layer that packet available */
		if (portq->status & PORTQ_STATUS_RECV_EMPTY) {
			portq->status &= ~PORTQ_STATUS_RECV_EMPTY;
			wake_up_interruptible(&portq->rx_wq);
		}

		spin_unlock(&portq->lock);
	}

	spin_unlock_irqrestore(&pgrp->list_lock, flags);
}

/* flush queue and init */
static void portq_flush_init(struct portq_group *pgrp)
{
	struct portq *portq;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&pgrp->list_lock, flags);

	for (i = 0; i < pgrp->port_cnt; i++) {

		portq = pgrp->port_list[i];
		if (!portq)
			continue;

		/* acquire queue lock first */
		spin_lock(&portq->lock);

		if (portq->status & PORTQ_STATUS_XMIT_QUEUED) {
			portq->status &= ~PORTQ_STATUS_XMIT_QUEUED;
			list_del(&portq->tx_list);
		}

		/* purge any tx packet in queue */
		skb_queue_purge(&portq->tx_q);

		/* wakeup blocked write */
		if (portq->status & PORTQ_STATUS_XMIT_FULL) {
			portq->status &= ~PORTQ_STATUS_XMIT_FULL;
			wake_up_interruptible(&portq->tx_wq);
		}

		/* purge any rx packet in queue */
		skb_queue_purge(&portq->rx_q);

		/* initialize statistics data */
		portq->stat_tx_request = 0L;
		portq->stat_tx_sent = 0L;
		portq->stat_tx_queue_max = 0L;
		portq->stat_rx_indicate = 0L;
		portq->stat_rx_got = 0L;
		portq->stat_rx_queue_max = 0L;
		portq->stat_fc_ap_throttle_cp = 0L;
		portq->stat_fc_ap_unthrottle_cp = 0L;
		portq->stat_fc_cp_throttle_ap = 0L;
		portq->stat_fc_cp_unthrottle_ap = 0L;

		spin_unlock(&portq->lock);
	}

	spin_unlock_irqrestore(&pgrp->list_lock, flags);

	/* make sure these variable in it's initial state */
	pgrp->is_rx_work_running = false;
	pgrp->is_tx_work_running = false;
	pgrp->rx_workq_sched_num = 0;
	pgrp->portq_local_port_fc = 0;
	pgrp->portq_remote_port_fc = 0;
}

/*
 * portq transmitter worker
 */
static void portq_tx_worker(struct work_struct *work)
{
	struct portq_group *pgrp =
		container_of(work, struct portq_group, tx_work);
	struct shm_rbctl *rbctl = pgrp->rbctl;
	struct portq *portq, *next;
	struct sk_buff *skb;
	int num, total = 0;
	int priority;
	while (1) {
		/*
		 * we do lock/unlock inner the loop, giving the other cpu(s) a
		 * chance to run the same worker when in SMP environments
		 */
		spin_lock_irq(&pgrp->list_lock);
		__pm_stay_awake(&port_tx_wakeup);
		if (rbctl->is_ap_xmit_stopped) {
			/* if any packet sent, notify cp */
			if (total > 0) {
				pgrp->ops->notify_sent();
			}
			__pm_relax(&port_tx_wakeup);
			spin_unlock_irq(&pgrp->list_lock);
			return;
		}

		/*
		 * num is used to count sent packet numbers during the
		 * following loop
		 */
		num = 0;

		priority = 0;	/* set 0 as a special value */

		/*
		 * priority schedule transmitting one packet every queue
		 * with the same priority
		 */
		list_for_each_entry_safe(portq, next, &pgrp->tx_head, tx_list) {

			if (!pgrp->ops->is_synced()) {
				/* if not sync, just return */
				__pm_relax(&port_tx_wakeup);
				spin_unlock_irq(&pgrp->list_lock);
				return;
			}

			/* acquire queue lock first */
			spin_lock(&portq->lock);

			if (portq_is_ap_xmit_throttled(portq)
					|| skb_queue_empty(&portq->tx_q)) {
				/* skip this queue */
				spin_unlock(&portq->lock);
				continue;
			}

			/* if ring buffer is full */
			if (shm_is_xmit_full(rbctl)) {
				/*
				 * notify CP that AP transmission stopped
				 * because of no tx ring buffer available,
				 * CP should wake me up after there are
				 * enough ring buffers free
				 */
				shm_notify_ap_tx_stopped(rbctl);
				pgrp->ops->tx_stop();

				/* release portq lock */
				spin_unlock(&portq->lock);

				/* if any packet sent, notify cp */
				if (total > 0) {
					pgrp->ops->notify_sent();
				}

				__pm_relax(&port_tx_wakeup);
				spin_unlock_irq(&pgrp->list_lock);
				return;
			}

			if (!priority) {
				/* first packet during this loop */
				priority = portq->priority;
			} else if (priority != portq->priority) {
				/*
				 * we only send packet with the same priority
				 * during this loop
				 */
				spin_unlock(&portq->lock); /* release lock */
				break;
			}

			/*
			 * otherwise, we meet either the first packet or the
			 * same priority packet situation, so do the sending
			 * operation
			 */
			skb = skb_dequeue(&portq->tx_q); /* rm skb from tx_q */
			portq->stat_tx_sent++;
			if (skb_queue_empty(&portq->tx_q)) {
				portq->status &= ~PORTQ_STATUS_XMIT_QUEUED;
				list_del(&portq->tx_list);
			}
			shm_xmit(rbctl, skb);	/* write to rb */
			data_dump(skb->data, skb->len, portq->port, DATA_TX, pgrp->dump_flag);
			trace_portq_xmit(pgrp->grp_type, portq->port, skb->len);
			kfree_skb(skb);	/* free skb memory */
			num++, total++;	/* count */

			/* notify upper layer that free socket available */
			if (portq->status & PORTQ_STATUS_XMIT_FULL) {
				portq->status &= ~PORTQ_STATUS_XMIT_FULL;
				wake_up_interruptible(&portq->tx_wq);
			}

			spin_unlock(&portq->lock);	/* release lock */
		}

		/* very trick code, lock must be here */
		spin_lock(&pgrp->tx_work_lock);
		if (num == 0) {
			/* all the tx queue is empty or flow control blocked */

			pgrp->is_tx_work_running = false;

			spin_unlock(&pgrp->tx_work_lock);

			/* if any packet sent, notify cp */
			if (total > 0) {
				pgrp->ops->notify_sent();
			}
			/* unlock and return */
			__pm_relax(&port_tx_wakeup);
			spin_unlock_irq(&pgrp->list_lock);
			return;
		}
		spin_unlock(&pgrp->tx_work_lock);

		/*
		 * as a good citizen, we should give other people a
		 * chance to do their emergency jobs
		 *
		 * NOTICE: total may > PORTQ_TX_WORKQ_SHOTS
		 */
		if (total >= rbctl->tx_skbuf_num) {
			/* reschedule self again */
			portq_schedule_tx(pgrp);
			pgrp->ops->notify_sent();

			/* unlock and return */
			__pm_relax(&port_tx_wakeup);
			spin_unlock_irq(&pgrp->list_lock);
			return;
		}
		__pm_relax(&port_tx_wakeup);
		spin_unlock_irq(&pgrp->list_lock);
	}
}

/*
 * portq receiver worker
 */
static void portq_rx_worker(struct work_struct *work)
{
	struct portq_group *pgrp =
		container_of(work, struct portq_group, rx_work.work);
	struct shm_rbctl *rbctl = pgrp->rbctl;
	struct portq *portq;
	struct sk_buff *skb;
	int i, port;

	pgrp->rx_workq_sched_num++;
	for (i = 0; i < rbctl->rx_skbuf_num; i++) {

		if (!pgrp->ops->is_synced()) {
			/* if not sync, just return */
			spin_lock_irq(&pgrp->rx_work_lock);
			pgrp->is_rx_work_running = false;
			spin_unlock_irq(&pgrp->rx_work_lock);
			return;
		}

		/*
		 * we do lock/unlock inner the loop, giving the other cpu(s) a
		 * chance to run the same worker when in SMP environments
		 */
		spin_lock_irq(&pgrp->list_lock);

		/* process share memory socket buffer flow control */
		if (rbctl->is_cp_xmit_stopped
		    && shm_has_enough_free_rx_skbuf(rbctl)) {
			shm_notify_cp_tx_resume(rbctl);
			pgrp->ops->tx_resume();
		}

		/* be carefull and careful again, lock must be here */
		spin_lock(&pgrp->rx_work_lock);
		if (shm_is_recv_empty(rbctl)) {
			pgrp->is_rx_work_running = false;
			spin_unlock(&pgrp->rx_work_lock);
			spin_unlock_irq(&pgrp->list_lock);
			__pm_relax(pgrp->ipc_ws);
			return;
		}
		spin_unlock(&pgrp->rx_work_lock);

		skb = shm_recv(rbctl);
		if (!skb) {
			/* if out of memory, try reschedule after a tick */
			queue_delayed_work(pgrp->wq, &pgrp->rx_work, 1);
			spin_lock(&pgrp->rx_work_lock);
			pgrp->is_rx_work_running = false;
			spin_unlock(&pgrp->rx_work_lock);
			spin_unlock_irq(&pgrp->list_lock);
			pr_err_ratelimited(
			     "%s: invalid skb for receiving packet\n",
			     __func__);
			return;
		}

		/* get port */
		port = ((struct shm_skhdr *)skb->data)->port;
		if (port < pgrp->port_offset ||
			port >= (pgrp->port_offset + pgrp->port_cnt)) {
			kfree_skb(skb);
			spin_unlock_irq(&pgrp->list_lock);
			pr_err(
			     "%s: receiving packet in invalid port:%d\n",
			     __func__, port);
			continue;
		}

		portq = pgrp->port_list[port - pgrp->port_offset];

		if (!portq) {	/* port is closed */
			kfree_skb(skb);
			spin_unlock_irq(&pgrp->list_lock);
			pr_err(
			     "%s: receiving packet,but port:%d is closed\n",
			     __func__, port);
			continue;
		}
		__pm_wakeup_event(&port_rx_wakeup, 2000);
		data_dump(skb->data, skb->len, portq->port, DATA_RX, pgrp->dump_flag);

		trace_portq_recv(pgrp->grp_type, portq->port, skb->len);

		spin_lock(&portq->lock);

		if (portq->recv_cb) {
			void (*cb)(struct sk_buff *, void *);
			cb = portq->recv_cb;
			skb_pull(skb, sizeof(struct shm_skhdr));
			portq->stat_rx_indicate++;
			portq->stat_rx_got++;
			spin_unlock(&portq->lock);
			spin_unlock_irq(&pgrp->list_lock);
			cb(skb, portq->recv_arg);
			continue;
		}

		skb_queue_tail(&portq->rx_q, skb);
		portq->stat_rx_indicate++;
		if (skb_queue_len(&portq->rx_q) > portq->stat_rx_queue_max)
			portq->stat_rx_queue_max = skb_queue_len(&portq->rx_q);

		/* process port flow control */
		if (portq_is_rx_above_hi_wm(portq))
			portq_recv_throttle(portq);

		/* notify upper layer that packet available */
		if (portq->status & PORTQ_STATUS_RECV_EMPTY) {
			portq->status &= ~PORTQ_STATUS_RECV_EMPTY;
			wake_up_interruptible(&portq->rx_wq);
		}

		spin_unlock(&portq->lock);

		spin_unlock_irq(&pgrp->list_lock);
	}

	/*
	 * if goes here, maybe there are pending packets to process,
	 * so we reschedule it
	 */
	portq_schedule_rx(pgrp);
}

/************** portqueue group *********************/
void portq_grp_connect(u8 grp_type)
{
	portq_grp[grp_type]->ops->connect();
}

/* stop sync */
void portq_grp_disconnect(u8 grp_type)
{
	struct portq_group *pgrp = portq_grp[grp_type];

	pgrp->ops->disconnect();
	/* ensure that any scheduled work has run to completion */
	flush_workqueue(pgrp->wq);

	/*
	 * and now no work is active or will be schedule, so we can
	 * cleanup any packet queued and initialize some key data
	 * structure to the beginning state
	 */
	shm_rb_data_init(pgrp->rbctl);
	portq_flush_init(pgrp);
}

int portq_grp_open(u8 grp_type)
{
	struct portq_group *pgrp = portq_grp[grp_type];

	pgrp->wq =
	    alloc_workqueue(pgrp->name, WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!pgrp->wq) {
		pr_err("%s: can't create workqueue\n", __func__);
		return -1;
	}

	pgrp->port_list = kzalloc(sizeof(*pgrp->port_list) * pgrp->port_cnt,
		GFP_KERNEL);

	if (!pgrp->port_list) {
		destroy_workqueue(pgrp->wq);
		return -1;
	}
	pgrp->ops->open();
	pgrp->is_open = true;

	return 0;
}

void portq_grp_close(u8 grp_type)
{
	struct portq_group *pgrp = portq_grp[grp_type];

	if (pgrp->is_open) {
		pgrp->is_open = false;
		pgrp->ops->close();
		destroy_workqueue(pgrp->wq);
		kfree(pgrp->port_list);
	}
}

struct portq_group *portq_grp_get(u8 grp_type)
{
	if (grp_type < portq_group_num)
		return portq_grp[grp_type];
	else
		return NULL;
}

struct portq_group *portq_grp_by_port(int port)
{
	int i;

	for (i = 0; i < portq_group_num; i++) {
		if (port < portq_grp[i]->port_offset + portq_grp[i]->port_cnt &&
			port >= portq_grp[i]->port_offset)
			return portq_grp[i];
	}

	return NULL;
}

void portq_grp_dump(u8 grp_type)
{
	struct portq_group *pgrp = portq_grp[grp_type];
	struct shm_rbctl *rbctl = pgrp->rbctl;
	struct portq *portq;
	int i;

	pr_err("shm_is_ap_xmit_stopped: %d\n",
	       rbctl->is_ap_xmit_stopped);
	pr_err("shm_is_cp_xmit_stopped: %d\n",
	       rbctl->is_cp_xmit_stopped);
	pr_err("acipc_ap_stopped_num:   %ld\n",
	       rbctl->ap_stopped_num);
	pr_err("acipc_ap_resumed_num:   %ld\n",
	       rbctl->ap_resumed_num);
	pr_err("acipc_cp_stopped_num:   %ld\n",
	       rbctl->cp_stopped_num);
	pr_err("acipc_cp_resumed_num:   %ld\n",
	       rbctl->cp_resumed_num);
	pr_err("tx_socket_total:        %d\n",
	       rbctl->tx_skbuf_num);
	pr_err("tx_socket_free:         %d\n",
	       shm_free_tx_skbuf(rbctl));
	pr_err("rx_socket_total:        %d\n",
	       rbctl->rx_skbuf_num);
	pr_err("rx_socket_free:         %d\n",
	       shm_free_rx_skbuf(rbctl));

	pr_err("\nport  tx_current  tx_request  tx_sent  tx_drop  tx_queue_max"
	       "  rx_current  rx_indicate   rx_got  rx_queue_max"
	       "  local_throttle  local_unthrottle"
	       "  remote_throttle  remote_unthrottle\n");
	for (i = 0; i < pgrp->port_cnt; i++) {
		portq = pgrp->port_list[i];
		if (!portq)
			continue;
		pr_err("%4d %12d %12ld %9ld %9ld %14ld %12d %13ld "
		       "%9ld %14ld %16ld %18ld %16ld %18ld\n",
		       portq->port, skb_queue_len(&portq->tx_q),
		       portq->stat_tx_request, portq->stat_tx_sent,
		       portq->stat_tx_drop, portq->stat_tx_queue_max,
		       skb_queue_len(&portq->rx_q), portq->stat_rx_indicate,
		       portq->stat_rx_got, portq->stat_rx_queue_max,
		       portq->stat_fc_ap_throttle_cp,
		       portq->stat_fc_ap_unthrottle_cp,
		       portq->stat_fc_cp_throttle_ap,
		       portq->stat_fc_cp_unthrottle_ap);
	}
}
