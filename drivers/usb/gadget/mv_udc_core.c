/*
 * Copyright (C) 2011 Marvell International Ltd. All rights reserved.
 * Author: Chao Xie <chao.xie@marvell.com>
 *	   Neil Zhang <zhangwm@marvell.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include <linux/device.h>
#include <linux/usb/ch9.h>
#include <linux/usb/gadget.h>
#include <linux/usb/otg.h>
#include <linux/pm.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/types.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/of.h>
#include <linux/platform_data/mv_usb.h>
#include <linux/usb/mv_usb2_phy.h>
#include <linux/pm_qos.h>
#include <asm/unaligned.h>
#include <dt-bindings/usb/mv_usb.h>
#include <linux/power_supply.h>

#include "mv_udc.h"

#define DRIVER_DESC		"Marvell PXA USB Device Controller driver"
#define DRIVER_VERSION		"8 Nov 2010"

#define ep_dir(ep)	(((ep)->ep_num == 0) ? \
				((ep)->udc->ep0_dir) : ((ep)->direction))

/* timeout value -- usec */
#define RESET_TIMEOUT		10000
#define FLUSH_TIMEOUT		10000
#define EPSTATUS_TIMEOUT	10000
#define PRIME_TIMEOUT		10000
#define READSAFE_TIMEOUT	1000
#define MAX_EPPRIME_TIMES	100000

#define LOOPS_USEC_SHIFT	1
#define LOOPS_USEC		(1 << LOOPS_USEC_SHIFT)
#define LOOPS(timeout)		((timeout) >> LOOPS_USEC_SHIFT)
#define	ENUMERATION_DELAY	(2 * HZ)

static DECLARE_COMPLETION(release_done);

static const char driver_name[] = "mv_udc";
static const char driver_desc[] = DRIVER_DESC;

/* controller device global variable */
static struct mv_udc   *the_controller;

static int mv_udc_enable(struct mv_udc *udc);
static void mv_udc_disable(struct mv_udc *udc);

static void nuke(struct mv_ep *ep, int status);
static void stop_activity(struct mv_udc *udc, struct usb_gadget_driver *driver);
static void call_charger_notifier(struct mv_udc *udc);
static void irq_process_tr_complete(struct mv_udc *udc, u32 type);
static void ep_dtd_set_ioc(struct mv_udc *udc, u32 ep_num);

#define set_ioc_safe(dtd) \
do { \
	volatile u8 *tmp = (volatile u8 *)(&dtd->size_ioc_sts); \
	tmp += 1; \
	*tmp |= (DTD_IOC >> 8); \
} while (0)

static enum power_supply_type map_charger_type(unsigned int type)
{
	switch (type) {
	case NULL_CHARGER:
		return POWER_SUPPLY_TYPE_UNKNOWN;
	case DCP_CHARGER:
		return POWER_SUPPLY_TYPE_USB_DCP;
	case CDP_CHARGER:
		return POWER_SUPPLY_TYPE_USB_CDP;
	case NONE_STANDARD_CHARGER:
		return POWER_SUPPLY_TYPE_UPS;
	case DEFAULT_CHARGER:
		return POWER_SUPPLY_TYPE_UNKNOWN;
	case SDP_CHARGER:
	default:
		return POWER_SUPPLY_TYPE_USB;
	}
}

/* for endpoint 0 operations */
static const struct usb_endpoint_descriptor mv_ep0_desc = {
	.bLength =		USB_DT_ENDPOINT_SIZE,
	.bDescriptorType =	USB_DT_ENDPOINT,
	.bEndpointAddress =	0,
	.bmAttributes =		USB_ENDPOINT_XFER_CONTROL,
	.wMaxPacketSize =	EP0_MAX_PKT_SIZE,
};

/* Rx interrupt optimization */
static int rx_opt_timer_init(struct mv_udc *udc, u8 timer, u32 msec, int repeat)
{
	u32 val, ctrl;

	if (timer > 1)
		return -EINVAL;

	val = ((1000 * msec) - 1) & VUSBHS_GPTIMER_CTRL_GPTLD_MASK;
	ctrl = (repeat ? VUSBHS_GPTIMER_CTRL_GPTMODE : 0);

	if (timer == 0) {
		writel(cpu_to_le32(val), &udc->timer_regs->gptimer0ld);
		writel(cpu_to_le32(ctrl), &udc->timer_regs->gptimer0ctrl);
	} else {
		writel(cpu_to_le32(val), &udc->timer_regs->gptimer1ld);
		writel(cpu_to_le32(ctrl), &udc->timer_regs->gptimer1ctrl);
	}

	udc->gptimer[timer].num = timer;
	udc->gptimer[timer].msec = msec;
	udc->gptimer[timer].repeat = repeat;
	udc->gptimer[timer].initialized = true;

	return 0;
}

static int rx_opt_timer_start(struct mv_udc *udc, u8 timer)
{
	if (timer > 1)
		return -EINVAL;

	if (!udc->gptimer[timer].initialized)
		return -EINVAL;

	if (timer == 0)
		writel(cpu_to_le32(
			VUSBHS_GPTIMER_CTRL_GPTRUN | VUSBHS_GPTIMER_CTRL_GPTRST)
			, &udc->timer_regs->gptimer0ctrl);
	else
		writel(cpu_to_le32(
			VUSBHS_GPTIMER_CTRL_GPTRUN | VUSBHS_GPTIMER_CTRL_GPTRST)
			, &udc->timer_regs->gptimer1ctrl);
	return 0;
}

static int rx_opt_timer_stop(struct mv_udc *udc, u32 timer)
{
	u32 val;

	if (timer > 1)
		return -EINVAL;

	if (!udc->gptimer[timer].initialized)
		return -EINVAL;

	if (timer == 0) {
		val = readl(&udc->timer_regs->gptimer0ctrl) &
			cpu_to_le32(~VUSBHS_GPTIMER_CTRL_GPTRUN);
		writel(cpu_to_le32(val), &udc->timer_regs->gptimer0ctrl);
	} else {
		val = readl(&udc->timer_regs->gptimer1ctrl) &
			cpu_to_le32(~VUSBHS_GPTIMER_CTRL_GPTRUN);
		writel(cpu_to_le32(val), &udc->timer_regs->gptimer1ctrl);
	}

	return 0;
}

/* resets the rx_pkt_cnt for all EPs and starts a long timer */
static inline int kick_long_timer(struct mv_udc *udc)
{
	memset(udc->rx_pkt_cnt, 0, sizeof(udc->rx_pkt_cnt));
	return rx_opt_timer_start(udc, RX_LONG_TIMER_IDX);
}

static inline int stop_long_timer(struct mv_udc *udc)
{
	return rx_opt_timer_stop(udc, RX_LONG_TIMER_IDX);
}

static inline int kick_short_timer(struct mv_udc *udc)
{
	return rx_opt_timer_start(udc, RX_SHORT_TIMER_IDX);
}

static inline int stop_short_timer(struct mv_udc *udc)
{
	return rx_opt_timer_stop(udc, RX_SHORT_TIMER_IDX);
}

static void rx_opt_switch_state(struct mv_udc *udc, enum rx_opt_state_enum new)
{
	int i;
	if (udc->rx_opt_state.cur != new) {
		udc->rx_opt_state.cur = new;
		udc->rx_opt_state.hits[new]++;

		if (new == RX_OPT_DISABLE) {
			for (i = 1; i < 16; i++) {
				ep_dtd_set_ioc(udc, i);
				udc->rx_no_int[i] = 0;
			}
			stop_short_timer(udc);
			stop_long_timer(udc);
			memset(udc->rx_opt_state.hits, 0,
				sizeof(udc->rx_opt_state.hits));
			irq_process_tr_complete(udc, 0);
		}
	}
}

static void rx_opt_process_long_timeout(struct mv_udc *udc)
{
	int i, flag = 0;
	u32 pps_thr;
	enum rx_opt_state_enum state;

	pr_debug("process long timeout\n");

	udc->rx_opt_stats[RX_LONG_TIMER_IDX].expired++;
	state = udc->rx_opt_state.cur;

	switch (state) {
	case RX_OPT_DISABLE:
	case RX_OPT_IDLE:
		pr_err("state is %d and long timer expired\n", state);
		break;
	case RX_OPT_ANALYZE:
	case RX_OPT_ENABLE:
		pps_thr = (state == RX_OPT_ANALYZE) ?
			udc->rx_opt_conf.pps_high : udc->rx_opt_conf.pps_low;
		for (i = 1; i < 16; i++) {
			if (udc->rx_pkt_cnt[i] > pps_thr *
			    udc->rx_opt_conf.long_timeout_sec) {
				udc->rx_no_int[i] = 1;
				flag = 1;
			} else {
				if (state == RX_OPT_ENABLE && udc->rx_no_int[i])
					ep_dtd_set_ioc(udc, i);
				udc->rx_no_int[i] = 0;
			}
		}

		if (flag) {
			rx_opt_switch_state(udc, RX_OPT_ENABLE);
			kick_short_timer(udc);
			kick_long_timer(udc);
		} else {
			rx_opt_switch_state(udc, RX_OPT_IDLE);
			stop_short_timer(udc);
			stop_long_timer(udc);
		}
		break;
	default:
		pr_err("Unknown state\n");
		BUG();
		break;
	}
}

static void rx_opt_process_short_timeout(struct mv_udc *udc)
{
	pr_debug("process short timeout\n");
	udc->rx_opt_stats[RX_SHORT_TIMER_IDX].expired++;
	kick_short_timer(udc);
}

static u8 mv_udc_rx_opt_init(struct mv_udc *udc)
{
	int ret;

	udc->rx_opt_conf.pps_high = DEFAULT_PPS_HIGH_THR;
	udc->rx_opt_conf.pps_low = DEFAULT_PPS_LOW_THR;
	udc->rx_opt_conf.short_timeout_msec = DEFAULT_SHORT_TIMEOUT_MSEC;
	udc->rx_opt_conf.long_timeout_sec = DEFAULT_LONG_TIMEOUT_SEC;

#ifdef CONFIG_USB_MV_UDC_RX_INT_OPT
	udc->rx_opt_state.cur = RX_OPT_IDLE;
#else
	udc->rx_opt_state.cur = RX_OPT_DISABLE;
#endif

	/* set timer0 to 2msec one shot */
	ret = rx_opt_timer_init(udc, RX_SHORT_TIMER_IDX,
		udc->rx_opt_conf.short_timeout_msec, false);
	if (ret) {
		pr_err("rx_opt_timer_init: USB gptimer%d init failed, ret=%d\n",
			RX_SHORT_TIMER_IDX, ret);
		goto err;
	}

	/* set timer1 to 2 sec one shot */
	ret = rx_opt_timer_init(udc, RX_LONG_TIMER_IDX,
		udc->rx_opt_conf.long_timeout_sec * 1000, false);
	if (ret) {
		pr_err("rx_opt_timer_init: USB gptimer%d init failed, ret=%d\n",
			RX_LONG_TIMER_IDX, ret);
		goto stop_st;
	}
	return 0;

stop_st:
	rx_opt_timer_stop(udc, RX_SHORT_TIMER_IDX);
err:
	return ret;
}

static void mv_udc_rx_opt_exit(struct mv_udc *udc)
{
	rx_opt_timer_stop(udc, RX_SHORT_TIMER_IDX);
	rx_opt_timer_stop(udc, RX_LONG_TIMER_IDX);
}

/* Rx interrupt optimization sysfs */
#ifdef CONFIG_USB_MV_UDC_RX_INT_OPT_SYS_FS

/*
 * Spinlock for accessing shared resources which are normally accessed from
 * interrupt context from sysfs (thread context)
 */
static DEFINE_SPINLOCK(rx_opt_lock);

static struct rx_opt_config rx_opt_get_config(struct mv_udc *udc)
{
	return udc->rx_opt_conf;
}

static void rx_opt_set_config(struct rx_opt_config *cfg, struct mv_udc *udc)
{
	/* only allowed in disabled mode */
	if (udc->rx_opt_state.cur == RX_OPT_DISABLE) {
		BUG_ON(!cfg);
		udc->rx_opt_conf = *cfg;
		rx_opt_timer_init(udc, RX_SHORT_TIMER_IDX,
			cfg->short_timeout_msec, false);
		rx_opt_timer_init(udc, RX_LONG_TIMER_IDX,
			cfg->long_timeout_sec * 1000, false);
	} else
		pr_err("trying to change config not in DISABLE state\n");
}

static void rx_opt_get_pkt_cnt(struct mv_udc *udc, unsigned int *rx_pkt_cnt)
{
	BUG_ON(!rx_pkt_cnt);
	memcpy(rx_pkt_cnt, udc->rx_pkt_cnt, sizeof(udc->rx_pkt_cnt));
}

static void rx_opt_get_no_int(struct mv_udc *udc, unsigned int *rx_no_int)
{
	BUG_ON(!rx_no_int);
	memcpy(rx_no_int, udc->rx_no_int, sizeof(udc->rx_no_int));
}

static struct rx_opt_state rx_opt_get_state(void)
{
	struct mv_udc *udc = the_controller;
	return udc->rx_opt_state;
}

static struct rx_opt_timer_stats rx_opt_get_timer_stats(int timer)
{
	struct mv_udc *udc = the_controller;
	return udc->rx_opt_stats[timer];
}

static void rx_opt_reset_timer_stats(int timer)
{
	struct mv_udc *udc = the_controller;

	memset(&udc->rx_opt_stats[timer], 0,
		sizeof(struct rx_opt_timer_stats));
}

static ssize_t rx_opt_show_state(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	int len, i;
	struct rx_opt_state state;
	unsigned long flags;
	static char *rx_int_state_to_str[] = {"DISABLE", "IDLE", "ANALYZE",
						"ENABLE"};

	spin_lock_irqsave(&rx_opt_lock, flags);
	state = rx_opt_get_state();
	spin_unlock_irqrestore(&rx_opt_lock, flags);

	len = sprintf(buf, "Current: %s\n", rx_int_state_to_str[state.cur]);
	for (i = 0; i < RX_OPT_STATE_CNT; i++)
		len += sprintf(buf + len, "%s hits: %d\n",
				rx_int_state_to_str[i], state.hits[i]);
	return len;
}

static ssize_t rx_opt_set_state(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t size)
{
	unsigned long flags;
	int enable;
	struct rx_opt_state state;

	if (sscanf(buf, "%d", &enable) != 1)
		return -EINVAL;

	spin_lock_irqsave(&rx_opt_lock, flags);
	state = rx_opt_get_state();
	spin_unlock_irqrestore(&rx_opt_lock, flags);

	if (enable) {
		if (state.cur == RX_OPT_DISABLE) {
			spin_lock_irqsave(&rx_opt_lock, flags);
			rx_opt_switch_state(the_controller, RX_OPT_IDLE);
			spin_unlock_irqrestore(&rx_opt_lock, flags);
		}
	} else {
		spin_lock_irqsave(&rx_opt_lock, flags);
		rx_opt_switch_state(the_controller, RX_OPT_DISABLE);
		spin_unlock_irqrestore(&rx_opt_lock, flags);
	}
	return size;
}

static ssize_t rx_opt_show_timer_stats(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	int len;
	unsigned long flags;
	struct rx_opt_timer_stats short_stats, long_stats;

	spin_lock_irqsave(&rx_opt_lock, flags);
	short_stats = rx_opt_get_timer_stats(RX_SHORT_TIMER_IDX);
	long_stats = rx_opt_get_timer_stats(RX_LONG_TIMER_IDX);
	spin_unlock_irqrestore(&rx_opt_lock, flags);

	len = sprintf(buf, "short timer stats:\n");
	len += sprintf(buf + len, "expired = %d\n", short_stats.expired);
	len += sprintf(buf + len, "long timer stats:\n");
	len += sprintf(buf + len, "expired = %d\n", long_stats.expired);

	return len;
}

static ssize_t rx_opt_clear_timer_stats(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t size)
{
	unsigned long flags;

	spin_lock_irqsave(&rx_opt_lock, flags);
	rx_opt_reset_timer_stats(RX_LONG_TIMER_IDX);
	rx_opt_reset_timer_stats(RX_SHORT_TIMER_IDX);
	spin_unlock_irqrestore(&rx_opt_lock, flags);

	return size;
}

static ssize_t rx_opt_show_ep_status(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct mv_udc *udc = the_controller;
	unsigned int rx_pkt_cnt[16];
	unsigned int rx_no_int[16];
	int len, i;
	unsigned long flags;

	spin_lock_irqsave(&rx_opt_lock, flags);
	rx_opt_get_pkt_cnt(udc, rx_pkt_cnt);
	rx_opt_get_no_int(udc, rx_no_int);
	spin_unlock_irqrestore(&rx_opt_lock, flags);

	len = sprintf(buf, "Endpoints rx optimization status\n");
	len += sprintf(buf+len, "endpoint  rx_pkt_cnt  rx_no_int\n");
	for (i = 0; i < 16; i++)
		len += sprintf(buf+len, "EP%2d%11d%11d\n", i, rx_pkt_cnt[i],
			       rx_no_int[i]);

	return len;
}

static ssize_t rx_opt_show_config(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int len;

	struct rx_opt_config cfg = rx_opt_get_config(the_controller);

	len = sprintf(buf, "Configuration\n");
	len += sprintf(buf + len, "PPS_HIGH = %d, PPS_LOW = %d\n"
		       "LONG TIMEOUT = %d[sec], SHORT_TIMEOUT = %d[msec]\n",
		       cfg.pps_high, cfg.pps_low, cfg.long_timeout_sec,
		       cfg.short_timeout_msec);

	return len;
}

static ssize_t rx_opt_set_short_timeout(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t size)
{
	struct rx_opt_config cfg = rx_opt_get_config(the_controller);

	if (sscanf(buf, "%d", &cfg.short_timeout_msec) != 1)
		return -EINVAL;

	cfg.pps_low = 1000 / cfg.short_timeout_msec;
	cfg.pps_high = cfg.pps_low + 100;
	rx_opt_set_config(&cfg, the_controller);

	return size;
}

static ssize_t rx_opt_set_long_timeout(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	struct rx_opt_config cfg = rx_opt_get_config(the_controller);

	if (sscanf(buf, "%d", &cfg.long_timeout_sec) != 1)
		return -EINVAL;

	rx_opt_set_config(&cfg, the_controller);

	return size;
}

static DEVICE_ATTR(state, S_IRUGO|S_IWUSR, rx_opt_show_state, rx_opt_set_state);
static DEVICE_ATTR(gptimers, S_IRUGO|S_IWUSR, rx_opt_show_timer_stats,
		    rx_opt_clear_timer_stats);
static DEVICE_ATTR(ep_status, S_IRUGO, rx_opt_show_ep_status, NULL);
static DEVICE_ATTR(config, S_IRUGO, rx_opt_show_config, NULL);
static DEVICE_ATTR(short_timeout_msec, S_IWUSR, NULL, rx_opt_set_short_timeout);
static DEVICE_ATTR(long_timeout_sec, S_IWUSR, NULL, rx_opt_set_long_timeout);

static struct attribute *mv_udc_attrs[] = {
	&dev_attr_state.attr,
	&dev_attr_gptimers.attr,
	&dev_attr_ep_status.attr,
	&dev_attr_config.attr,
	&dev_attr_short_timeout_msec.attr,
	&dev_attr_long_timeout_sec.attr,
	NULL,
};

struct attribute_group mv_udc_attr_group = {
	.attrs = mv_udc_attrs,
};

#endif
/* end Rx interrupt optimization */

/*
 * Set IOC for all pending dTDs - called from interrupt context or
 * interrupts disabled !
 */
static void ep_dtd_set_ioc(struct mv_udc *udc, u32 ep_num)
{
	u32 i;
	struct mv_ep	*curr_ep;
	struct mv_req *curr_req, *temp_req;
	struct mv_dtd	*curr_dtd;

	curr_ep = &udc->eps[ep_num * 2];

	/* mark the last dtd in each request as ioc */
	list_for_each_entry_safe(curr_req, temp_req, &curr_ep->queue, queue) {
		curr_dtd = curr_req->head;
		for (i = 0; i < curr_req->dtd_count - 1; i++)
			curr_dtd = curr_dtd->next_dtd_virt;
		set_ioc_safe(curr_dtd);
	}
}

static const char *charger_type(unsigned int type)
{
	switch (type) {
	case NULL_CHARGER: return "NULL_CHARGER";
	case DEFAULT_CHARGER: return "DEFAULT_CHARGER";
	case DCP_CHARGER: return "DCP_CHARGER";
	case CDP_CHARGER: return "CDP_CHARGER";
	case SDP_CHARGER: return "SDP_CHARGER";
	default: return "NONE_STANDARD_CHARGER";
	}
}

static void ep0_reset(struct mv_udc *udc)
{
	struct mv_ep *ep;
	u32 epctrlx;
	int i = 0;

	/* ep0 in and out */
	for (i = 0; i < 2; i++) {
		ep = &udc->eps[i];
		ep->udc = udc;

		/* ep0 dQH */
		ep->dqh = &udc->ep_dqh[i];

		/* configure ep0 endpoint capabilities in dQH */
		ep->dqh->max_packet_length =
			(EP0_MAX_PKT_SIZE << EP_QUEUE_HEAD_MAX_PKT_LEN_POS)
			| EP_QUEUE_HEAD_IOS | EP_QUEUE_HEAD_ZLT_SEL;

		ep->dqh->next_dtd_ptr = EP_QUEUE_HEAD_NEXT_TERMINATE;

		epctrlx = readl(&udc->op_regs->epctrlx[0]);
		if (i) {	/* TX */
			epctrlx |= EPCTRL_TX_ENABLE
				| (USB_ENDPOINT_XFER_CONTROL
					<< EPCTRL_TX_EP_TYPE_SHIFT);

		} else {	/* RX */
			epctrlx |= EPCTRL_RX_ENABLE
				| (USB_ENDPOINT_XFER_CONTROL
					<< EPCTRL_RX_EP_TYPE_SHIFT);
		}

		writel(epctrlx, &udc->op_regs->epctrlx[0]);
	}
}

/* protocol ep0 stall, will automatically be cleared on new transaction */
static void ep0_stall(struct mv_udc *udc)
{
	u32	epctrlx;

	/* set TX and RX to stall */
	epctrlx = readl(&udc->op_regs->epctrlx[0]);
	epctrlx |= EPCTRL_RX_EP_STALL | EPCTRL_TX_EP_STALL;
	writel(epctrlx, &udc->op_regs->epctrlx[0]);

	/* update ep0 state */
	udc->ep0_state = WAIT_FOR_SETUP;
	udc->ep0_dir = EP_DIR_OUT;
}

static int hw_ep_prime(struct mv_udc *udc, u32 bit_pos)
{
	u32 prime_times = 0;

	writel(bit_pos, &udc->op_regs->epprime);

	while (readl(&udc->op_regs->epprime) & bit_pos) {
		cpu_relax();
		prime_times++;
		if (prime_times > MAX_EPPRIME_TIMES) {
			dev_err(&udc->dev->dev, "epprime out of time\n");
			return -1;
		}
	}

	return 0;
}

static int process_ep_req(struct mv_udc *udc, int index,
	struct mv_req *curr_req)
{
	struct mv_dtd	*curr_dtd;
	struct mv_dqh	*curr_dqh;
	int td_complete, actual, remaining_length;
	int i, direction;
	int retval = 0;
	u32 errors;
	u32 bit_pos;

	curr_dqh = &udc->ep_dqh[index];
	direction = index % 2;

	curr_dtd = curr_req->head;
	td_complete = 0;
	actual = curr_req->req.length;

	for (i = 0; i < curr_req->dtd_count; i++) {
		if (curr_dtd->size_ioc_sts & DTD_STATUS_ACTIVE) {
			dev_dbg(&udc->dev->dev, "%s, dTD not completed\n",
				udc->eps[index].name);
			return 1;
		}

		errors = curr_dtd->size_ioc_sts & DTD_ERROR_MASK;
		if (!errors) {
			remaining_length =
				(curr_dtd->size_ioc_sts	& DTD_PACKET_SIZE)
					>> DTD_LENGTH_BIT_POS;
			actual -= remaining_length;

			if (direction == EP_DIR_OUT)
				udc->rx_pkt_cnt[curr_req->ep->ep_num]++;

			if (remaining_length) {
				if (direction) {
					dev_dbg(&udc->dev->dev,
						"TX dTD remains data\n");
					retval = -EPROTO;
					break;
				} else
					break;
			}
		} else {
			dev_info(&udc->dev->dev,
				"complete_tr error: ep=%d %s: error = 0x%x\n",
				index >> 1, direction ? "SEND" : "RECV",
				errors);
			if (errors & DTD_STATUS_HALTED) {
				/* Clear the errors and Halt condition */
				curr_dqh->size_ioc_int_sts &= ~errors;
				retval = -EPIPE;
			} else if (errors & DTD_STATUS_DATA_BUFF_ERR) {
				retval = -EPROTO;
			} else if (errors & DTD_STATUS_TRANSACTION_ERR) {
				retval = -EILSEQ;
			}
		}
		if (i != curr_req->dtd_count - 1)
			curr_dtd = (struct mv_dtd *)curr_dtd->next_dtd_virt;
	}
	if (retval)
		return retval;

	if (direction == EP_DIR_OUT)
		bit_pos = 1 << curr_req->ep->ep_num;
	else
		bit_pos = 1 << (16 + curr_req->ep->ep_num);

	while ((curr_dqh->curr_dtd_ptr == curr_dtd->td_dma)) {
		if (curr_dtd->dtd_next == EP_QUEUE_HEAD_NEXT_TERMINATE) {
			while (readl(&udc->op_regs->epstatus) & bit_pos)
				udelay(1);
			break;
		} else {
			if (!(readl(&udc->op_regs->epstatus) & bit_pos)) {
				/* The DMA engine thinks there is no more dTD */
				curr_dqh->next_dtd_ptr = curr_dtd->dtd_next
					& EP_QUEUE_HEAD_NEXT_POINTER_MASK;

				/* clear active and halt bit */
				curr_dqh->size_ioc_int_sts &=
						~(DTD_STATUS_ACTIVE
						| DTD_STATUS_HALTED);

				/* Do prime again */
				wmb();

				hw_ep_prime(udc, bit_pos);

				break;
			}
		}
		udelay(1);
	}

	curr_req->req.actual = actual;

	return 0;
}

/*
 * done() - retire a request; caller blocked irqs
 * @status : request status to be set, only works when
 * request is still in progress.
 */
static int done(struct mv_ep *ep, struct mv_req *req, int status)
	__releases(&ep->udc->lock)
	__acquires(&ep->udc->lock)
{
	struct mv_udc *udc = NULL;
	unsigned char stopped = ep->stopped;
	struct mv_dtd *curr_td, *next_td;
	int j;

	udc = (struct mv_udc *)ep->udc;

	if (req->req.dma == DMA_ADDR_INVALID && req->mapped == 0) {
		dev_info(&udc->dev->dev, "%s request %p already unmapped",
					ep->name, req);
		return -ESHUTDOWN;
	}

	/* Removed the req from fsl_ep->queue */
	list_del_init(&req->queue);

	/* req.status should be set as -EINPROGRESS in ep_queue() */
	if (req->req.status == -EINPROGRESS)
		req->req.status = status;
	else
		status = req->req.status;

	/* Free dtd for the request */
	next_td = req->head;
	for (j = 0; j < req->dtd_count; j++) {
		curr_td = next_td;
		if (j != req->dtd_count - 1)
			next_td = curr_td->next_dtd_virt;
		dma_pool_free(udc->dtd_pool, curr_td, curr_td->td_dma);
	}

	usb_gadget_unmap_request(&udc->gadget, &req->req, ep_dir(ep));
	req->req.dma = DMA_ADDR_INVALID;
	req->mapped = 0;

	if (status && (status != -ESHUTDOWN))
		dev_info(&udc->dev->dev, "complete %s req %p stat %d len %u/%u",
			ep->ep.name, &req->req, status,
			req->req.actual, req->req.length);

	ep->stopped = 1;

	spin_unlock(&ep->udc->lock);
	/*
	 * complete() is from gadget layer,
	 * eg fsg->bulk_in_complete()
	 */
	if (req->req.complete)
		req->req.complete(&ep->ep, &req->req);

	spin_lock(&ep->udc->lock);
	ep->stopped = stopped;

	if (udc->active)
		return 0;
	else
		return -ESHUTDOWN;
}

static int queue_dtd(struct mv_ep *ep, struct mv_req *req)
{
	struct mv_udc *udc;
	struct mv_dqh *dqh;
	struct mv_req *curr_req, *temp_req;
	u32 find_missing_dtd = 0;
	u32 bit_pos, direction;
	u32 usbcmd, epstatus;
	unsigned int loops;
	int retval = 0;

	udc = ep->udc;
	direction = ep_dir(ep);
	dqh = &(udc->ep_dqh[ep->ep_num * 2 + direction]);
	bit_pos = 1 << (((direction == EP_DIR_OUT) ? 0 : 16) + ep->ep_num);

	/* check if the pipe is empty */
	if (!(list_empty(&ep->queue))) {
		struct mv_req *lastreq;
		lastreq = list_entry(ep->queue.prev, struct mv_req, queue);
		lastreq->tail->dtd_next =
			req->head->td_dma & EP_QUEUE_HEAD_NEXT_POINTER_MASK;

		wmb();

		if (readl(&udc->op_regs->epprime) & bit_pos)
			goto done;

		loops = LOOPS(READSAFE_TIMEOUT);
		while (1) {
			/* start with setting the semaphores */
			usbcmd = readl(&udc->op_regs->usbcmd);
			usbcmd |= USBCMD_ATDTW_TRIPWIRE_SET;
			writel(usbcmd, &udc->op_regs->usbcmd);

			/* read the endpoint status */
			epstatus = readl(&udc->op_regs->epstatus) & bit_pos;

			/*
			 * Reread the ATDTW semaphore bit to check if it is
			 * cleared. When hardware see a hazard, it will clear
			 * the bit or else we remain set to 1 and we can
			 * proceed with priming of endpoint if not already
			 * primed.
			 */
			if (readl(&udc->op_regs->usbcmd)
				& USBCMD_ATDTW_TRIPWIRE_SET)
				break;

			loops--;
			if (loops == 0) {
				dev_err(&udc->dev->dev,
					"Timeout for ATDTW_TRIPWIRE...\n");
				retval = -ETIME;
				goto done;
			}
			udelay(LOOPS_USEC);
		}

		/* Clear the semaphore */
		usbcmd = readl(&udc->op_regs->usbcmd);
		usbcmd &= USBCMD_ATDTW_TRIPWIRE_CLEAR;
		writel(usbcmd, &udc->op_regs->usbcmd);

		if (epstatus)
			goto done;

		/* Check if there are missing dTD in the queue not primed */
		list_for_each_entry_safe(curr_req, temp_req, &ep->queue, queue)
			if (curr_req->head->size_ioc_sts & DTD_STATUS_ACTIVE) {
				pr_info("There are missing dTD need to be primed!\n");
				find_missing_dtd = 1;
				break;
			}
	}

	/* Write dQH next pointer and terminate bit to 0 */
	if (unlikely(find_missing_dtd))
		dqh->next_dtd_ptr = curr_req->head->td_dma
					& EP_QUEUE_HEAD_NEXT_POINTER_MASK;
	else
		dqh->next_dtd_ptr = req->head->td_dma
					& EP_QUEUE_HEAD_NEXT_POINTER_MASK;

	/* clear active and halt bit, in case set from a previous error */
	dqh->size_ioc_int_sts &= ~(DTD_STATUS_ACTIVE | DTD_STATUS_HALTED);

	/* Ensure that updates to the QH will occure before priming. */
	wmb();

	/* Prime the Endpoint */
	hw_ep_prime(udc, bit_pos);
done:
	return retval;
}

static struct mv_dtd *build_dtd(struct mv_req *req, unsigned *length,
		dma_addr_t *dma, int *is_last)
{
	struct mv_dtd *dtd;
	struct mv_udc *udc;
	struct mv_dqh *dqh;
	u32 temp, mult = 0;

	/* how big will this transfer be? */
	if (usb_endpoint_xfer_isoc(req->ep->ep.desc)) {
		dqh = req->ep->dqh;
		mult = (dqh->max_packet_length >> EP_QUEUE_HEAD_MULT_POS)
				& 0x3;
		*length = min(req->req.length - req->req.actual,
				(unsigned)(mult * req->ep->ep.maxpacket));
	} else
		*length = min(req->req.length - req->req.actual,
				(unsigned)EP_MAX_LENGTH_TRANSFER);

	udc = req->ep->udc;

	/*
	 * Be careful that no _GFP_HIGHMEM is set,
	 * or we can not use dma_to_virt
	 */
	dtd = dma_pool_alloc(udc->dtd_pool, GFP_ATOMIC, dma);
	if (dtd == NULL)
		return dtd;

	dtd->td_dma = *dma;
	/* initialize buffer page pointers */
	temp = (u32)(req->req.dma + req->req.actual);
	dtd->buff_ptr0 = cpu_to_le32(temp);
	temp &= ~0xFFF;
	dtd->buff_ptr1 = cpu_to_le32(temp + 0x1000);
	dtd->buff_ptr2 = cpu_to_le32(temp + 0x2000);
	dtd->buff_ptr3 = cpu_to_le32(temp + 0x3000);
	dtd->buff_ptr4 = cpu_to_le32(temp + 0x4000);

	req->req.actual += *length;

	/* zlp is needed if req->req.zero is set */
	if (req->req.zero) {
		if (*length == 0 || (*length % req->ep->ep.maxpacket) != 0)
			*is_last = 1;
		else
			*is_last = 0;
	} else if (req->req.length == req->req.actual)
		*is_last = 1;
	else
		*is_last = 0;

	/* Fill in the transfer size; set active bit */
	temp = ((*length << DTD_LENGTH_BIT_POS) | DTD_STATUS_ACTIVE);

	/* Enable interrupt for the last dtd of a request */
	if (*is_last && !req->req.no_interrupt)
		temp |= DTD_IOC;
	else if (ep_dir(req->ep) == EP_DIR_OUT && *is_last &&
		   !udc->rx_no_int[req->ep->ep_num])
		temp |= DTD_IOC;

	temp |= mult << 10;

	dtd->size_ioc_sts = temp;

	mb();

	return dtd;
}

/* generate dTD linked list for a request */
static int req_to_dtd(struct mv_req *req)
{
	unsigned count;
	int is_last, is_first = 1;
	struct mv_dtd *dtd, *last_dtd = NULL;
	struct mv_udc *udc;
	dma_addr_t dma;

	udc = req->ep->udc;

	do {
		dtd = build_dtd(req, &count, &dma, &is_last);
		if (dtd == NULL)
			return -ENOMEM;

		if (is_first) {
			is_first = 0;
			req->head = dtd;
		} else {
			last_dtd->dtd_next = dma;
			last_dtd->next_dtd_virt = dtd;
		}
		last_dtd = dtd;
		req->dtd_count++;
	} while (!is_last);

	/* set terminate bit to 1 for the last dTD */
	dtd->dtd_next = DTD_NEXT_TERMINATE;

	req->tail = dtd;

	return 0;
}

static int mv_ep_enable(struct usb_ep *_ep,
		const struct usb_endpoint_descriptor *desc)
{
	struct mv_udc *udc;
	struct mv_ep *ep;
	struct mv_dqh *dqh;
	u16 max = 0;
	u32 bit_pos, epctrlx, direction;
	unsigned char zlt = 0, ios = 0, mult = 0;
	unsigned long flags = 0;

	ep = container_of(_ep, struct mv_ep, ep);
	udc = ep->udc;

	if (!_ep || !desc
			|| desc->bDescriptorType != USB_DT_ENDPOINT)
		return -EINVAL;

	if (!udc->driver || udc->gadget.speed == USB_SPEED_UNKNOWN)
		return -ESHUTDOWN;

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	ep->stats.enable++;
#endif

	direction = ep_dir(ep);
	max = usb_endpoint_maxp(desc);

	/*
	 * disable HW zero length termination select
	 * driver handles zero length packet through req->req.zero
	 */
	zlt = 1;

	bit_pos = 1 << ((direction == EP_DIR_OUT ? 0 : 16) + ep->ep_num);

	spin_lock_irqsave(&udc->lock, flags);

	if (!udc->active) {
		spin_unlock_irqrestore(&udc->lock, flags);
		return -ESHUTDOWN;
	}

	/* Check if the Endpoint is Primed */
	if ((readl(&udc->op_regs->epprime) & bit_pos)
		|| (readl(&udc->op_regs->epstatus) & bit_pos)) {
		dev_info(&udc->dev->dev,
			"ep=%d %s: Init ERROR: ENDPTPRIME=0x%x,"
			" ENDPTSTATUS=0x%x, bit_pos=0x%x\n",
			(unsigned)ep->ep_num, direction ? "SEND" : "RECV",
			(unsigned)readl(&udc->op_regs->epprime),
			(unsigned)readl(&udc->op_regs->epstatus),
			(unsigned)bit_pos);
		goto en_done;
	}
	/* Set the max packet length, interrupt on Setup and Mult fields */
	switch (desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) {
	case USB_ENDPOINT_XFER_BULK:
		zlt = 1;
		break;
	case USB_ENDPOINT_XFER_CONTROL:
		ios = 1;
		break;
	case USB_ENDPOINT_XFER_INT:
		break;
	case USB_ENDPOINT_XFER_ISOC:
		/* Calculate transactions needed for high bandwidth iso */
		mult = (unsigned char)(1 + ((max >> 11) & 0x03));
		max = max & 0x7ff;	/* bit 0~10 */
		/* 3 transactions at most */
		if (mult > 3)
			goto en_done;
		break;
	default:
		goto en_done;
	}

	/* Get the endpoint queue head address */
	dqh = ep->dqh;
	dqh->max_packet_length = (max << EP_QUEUE_HEAD_MAX_PKT_LEN_POS)
		| (mult << EP_QUEUE_HEAD_MULT_POS)
		| (zlt ? EP_QUEUE_HEAD_ZLT_SEL : 0)
		| (ios ? EP_QUEUE_HEAD_IOS : 0);
	dqh->next_dtd_ptr = 1;
	dqh->size_ioc_int_sts = 0;

	ep->ep.maxpacket = max;
	ep->ep.desc = desc;
	ep->stopped = 0;

	/* Enable the endpoint for Rx or Tx and set the endpoint type */
	epctrlx = readl(&udc->op_regs->epctrlx[ep->ep_num]);
	if (direction == EP_DIR_IN) {
		epctrlx &= ~EPCTRL_TX_ALL_MASK;
		epctrlx |= EPCTRL_TX_ENABLE | EPCTRL_TX_DATA_TOGGLE_RST
			| ((desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK)
				<< EPCTRL_TX_EP_TYPE_SHIFT);
	} else {
		epctrlx &= ~EPCTRL_RX_ALL_MASK;
		epctrlx |= EPCTRL_RX_ENABLE | EPCTRL_RX_DATA_TOGGLE_RST
			| ((desc->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK)
				<< EPCTRL_RX_EP_TYPE_SHIFT);
	}
	writel(epctrlx, &udc->op_regs->epctrlx[ep->ep_num]);

	/*
	 * Implement Guideline (GL# USB-7) The unused endpoint type must
	 * be programmed to bulk.
	 */
	epctrlx = readl(&udc->op_regs->epctrlx[ep->ep_num]);
	if ((epctrlx & EPCTRL_RX_ENABLE) == 0) {
		epctrlx |= (USB_ENDPOINT_XFER_BULK
				<< EPCTRL_RX_EP_TYPE_SHIFT);
		writel(epctrlx, &udc->op_regs->epctrlx[ep->ep_num]);
	}

	epctrlx = readl(&udc->op_regs->epctrlx[ep->ep_num]);
	if ((epctrlx & EPCTRL_TX_ENABLE) == 0) {
		epctrlx |= (USB_ENDPOINT_XFER_BULK
				<< EPCTRL_TX_EP_TYPE_SHIFT);
		writel(epctrlx, &udc->op_regs->epctrlx[ep->ep_num]);
	}

	spin_unlock_irqrestore(&udc->lock, flags);

	return 0;
en_done:
	spin_unlock_irqrestore(&udc->lock, flags);
	return -EINVAL;
}

static int  mv_ep_disable(struct usb_ep *_ep)
{
	struct mv_udc *udc;
	struct mv_ep *ep;
	struct mv_dqh *dqh;
	u32 bit_pos, epctrlx, direction;
	unsigned long flags;
	u32 active;

	ep = container_of(_ep, struct mv_ep, ep);
	if ((_ep == NULL) || !ep->ep.desc)
		return -EINVAL;

	udc = ep->udc;

	if (!udc->vbus_active) {
		dev_dbg(&udc->dev->dev,
			"usb already plug out!\n");
		return -EINVAL;
	}

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	ep->stats.disable++;
#endif

	/* Get the endpoint queue head address */
	dqh = ep->dqh;

	spin_lock_irqsave(&udc->lock, flags);

	active = udc->active;
	if (!active)
		mv_udc_enable(udc);

	direction = ep_dir(ep);
	bit_pos = 1 << ((direction == EP_DIR_OUT ? 0 : 16) + ep->ep_num);

	/* Reset the max packet length and the interrupt on Setup */
	dqh->max_packet_length = 0;

	/* Disable the endpoint for Rx or Tx and reset the endpoint type */
	epctrlx = readl(&udc->op_regs->epctrlx[ep->ep_num]);
	epctrlx &= ~((direction == EP_DIR_IN)
			? (EPCTRL_TX_ENABLE | EPCTRL_TX_TYPE)
			: (EPCTRL_RX_ENABLE | EPCTRL_RX_TYPE));
	writel(epctrlx, &udc->op_regs->epctrlx[ep->ep_num]);

	/* nuke all pending requests (does flush) */
	nuke(ep, -ESHUTDOWN);

	ep->ep.desc = NULL;
	ep->stopped = 1;

	if (!active)
		mv_udc_disable(udc);

	spin_unlock_irqrestore(&udc->lock, flags);

	return 0;
}

static struct usb_request *
mv_alloc_request(struct usb_ep *_ep, gfp_t gfp_flags)
{
	struct mv_req *req = NULL;

	req = kzalloc(sizeof *req, gfp_flags);
	if (!req)
		return NULL;

	req->req.dma = DMA_ADDR_INVALID;
	INIT_LIST_HEAD(&req->queue);

	return &req->req;
}

static void mv_free_request(struct usb_ep *_ep, struct usb_request *_req)
{
	struct mv_req *req = NULL;

	req = container_of(_req, struct mv_req, req);

	if (_req)
		kfree(req);
}

static void mv_ep_fifo_flush(struct usb_ep *_ep)
{
	struct mv_udc *udc;
	u32 bit_pos, direction;
	struct mv_ep *ep;
	unsigned int loops;

	if (!_ep)
		return;

	ep = container_of(_ep, struct mv_ep, ep);
	if (!ep->ep.desc)
		return;

	udc = ep->udc;
	if (!udc->active)
		return;

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	ep->stats.flush++;
#endif

	direction = ep_dir(ep);

	if (ep->ep_num == 0)
		bit_pos = (1 << 16) | 1;
	else if (direction == EP_DIR_OUT)
		bit_pos = 1 << ep->ep_num;
	else
		bit_pos = 1 << (16 + ep->ep_num);

	loops = LOOPS(EPSTATUS_TIMEOUT);
	do {
		unsigned int inter_loops;

		if (loops == 0) {
			dev_err(&udc->dev->dev,
				"TIMEOUT for ENDPTSTATUS=0x%x, bit_pos=0x%x\n",
				(unsigned)readl(&udc->op_regs->epstatus),
				(unsigned)bit_pos);
			return;
		}
		/* Write 1 to the Flush register */
		writel(bit_pos, &udc->op_regs->epflush);

		/* Wait until flushing completed */
		inter_loops = LOOPS(FLUSH_TIMEOUT);
		while (readl(&udc->op_regs->epflush)) {
			/*
			 * ENDPTFLUSH bit should be cleared to indicate this
			 * operation is complete
			 */
			if (inter_loops == 0) {
				dev_err(&udc->dev->dev,
					"TIMEOUT for ENDPTFLUSH=0x%x,"
					"bit_pos=0x%x\n",
					(unsigned)readl(&udc->op_regs->epflush),
					(unsigned)bit_pos);
				return;
			}
			inter_loops--;
			udelay(LOOPS_USEC);
		}
		loops--;
	} while (readl(&udc->op_regs->epstatus) & bit_pos);

	writel(bit_pos, &udc->op_regs->epcomplete);
}

/* queues (submits) an I/O request to an endpoint */
static int
mv_ep_queue(struct usb_ep *_ep, struct usb_request *_req, gfp_t gfp_flags)
{
	struct mv_ep *ep = container_of(_ep, struct mv_ep, ep);
	struct mv_req *req = container_of(_req, struct mv_req, req);
	struct mv_udc *udc = ep->udc;
	unsigned long flags;
	int retval;

	/* catch various bogus parameters */
	if (!_req || !req->req.complete || !req->req.buf
			|| !list_empty(&req->queue)) {
		dev_err(&udc->dev->dev, "%s, bad params", __func__);
		return -EINVAL;
	}
	if (unlikely(!_ep || !ep->ep.desc)) {
		dev_err(&udc->dev->dev, "%s, bad ep", __func__);
		return -EINVAL;
	}

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	ep->stats.queue++;
#endif

	udc = ep->udc;
	if (!udc->driver || udc->gadget.speed == USB_SPEED_UNKNOWN)
		return -ESHUTDOWN;

	req->ep = ep;

	/* map virtual address to hardware */
	retval = usb_gadget_map_request(&udc->gadget, _req, ep_dir(ep));
	if (retval)
		return retval;
	req->req.dma = _req->dma;
	req->mapped = 1;

	req->req.status = -EINPROGRESS;
	req->req.actual = 0;
	req->dtd_count = 0;

	spin_lock_irqsave(&udc->lock, flags);

	if (udc->stopped || !udc->active || !ep->ep.desc) {
		spin_unlock_irqrestore(&udc->lock, flags);
		dev_info(&udc->dev->dev,
			"udc or %s is already disabled!\n", ep->name);
		retval = -EINVAL;
		goto err_unmap_dma;
	}

	/* build dtds and push them to device queue */
	if (!req_to_dtd(req)) {
		retval = queue_dtd(ep, req);
		if (retval) {
			spin_unlock_irqrestore(&udc->lock, flags);
			dev_err(&udc->dev->dev, "Failed to queue dtd\n");
			goto err_unmap_dma;
		}
	} else {
		spin_unlock_irqrestore(&udc->lock, flags);
		dev_err(&udc->dev->dev, "Failed to dma_pool_alloc\n");
		retval = -ENOMEM;
		goto err_unmap_dma;
	}

	/* Update ep0 state */
	if (ep->ep_num == 0)
		udc->ep0_state = DATA_STATE_XMIT;

	/* irq handler advances the queue */
	list_add_tail(&req->queue, &ep->queue);
	spin_unlock_irqrestore(&udc->lock, flags);

	return 0;

err_unmap_dma:
	usb_gadget_unmap_request(&udc->gadget, _req, ep_dir(ep));
	req->req.dma = DMA_ADDR_INVALID;
	req->mapped = 0;

	return retval;
}

static void mv_prime_ep(struct mv_ep *ep, struct mv_req *req)
{
	struct mv_dqh *dqh = ep->dqh;
	u32 bit_pos;

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	ep->stats.prime++;
#endif

	/* Write dQH next pointer and terminate bit to 0 */
	dqh->next_dtd_ptr = req->head->td_dma
		& EP_QUEUE_HEAD_NEXT_POINTER_MASK;

	/* clear active and halt bit, in case set from a previous error */
	dqh->size_ioc_int_sts &= ~(DTD_STATUS_ACTIVE | DTD_STATUS_HALTED);

	/* Ensure that updates to the QH will occure before priming. */
	wmb();

	bit_pos = 1 << (((ep_dir(ep) == EP_DIR_OUT) ? 0 : 16) + ep->ep_num);

	/* Prime the Endpoint */
	hw_ep_prime(ep->udc, bit_pos);
}

/* dequeues (cancels, unlinks) an I/O request from an endpoint */
static int mv_ep_dequeue(struct usb_ep *_ep, struct usb_request *_req)
{
	struct mv_ep *ep = container_of(_ep, struct mv_ep, ep);
	struct mv_req *req;
	struct mv_udc *udc = ep->udc;
	unsigned long flags;
	int stopped, ret = 0;
	u32 epctrlx;

	if (!_ep || !_req)
		return -EINVAL;

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	ep->stats.dequeue++;
#endif

	spin_lock_irqsave(&udc->lock, flags);
	if (!udc->active) {
		spin_unlock_irqrestore(&udc->lock, flags);
		return 0;
	}

	/* make sure it's actually queued on this endpoint */
	list_for_each_entry(req, &ep->queue, queue) {
		if (&req->req == _req)
			break;
	}
	if (&req->req != _req) {
		ret = -EINVAL;
		goto out;
	}

	stopped = ep->stopped;

	/* Stop the ep before we deal with the queue */
	ep->stopped = 1;
	epctrlx = readl(&udc->op_regs->epctrlx[ep->ep_num]);
	if (ep_dir(ep) == EP_DIR_IN)
		epctrlx &= ~EPCTRL_TX_ENABLE;
	else
		epctrlx &= ~EPCTRL_RX_ENABLE;
	writel(epctrlx, &udc->op_regs->epctrlx[ep->ep_num]);

	/* The request is in progress, or completed but not dequeued */
	if (ep->queue.next == &req->queue) {
		_req->status = -ECONNRESET;
		mv_ep_fifo_flush(_ep);	/* flush current transfer */

		/* The request isn't the last request in this ep queue */
		if (req->queue.next != &ep->queue) {
			struct mv_req *next_req;

			next_req = list_entry(req->queue.next,
				struct mv_req, queue);

			/* Point the QH to the first TD of next request */
			mv_prime_ep(ep, next_req);
		} else {
			struct mv_dqh *qh;

			qh = ep->dqh;
			qh->next_dtd_ptr = 1;
			qh->size_ioc_int_sts = 0;
		}

		/* The request hasn't been processed, patch up the TD chain */
	} else {
		struct mv_req *prev_req;

		prev_req = list_entry(req->queue.prev, struct mv_req, queue);
		writel(readl(&req->tail->dtd_next),
				&prev_req->tail->dtd_next);

	}

	ret = done(ep, req, -ECONNRESET);
	if (ret)
		goto out;

	/* Enable EP */
	epctrlx = readl(&udc->op_regs->epctrlx[ep->ep_num]);
	if (ep_dir(ep) == EP_DIR_IN)
		epctrlx |= EPCTRL_TX_ENABLE;
	else
		epctrlx |= EPCTRL_RX_ENABLE;
	writel(epctrlx, &udc->op_regs->epctrlx[ep->ep_num]);
	ep->stopped = stopped;

out:
	spin_unlock_irqrestore(&udc->lock, flags);
	return ret;
}

static void ep_set_stall(struct mv_udc *udc, u8 ep_num, u8 direction, int stall)
{
	u32 epctrlx;

	epctrlx = readl(&udc->op_regs->epctrlx[ep_num]);

	if (stall) {
		if (direction == EP_DIR_IN)
			epctrlx |= EPCTRL_TX_EP_STALL;
		else
			epctrlx |= EPCTRL_RX_EP_STALL;
	} else {
		if (direction == EP_DIR_IN) {
			epctrlx &= ~EPCTRL_TX_EP_STALL;
			epctrlx |= EPCTRL_TX_DATA_TOGGLE_RST;
		} else {
			epctrlx &= ~EPCTRL_RX_EP_STALL;
			epctrlx |= EPCTRL_RX_DATA_TOGGLE_RST;
		}
	}
	writel(epctrlx, &udc->op_regs->epctrlx[ep_num]);
}

static int ep_is_stall(struct mv_udc *udc, u8 ep_num, u8 direction)
{
	u32 epctrlx;

	epctrlx = readl(&udc->op_regs->epctrlx[ep_num]);

	if (direction == EP_DIR_OUT)
		return (epctrlx & EPCTRL_RX_EP_STALL) ? 1 : 0;
	else
		return (epctrlx & EPCTRL_TX_EP_STALL) ? 1 : 0;
}

static int mv_ep_set_halt_wedge(struct usb_ep *_ep, int halt, int wedge)
{
	struct mv_ep *ep;
	unsigned long flags = 0;
	int status = 0;
	struct mv_udc *udc;

	ep = container_of(_ep, struct mv_ep, ep);
	udc = ep->udc;
	if (!_ep || !ep->ep.desc) {
		status = -EINVAL;
		goto out;
	}

	if (ep->ep.desc->bmAttributes == USB_ENDPOINT_XFER_ISOC) {
		status = -EOPNOTSUPP;
		goto out;
	}

	/*
	 * Attempt to halt IN ep will fail if any transfer requests
	 * are still queue
	 */
	if (halt && (ep_dir(ep) == EP_DIR_IN) && !list_empty(&ep->queue)) {
		status = -EAGAIN;
		goto out;
	}

	spin_lock_irqsave(&ep->udc->lock, flags);
	ep_set_stall(udc, ep->ep_num, ep_dir(ep), halt);
	if (halt && wedge)
		ep->wedge = 1;
	else if (!halt)
		ep->wedge = 0;
	spin_unlock_irqrestore(&ep->udc->lock, flags);

	if (ep->ep_num == 0) {
		udc->ep0_state = WAIT_FOR_SETUP;
		udc->ep0_dir = EP_DIR_OUT;
	}
out:
	return status;
}

static int mv_ep_set_halt(struct usb_ep *_ep, int halt)
{
	return mv_ep_set_halt_wedge(_ep, halt, 0);
}

static int mv_ep_set_wedge(struct usb_ep *_ep)
{
	return mv_ep_set_halt_wedge(_ep, 1, 1);
}

static struct usb_ep_ops mv_ep_ops = {
	.enable		= mv_ep_enable,
	.disable	= mv_ep_disable,

	.alloc_request	= mv_alloc_request,
	.free_request	= mv_free_request,

	.queue		= mv_ep_queue,
	.dequeue	= mv_ep_dequeue,

	.set_wedge	= mv_ep_set_wedge,
	.set_halt	= mv_ep_set_halt,
	.fifo_flush	= mv_ep_fifo_flush,	/* flush fifo */
};

static void udc_clock_enable(struct mv_udc *udc)
{
	clk_enable(udc->clk);
}

static void udc_clock_disable(struct mv_udc *udc)
{
	clk_disable(udc->clk);
}

static void udc_stop(struct mv_udc *udc)
{
	u32 tmp;

	/* Disable interrupts */
	tmp = readl(&udc->op_regs->usbintr);
	tmp &= ~(USBINTR_INT_EN | USBINTR_ERR_INT_EN |
		USBINTR_PORT_CHANGE_DETECT_EN |
		USBINTR_RESET_EN | USBINTR_DEVICE_SUSPEND |
		USBINTR_GPTIMER0_EN | USBINTR_GPTIMER1_EN);
	writel(tmp, &udc->op_regs->usbintr);

	udc->stopped = 1;

	/* Reset the Run the bit in the command register to stop VUSB */
	tmp = readl(&udc->op_regs->usbcmd);
	tmp &= ~USBCMD_RUN_STOP;
	writel(tmp, &udc->op_regs->usbcmd);
}

static void udc_start(struct mv_udc *udc)
{
	u32 usbintr;

	usbintr = USBINTR_INT_EN | USBINTR_ERR_INT_EN
		| USBINTR_PORT_CHANGE_DETECT_EN
		| USBINTR_RESET_EN | USBINTR_DEVICE_SUSPEND
		| USBINTR_GPTIMER0_EN | USBINTR_GPTIMER1_EN;
	/* Enable interrupts */
	writel(usbintr, &udc->op_regs->usbintr);

	udc->stopped = 0;

	/* Set the Run bit in the command register */
	writel(USBCMD_RUN_STOP, &udc->op_regs->usbcmd);
}

static int udc_reset(struct mv_udc *udc)
{
	unsigned int loops;
	u32 tmp, portsc;

	/* Stop the controller */
	tmp = readl(&udc->op_regs->usbcmd);
	tmp &= ~USBCMD_RUN_STOP;
	writel(tmp, &udc->op_regs->usbcmd);

	/* Reset the controller to get default values */
	writel(USBCMD_CTRL_RESET, &udc->op_regs->usbcmd);

	/* wait for reset to complete */
	loops = LOOPS(RESET_TIMEOUT);
	while (readl(&udc->op_regs->usbcmd) & USBCMD_CTRL_RESET) {
		if (loops == 0) {
			dev_err(&udc->dev->dev,
				"Wait for RESET completed TIMEOUT\n");
			return -ETIMEDOUT;
		}
		loops--;
		udelay(LOOPS_USEC);
	}

	/* set controller to device mode */
	tmp = readl(&udc->op_regs->usbmode);
	tmp |= USBMODE_CTRL_MODE_DEVICE;

	/* turn setup lockout off, require setup tripwire in usbcmd */
	tmp |= USBMODE_SETUP_LOCK_OFF | USBMODE_STREAM_DISABLE;

	writel(tmp, &udc->op_regs->usbmode);

	writel(0x0, &udc->op_regs->epsetupstat);

	/* Configure the Endpoint List Address */
	writel(udc->ep_dqh_dma & USB_EP_LIST_ADDRESS_MASK,
		&udc->op_regs->eplistaddr);

	portsc = readl(&udc->op_regs->portsc[0]);
	if (readl(&udc->cap_regs->hcsparams) & HCSPARAMS_PPC)
		portsc &= (~PORTSCX_W1C_BITS | ~PORTSCX_PORT_POWER);

	if (udc->force_fs)
		portsc |= PORTSCX_FORCE_FULL_SPEED_CONNECT;
	else
		portsc &= (~PORTSCX_FORCE_FULL_SPEED_CONNECT);

	writel(portsc, &udc->op_regs->portsc[0]);

	tmp = readl(&udc->op_regs->epctrlx[0]);
	tmp &= ~(EPCTRL_TX_EP_STALL | EPCTRL_RX_EP_STALL);
	writel(tmp, &udc->op_regs->epctrlx[0]);

	return 0;
}

static int mv_udc_enable_internal(struct mv_udc *udc)
{
	int retval;

	if (udc->active)
		return 0;

	dev_dbg(&udc->dev->dev, "enable udc\n");
	udc_clock_enable(udc);
	retval = usb_phy_init(udc->phy);
	if (retval) {
		dev_err(&udc->dev->dev,
			"init phy error %d\n", retval);
		udc_clock_disable(udc);
		return retval;
	}

	udc->active = 1;

	return 0;
}

static int mv_udc_enable(struct mv_udc *udc)
{
	if (udc->clock_gating)
		return mv_udc_enable_internal(udc);

	return 0;
}

static void mv_udc_disable_internal(struct mv_udc *udc)
{
	if (udc->active) {
		dev_dbg(&udc->dev->dev, "disable udc\n");
		usb_phy_shutdown(udc->phy);
		udc_clock_disable(udc);
		udc->active = 0;
	}
}

static void mv_udc_disable(struct mv_udc *udc)
{
	if (udc->clock_gating)
		mv_udc_disable_internal(udc);
}

static int mv_udc_get_frame(struct usb_gadget *gadget)
{
	struct mv_udc *udc;
	u16	retval;

	if (!gadget)
		return -ENODEV;

	udc = container_of(gadget, struct mv_udc, gadget);

	retval = readl(&udc->op_regs->frindex) & USB_FRINDEX_MASKS;

	return retval;
}

/* Tries to wake up the host connected to this gadget */
static int mv_udc_wakeup(struct usb_gadget *gadget)
{
	struct mv_udc *udc = container_of(gadget, struct mv_udc, gadget);
	u32 portsc;

	/* Remote wakeup feature not enabled by host */
	if (!udc->remote_wakeup)
		return -ENOTSUPP;

	portsc = readl(&udc->op_regs->portsc);
	/* not suspended? */
	if (!(portsc & PORTSCX_PORT_SUSPEND))
		return 0;
	/* trigger force resume */
	portsc |= PORTSCX_PORT_FORCE_RESUME;
	writel(portsc, &udc->op_regs->portsc[0]);
	return 0;
}

static void uevent_worker(struct work_struct *work)
{
	struct mv_udc *udc = container_of(work, struct mv_udc, event_work);
	char *connected[2]    = { "USB_STATE=CONNECTED", NULL };
	char *disconnected[2] = { "USB_STATE=DISCONNECTED", NULL };
	static int is_charge_mode;

	if (!udc)
		return;

	kobject_uevent_env(&udc->dev->dev.kobj, KOBJ_CHANGE,
			udc->vbus_active ? connected : disconnected);

#ifdef CONFIG_USB_GADGET_CHARGE_ONLY
	/* send fake usb connect uevent so that Android can handle it */
	if (is_charge_only_mode() && (udc->charger_type != DCP_CHARGER)) {
		if (udc->vbus_active) {
			charge_only_send_uevent(1);
			msleep(90);
			charge_only_send_uevent(2);
		} else
			charge_only_send_uevent(3);
	}

	/* if previous mode is charge only mode,
	 * disable it when switch to other function
	 */
	if (is_charge_mode && !udc->vbus_active)
		charge_only_send_uevent(3);

	is_charge_mode = is_charge_only_mode();
#endif /* CONFIG_USB_GADGET_CHARGE_ONLY */
}

static int mv_udc_vbus_session(struct usb_gadget *gadget, int is_active)
{
	struct mv_udc *udc;
	unsigned long flags;
	int retval = 0;

	udc = container_of(gadget, struct mv_udc, gadget);

#ifdef CONFIG_USB_GADGET_CHARGE_ONLY
	if (is_charge_only_mode()) {
		is_active = extcon_get_cable_state(udc->extcon, "VBUS");
		dev_info(&udc->dev->dev, "%s: charge_only_mode: vbus = %d\n",
			 __func__, is_active);
	}
#endif /* CONFIG_USB_GADGET_CHARGE_ONLY */

	udc->vbus_active = (is_active != 0);

	dev_info(&udc->dev->dev, "%s: softconnect %d, vbus_active %d\n",
		__func__, udc->softconnect, udc->vbus_active);

	schedule_work(&udc->event_work);

	if (udc->vbus_active) {
		retval = mv_udc_enable(udc);
		if (retval)
			goto out;
		pm_stay_awake(&udc->dev->dev);
		pm_qos_update_request(&udc->qos_idle, udc->lpm_qos);

		spin_lock_irqsave(&udc->lock, flags);
		/* stop udc before do charger detect */
		udc_stop(udc);
		spin_unlock_irqrestore(&udc->lock, flags);

		udc->charger_type = usb_phy_charger_detect(udc->phy);
		/* do it again to debounce */
		if (udc->charger_type != DCP_CHARGER) {
			msleep(300);
			udc->charger_type = usb_phy_charger_detect(udc->phy);
		}
	} else {
		udc->power = 0;
		udc->charger_type = NULL_CHARGER;
	}

	if (work_pending(&udc->delayed_charger_work.work))
		cancel_delayed_work(&udc->delayed_charger_work);

	/* SDP and NONE_STANDARD chargers need some delay to confirm */
	if (udc->charger_type == DEFAULT_CHARGER) {
		int enum_delay  = ENUMERATION_DELAY;

#ifdef CONFIG_USB_GADGET_CHARGE_ONLY
		if (is_charge_only_mode())
			enum_delay = HZ >> 3;
#endif /* CONFIG_USB_GADGET_CHARGE_ONLY */

		dev_info(&udc->dev->dev, "1st stage charger type: %s\n",
					charger_type(udc->charger_type));
		call_charger_notifier(udc);
		schedule_delayed_work(&udc->delayed_charger_work,
					enum_delay);
	/* NULL, DCP, CDP chargers already confirmed at this time */
	} else
		schedule_delayed_work(&udc->delayed_charger_work, 0);

	spin_lock_irqsave(&udc->lock, flags);
	if (udc->driver && udc->softconnect && udc->vbus_active) {
			/* Clock is disabled, need re-init registers */
		udc_reset(udc);
		ep0_reset(udc);
		udc_start(udc);
	} else if (udc->driver && udc->softconnect) {
		if (!udc->active) {
			spin_unlock_irqrestore(&udc->lock, flags);
			goto out;
		}

		/* stop all the transfer in queue*/
		udc_stop(udc);
		stop_activity(udc, udc->driver);
	}

	if (!udc->vbus_active)
		mv_udc_disable(udc);

	spin_unlock_irqrestore(&udc->lock, flags);

out:
	return retval;
}

/* constrain controller's VBUS power usage */
static int mv_udc_vbus_draw(struct usb_gadget *gadget, unsigned mA)
{
	struct mv_udc *udc;

	udc = container_of(gadget, struct mv_udc, gadget);
	udc->power = mA;

	return 0;
}

static int mv_udc_pullup(struct usb_gadget *gadget, int is_on)
{
	struct mv_udc *udc;
	unsigned long flags;
	int retval = 0;

	udc = container_of(gadget, struct mv_udc, gadget);
	spin_lock_irqsave(&udc->lock, flags);

	if (udc->softconnect == is_on)
		goto out;

	udc->softconnect = (is_on != 0);

	dev_info(&udc->dev->dev, "%s: softconnect %d, vbus_active %d\n",
			__func__, udc->softconnect, udc->vbus_active);

	if (udc->driver && udc->softconnect && udc->vbus_active) {
		retval = mv_udc_enable(udc);
		if (retval == 0) {
			/* Clock is disabled, need re-init registers */
			udc_reset(udc);
			ep0_reset(udc);
			udc_start(udc);
		}
	} else if (udc->driver && udc->vbus_active) {
		/* stop all the transfer in queue*/
		udc_stop(udc);
		stop_activity(udc, udc->driver);
		mv_udc_disable(udc);
	}
out:
	spin_unlock_irqrestore(&udc->lock, flags);
	return retval;
}

static int mv_set_selfpowered(struct usb_gadget *gadget, int is_on)
{
	struct mv_udc *udc;
	unsigned long flags;

	udc = container_of(gadget, struct mv_udc, gadget);

	spin_lock_irqsave(&udc->lock, flags);
	udc->selfpowered = (is_on != 0);
	spin_unlock_irqrestore(&udc->lock, flags);
	return 0;
}

static int mv_udc_start(struct usb_gadget *, struct usb_gadget_driver *);
static int mv_udc_stop(struct usb_gadget *, struct usb_gadget_driver *);
/* device controller usb_gadget_ops structure */
static const struct usb_gadget_ops mv_ops = {

	/* returns the current frame number */
	.get_frame	= mv_udc_get_frame,

	/* tries to wake up the host connected to this gadget */
	.wakeup		= mv_udc_wakeup,

	/* notify controller that VBUS is powered or not */
	.vbus_session	= mv_udc_vbus_session,

	/* constrain controller's VBUS power usage */
	.vbus_draw	= mv_udc_vbus_draw,

	/* D+ pullup, software-controlled connect/disconnect to USB host */
	.pullup		= mv_udc_pullup,

	.set_selfpowered = mv_set_selfpowered,

	.udc_start	= mv_udc_start,
	.udc_stop	= mv_udc_stop,
};

static int eps_init(struct mv_udc *udc)
{
	struct mv_ep	*ep;
	char name[14];
	int i;

	/* initialize ep0 */
	ep = &udc->eps[0];
	ep->udc = udc;
	strncpy(ep->name, "ep0", sizeof(ep->name));
	ep->ep.name = ep->name;
	ep->ep.ops = &mv_ep_ops;
	ep->wedge = 0;
	ep->stopped = 0;
	usb_ep_set_maxpacket_limit(&ep->ep, EP0_MAX_PKT_SIZE);
	ep->ep_num = 0;
	ep->ep.desc = &mv_ep0_desc;
	INIT_LIST_HEAD(&ep->queue);

	ep->ep_type = USB_ENDPOINT_XFER_CONTROL;

	/* initialize other endpoints */
	for (i = 2; i < udc->max_eps * 2; i++) {
		ep = &udc->eps[i];
		if (i % 2) {
			snprintf(name, sizeof(name), "ep%din", i / 2);
			ep->direction = EP_DIR_IN;
		} else {
			snprintf(name, sizeof(name), "ep%dout", i / 2);
			ep->direction = EP_DIR_OUT;
		}
		ep->udc = udc;
		strncpy(ep->name, name, sizeof(ep->name));
		ep->ep.name = ep->name;

		ep->ep.ops = &mv_ep_ops;
		ep->stopped = 0;
		usb_ep_set_maxpacket_limit(&ep->ep, (unsigned short) ~0);
		ep->ep_num = i / 2;

		INIT_LIST_HEAD(&ep->queue);
		list_add_tail(&ep->ep.ep_list, &udc->gadget.ep_list);

		ep->dqh = &udc->ep_dqh[i];
	}

	return 0;
}

/* delete all endpoint requests, called with spinlock held */
static void nuke(struct mv_ep *ep, int status)
{
	/* called with spinlock held */
	ep->stopped = 1;

	/* endpoint fifo flush */
	mv_ep_fifo_flush(&ep->ep);

	while (!list_empty(&ep->queue)) {
		struct mv_req *req = NULL;
		req = list_entry(ep->queue.next, struct mv_req, queue);
		done(ep, req, status);
	}
}

/* stop all USB activities */
static void stop_activity(struct mv_udc *udc, struct usb_gadget_driver *driver)
{
	struct mv_ep	*ep;

	nuke(&udc->eps[0], -ESHUTDOWN);

	list_for_each_entry(ep, &udc->gadget.ep_list, ep.ep_list) {
		nuke(ep, -ESHUTDOWN);
	}

	/* report disconnect; the driver is already quiesced */
	if (driver) {
		spin_unlock(&udc->lock);
		driver->disconnect(&udc->gadget);
		spin_lock(&udc->lock);
	}
}

static int mv_udc_start(struct usb_gadget *gadget,
		struct usb_gadget_driver *driver)
{
	struct mv_udc *udc;
	int retval = 0;
	unsigned long flags;

	udc = container_of(gadget, struct mv_udc, gadget);

	if (udc->driver)
		return -EBUSY;

	spin_lock_irqsave(&udc->lock, flags);

	/* hook up the driver ... */
	driver->driver.bus = NULL;
	udc->driver = driver;

	udc->usb_state = USB_STATE_ATTACHED;
	udc->ep0_state = WAIT_FOR_SETUP;
	udc->ep0_dir = EP_DIR_OUT;
	udc->selfpowered = 0;

	spin_unlock_irqrestore(&udc->lock, flags);

	if (udc->transceiver) {
		retval = otg_set_peripheral(udc->transceiver->otg,
					&udc->gadget);
		if (retval) {
			dev_err(&udc->dev->dev,
				"unable to register peripheral to otg\n");
			udc->driver = NULL;
			return retval;
		}
	}

#ifndef CONFIG_USB_G_ANDROID
	/* pullup is always on */
	mv_udc_pullup(&udc->gadget, 1);
#endif

	/* When boot with cable attached, there will be no vbus irq occurred */
	if (udc->qwork)
		queue_work(udc->qwork, &udc->vbus_work);

	return 0;
}

static int mv_udc_stop(struct usb_gadget *gadget,
		struct usb_gadget_driver *driver)
{
	struct mv_udc *udc;
	unsigned long flags;

	udc = container_of(gadget, struct mv_udc, gadget);

	spin_lock_irqsave(&udc->lock, flags);

	mv_udc_enable(udc);
	udc_stop(udc);

	/* stop all usb activities */
	udc->gadget.speed = USB_SPEED_UNKNOWN;
	stop_activity(udc, driver);
	mv_udc_disable(udc);

	spin_unlock_irqrestore(&udc->lock, flags);

	/* unbind gadget driver */
	udc->driver = NULL;

	return 0;
}

static void mv_set_ptc(struct mv_udc *udc, u32 mode)
{
	u32 portsc;

	portsc = readl(&udc->op_regs->portsc[0]);
	portsc |= mode << 16;
	writel(portsc, &udc->op_regs->portsc[0]);
}

static void prime_status_complete(struct usb_ep *ep, struct usb_request *_req)
{
	struct mv_ep *mvep = container_of(ep, struct mv_ep, ep);
	struct mv_req *req = container_of(_req, struct mv_req, req);
	struct mv_udc *udc;
	unsigned long flags;

	udc = mvep->udc;

	dev_info(&udc->dev->dev, "switch to test mode %d\n", req->test_mode);

	spin_lock_irqsave(&udc->lock, flags);
	if (req->test_mode) {
		mv_set_ptc(udc, req->test_mode);
		req->test_mode = 0;
	}
	spin_unlock_irqrestore(&udc->lock, flags);
}

static int
udc_prime_status(struct mv_udc *udc, u8 direction, u16 status, bool empty)
{
	int retval = 0;
	struct mv_req *req;
	struct mv_ep *ep;

	ep = &udc->eps[0];
	udc->ep0_dir = direction;
	udc->ep0_state = WAIT_FOR_OUT_STATUS;

	req = udc->status_req;

	/* fill in the reqest structure */
	if (!empty) {
		*((u16 *) req->req.buf) = cpu_to_le16(status);
		req->req.length = 2;
	} else
		req->req.length = 0;

	req->ep = ep;
	req->req.status = -EINPROGRESS;
	req->req.actual = 0;
	if (udc->test_mode) {
		req->req.complete = prime_status_complete;
		req->test_mode = udc->test_mode;
		udc->test_mode = 0;
	} else
		req->req.complete = NULL;
	req->dtd_count = 0;

	if (req->req.dma == DMA_ADDR_INVALID) {
		req->req.dma = dma_map_single(ep->udc->gadget.dev.parent,
				req->req.buf, req->req.length,
				ep_dir(ep) ? DMA_TO_DEVICE : DMA_FROM_DEVICE);
		req->mapped = 1;
	}

	/* prime the data phase */
	if (!req_to_dtd(req)) {
		retval = queue_dtd(ep, req);
		if (retval) {
			dev_err(&udc->dev->dev,
				"Failed to queue dtd when prime status\n");
			goto out;
		}
	} else{	/* no mem */
		retval = -ENOMEM;
		dev_err(&udc->dev->dev,
			"Failed to dma_pool_alloc when prime status\n");
		goto out;
	}

	list_add_tail(&req->queue, &ep->queue);

	return 0;
out:
	usb_gadget_unmap_request(&udc->gadget, &req->req, ep_dir(ep));
	req->req.dma = DMA_ADDR_INVALID;
	req->mapped = 0;

	return retval;
}

static void mv_udc_testmode(struct mv_udc *udc, u16 index)
{
	if (index <= TEST_FORCE_EN) {
		udc->test_mode = index;
		if (udc_prime_status(udc, EP_DIR_IN, 0, true))
			ep0_stall(udc);
	} else
		dev_err(&udc->dev->dev,
			"This test mode(%d) is not supported\n", index);
}

static void ch9setaddress(struct mv_udc *udc, struct usb_ctrlrequest *setup)
{
	udc->dev_addr = (u8)setup->wValue;

	/* update usb state */
	udc->usb_state = USB_STATE_ADDRESS;

	if (udc_prime_status(udc, EP_DIR_IN, 0, true))
		ep0_stall(udc);
}

static void ch9getstatus(struct mv_udc *udc, u8 ep_num,
	struct usb_ctrlrequest *setup)
{
	u16 status = 0;
	int retval;

	if ((setup->bRequestType & (USB_DIR_IN | USB_TYPE_MASK))
		!= (USB_DIR_IN | USB_TYPE_STANDARD))
		return;

	if ((setup->bRequestType & USB_RECIP_MASK) == USB_RECIP_DEVICE) {
		status = udc->selfpowered << USB_DEVICE_SELF_POWERED;
		status |= udc->remote_wakeup << USB_DEVICE_REMOTE_WAKEUP;
	} else if ((setup->bRequestType & USB_RECIP_MASK)
			== USB_RECIP_INTERFACE) {
		/* get interface status */
		status = 0;
	} else if ((setup->bRequestType & USB_RECIP_MASK)
			== USB_RECIP_ENDPOINT) {
		u8 ep_num, direction;

		ep_num = setup->wIndex & USB_ENDPOINT_NUMBER_MASK;
		direction = (setup->wIndex & USB_ENDPOINT_DIR_MASK)
				? EP_DIR_IN : EP_DIR_OUT;
		status = ep_is_stall(udc, ep_num, direction)
				<< USB_ENDPOINT_HALT;
	}

	retval = udc_prime_status(udc, EP_DIR_IN, status, false);
	if (retval)
		ep0_stall(udc);
	else
		udc->ep0_state = DATA_STATE_XMIT;
}

static void ch9clearfeature(struct mv_udc *udc, struct usb_ctrlrequest *setup)
{
	u8 ep_num;
	u8 direction;
	struct mv_ep *ep;

	if ((setup->bRequestType & (USB_TYPE_MASK | USB_RECIP_MASK))
		== ((USB_TYPE_STANDARD | USB_RECIP_DEVICE))) {
		switch (setup->wValue) {
		case USB_DEVICE_REMOTE_WAKEUP:
			udc->remote_wakeup = 0;
			break;
		default:
			goto out;
		}
	} else if ((setup->bRequestType & (USB_TYPE_MASK | USB_RECIP_MASK))
		== ((USB_TYPE_STANDARD | USB_RECIP_ENDPOINT))) {
		switch (setup->wValue) {
		case USB_ENDPOINT_HALT:
			ep_num = setup->wIndex & USB_ENDPOINT_NUMBER_MASK;
			direction = (setup->wIndex & USB_ENDPOINT_DIR_MASK)
				? EP_DIR_IN : EP_DIR_OUT;
			if (setup->wValue != 0 || setup->wLength != 0
				|| ep_num > udc->max_eps)
				goto out;
			ep = &udc->eps[ep_num * 2 + direction];
			if (ep->wedge == 1)
				break;
			ep_set_stall(udc, ep_num, direction, 0);
			break;
		default:
			goto out;
		}
	} else
		goto out;

	if (udc_prime_status(udc, EP_DIR_IN, 0, true))
		ep0_stall(udc);
out:
	return;
}

static const char *reqname(unsigned bRequest)
{
	switch (bRequest) {
	case USB_REQ_GET_STATUS: return "GET_STATUS";
	case USB_REQ_CLEAR_FEATURE: return "CLEAR_FEATURE";
	case USB_REQ_SET_FEATURE: return "SET_FEATURE";
	case USB_REQ_SET_ADDRESS: return "SET_ADDRESS";
	case USB_REQ_GET_DESCRIPTOR: return "GET_DESCRIPTOR";
	case USB_REQ_SET_DESCRIPTOR: return "SET_DESCRIPTOR";
	case USB_REQ_GET_CONFIGURATION: return "GET_CONFIGURATION";
	case USB_REQ_SET_CONFIGURATION: return "SET_CONFIGURATION";
	case USB_REQ_GET_INTERFACE: return "GET_INTERFACE";
	case USB_REQ_SET_INTERFACE: return "SET_INTERFACE";
	default: return "*UNKNOWN*";
	}
}

static const char *desc_type(unsigned type)
{
	switch (type) {
	case USB_DT_DEVICE: return "USB_DT_DEVICE";
	case USB_DT_CONFIG: return "USB_DT_CONFIG";
	case USB_DT_STRING: return "USB_DT_STRING";
	case USB_DT_INTERFACE: return "USB_DT_INTERFACE";
	case USB_DT_ENDPOINT: return "USB_DT_ENDPOINT";
	case USB_DT_DEVICE_QUALIFIER: return "USB_DT_DEVICE_QUALIFIER";
	case USB_DT_OTHER_SPEED_CONFIG: return "USB_DT_OTHER_SPEED_CONFIG";
	case USB_DT_INTERFACE_POWER: return "USB_DT_INTERFACE_POWER";
	default: return "*UNKNOWN*";
	}
}

static void ch9setfeature(struct mv_udc *udc, struct usb_ctrlrequest *setup)
{
	u8 ep_num;
	u8 direction;

	if ((setup->bRequestType & (USB_TYPE_MASK | USB_RECIP_MASK))
		== ((USB_TYPE_STANDARD | USB_RECIP_DEVICE))) {
		switch (setup->wValue) {
		case USB_DEVICE_REMOTE_WAKEUP:
			udc->remote_wakeup = 1;
			break;
		case USB_DEVICE_TEST_MODE:
			if (setup->wIndex & 0xFF
				||  udc->gadget.speed != USB_SPEED_HIGH)
				ep0_stall(udc);

			if (udc->usb_state != USB_STATE_CONFIGURED
				&& udc->usb_state != USB_STATE_ADDRESS
				&& udc->usb_state != USB_STATE_DEFAULT)
				ep0_stall(udc);

			mv_udc_testmode(udc, (setup->wIndex >> 8));
			goto out;
		default:
			goto out;
		}
	} else if ((setup->bRequestType & (USB_TYPE_MASK | USB_RECIP_MASK))
		== ((USB_TYPE_STANDARD | USB_RECIP_ENDPOINT))) {
		switch (setup->wValue) {
		case USB_ENDPOINT_HALT:
			ep_num = setup->wIndex & USB_ENDPOINT_NUMBER_MASK;
			direction = (setup->wIndex & USB_ENDPOINT_DIR_MASK)
				? EP_DIR_IN : EP_DIR_OUT;
			if (setup->wValue != 0 || setup->wLength != 0
				|| ep_num > udc->max_eps)
				goto out;
			ep_set_stall(udc, ep_num, direction, 1);
			break;
		default:
			goto out;
		}
	} else
		goto out;

	if (udc_prime_status(udc, EP_DIR_IN, 0, true))
		ep0_stall(udc);
out:
	return;
}

static void handle_setup_packet(struct mv_udc *udc, u8 ep_num,
	struct usb_ctrlrequest *setup)
	__releases(&ep->udc->lock)
	__acquires(&ep->udc->lock)
{
	bool delegate = false;
	int ret;

	nuke(&udc->eps[ep_num * 2 + EP_DIR_OUT], -ESHUTDOWN);

	dev_dbg(&udc->dev->dev, "%s, \t%s, \t%d\n", reqname(setup->bRequest),
		(setup->bRequest == USB_REQ_GET_DESCRIPTOR)
		 ? desc_type(setup->wValue >> 8) : NULL,
		 setup->wIndex);

	/* We process some stardard setup requests here */
	if ((setup->bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD) {
		switch (setup->bRequest) {
		case USB_REQ_GET_STATUS:
			ch9getstatus(udc, ep_num, setup);
			break;

		case USB_REQ_SET_ADDRESS:
			ch9setaddress(udc, setup);
			if (work_pending(&udc->delayed_charger_work.work))
				cancel_delayed_work(&udc->delayed_charger_work);
			udc->charger_type = SDP_CHARGER;
			schedule_delayed_work(&udc->delayed_charger_work, 0);
			break;

		case USB_REQ_CLEAR_FEATURE:
			ch9clearfeature(udc, setup);
			break;

		case USB_REQ_SET_FEATURE:
			ch9setfeature(udc, setup);
			break;

		default:
			delegate = true;
		}
	} else
		delegate = true;

	/* delegate USB standard requests to the gadget driver */
	if (delegate) {
		/* USB requests handled by gadget */
		if (setup->wLength) {
			/* DATA phase from gadget, STATUS phase from udc */
			udc->ep0_dir = (setup->bRequestType & USB_DIR_IN)
					?  EP_DIR_IN : EP_DIR_OUT;
			spin_unlock(&udc->lock);
			ret = udc->driver->setup(&udc->gadget,
						&udc->local_setup_buff);
			spin_lock(&udc->lock);
			if (!udc->active)
				return;
			if (ret < 0)
				ep0_stall(udc);

			udc->ep0_state = (setup->bRequestType & USB_DIR_IN)
					?  DATA_STATE_XMIT : DATA_STATE_RECV;
		} else {
			/* no DATA phase, IN STATUS phase from gadget */
			udc->ep0_dir = EP_DIR_IN;
			spin_unlock(&udc->lock);
			ret = udc->driver->setup(&udc->gadget,
					&udc->local_setup_buff);
			spin_lock(&udc->lock);
			if (!udc->active)
				return;
			if (ret < 0)
				ep0_stall(udc);

			udc->ep0_state = WAIT_FOR_OUT_STATUS;
		}
	}
}

/* complete DATA or STATUS phase of ep0 prime status phase if needed */
static int  ep0_req_complete(struct mv_udc *udc,
	struct mv_ep *ep0, struct mv_req *req)
{
	u32 new_addr;
	int ret;

	if (udc->usb_state == USB_STATE_ADDRESS) {
		/* set the new address */
		new_addr = (u32)udc->dev_addr;
		writel(new_addr << USB_DEVICE_ADDRESS_BIT_SHIFT,
			&udc->op_regs->deviceaddr);
	}

	ret = done(ep0, req, 0);
	if (ret)
		return ret;

	switch (udc->ep0_state) {
	case DATA_STATE_XMIT:
		/* receive status phase */
		if (udc_prime_status(udc, EP_DIR_OUT, 0, true))
			ep0_stall(udc);
		break;
	case DATA_STATE_RECV:
		/* send status phase */
		if (udc_prime_status(udc, EP_DIR_IN, 0 , true))
			ep0_stall(udc);
		break;
	case WAIT_FOR_OUT_STATUS:
		udc->ep0_state = WAIT_FOR_SETUP;
		break;
	case WAIT_FOR_SETUP:
		dev_err(&udc->dev->dev, "unexpect ep0 packets\n");
		break;
	default:
		ep0_stall(udc);
		break;
	}

	return 0;
}

static void get_setup_data(struct mv_udc *udc, u8 ep_num, u8 *buffer_ptr)
{
	u32 temp;
	struct mv_dqh *dqh;

	dqh = &udc->ep_dqh[ep_num * 2 + EP_DIR_OUT];

	/* Clear bit in ENDPTSETUPSTAT */
	writel((1 << ep_num), &udc->op_regs->epsetupstat);

	/* while a hazard exists when setup package arrives */
	do {
		/* Set Setup Tripwire */
		temp = readl(&udc->op_regs->usbcmd);
		writel(temp | USBCMD_SETUP_TRIPWIRE_SET, &udc->op_regs->usbcmd);

		/* Copy the setup packet to local buffer */
		memcpy(buffer_ptr, (u8 *) dqh->setup_buffer, 8);
	} while (!(readl(&udc->op_regs->usbcmd) & USBCMD_SETUP_TRIPWIRE_SET));

	/* Clear Setup Tripwire */
	temp = readl(&udc->op_regs->usbcmd);
	writel(temp & ~USBCMD_SETUP_TRIPWIRE_SET, &udc->op_regs->usbcmd);
}

static void irq_process_tr_complete(struct mv_udc *udc, u32 type)
{
	u32 tmp, bit_pos;
	int i, ep_num = 0, direction = 0;
	struct mv_ep	*curr_ep;
	struct mv_req *curr_req, *temp_req;
	int status;

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	if (type == USBSTS_INT)
		udc->stats.interrupts.tr_complete++;
	else
		udc->stats.interrupts.tr_complete_fake++;
#endif

	/*
	 * We use separate loops for ENDPTSETUPSTAT and ENDPTCOMPLETE
	 * because the setup packets are to be read ASAP
	 */

	/* Process all Setup packet received interrupts */
	tmp = readl(&udc->op_regs->epsetupstat);

	if (tmp) {
		for (i = 0; i < udc->max_eps; i++) {
			if (tmp & (1 << i)) {
#ifdef CONFIG_USB_GADGET_DEBUG_FILES
				udc->eps[i].stats.interrupts.setup++;
#endif
				get_setup_data(udc, i,
					(u8 *)(&udc->local_setup_buff));
				handle_setup_packet(udc, i,
					&udc->local_setup_buff);
			}
		}
	}

	if (!udc->active)
		return;

	if (type == USBSTS_INT) {
		if (udc->rx_opt_state.cur == RX_OPT_IDLE) {
			kick_long_timer(udc);
			rx_opt_switch_state(udc, RX_OPT_ANALYZE);
		} else if (udc->rx_opt_state.cur == RX_OPT_ENABLE)
			kick_short_timer(udc);
	}

	/* Don't clear the endpoint setup status register here.
	 * It is cleared as a setup packet is read out of the buffer
	 */

	/* Process non-setup transaction complete interrupts */
	tmp = readl(&udc->op_regs->epcomplete);

	if (!tmp)
		return;

	writel(tmp, &udc->op_regs->epcomplete);

	for (i = 0; i < udc->max_eps * 2; i++) {
		ep_num = i >> 1;
		direction = i % 2;

		bit_pos = 1 << (ep_num + 16 * direction);

		if (!(bit_pos & tmp))
			continue;

		if (i == 1)
			curr_ep = &udc->eps[0];
		else
			curr_ep = &udc->eps[i];

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
		curr_ep->stats.interrupts.complete++;
#endif
		/* process the req queue until an uncomplete request */
		list_for_each_entry_safe(curr_req, temp_req,
			&curr_ep->queue, queue) {
			status = process_ep_req(udc, i, curr_req);
			if (status)
				break;

			/* write back status to req */
			curr_req->req.status = status;

			/* ep0 request completion */
			if (ep_num == 0) {
				if (ep0_req_complete(udc, curr_ep, curr_req))
					return;
				break;
			} else {
				if (done(curr_ep, curr_req, status))
					return;
			}
		}
	}
}

static void irq_process_reset(struct mv_udc *udc)
{
	u32 tmp;
	unsigned int loops;

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	udc->stats.interrupts.reset++;
#endif
	udc->ep0_dir = EP_DIR_OUT;
	udc->ep0_state = WAIT_FOR_SETUP;
	udc->remote_wakeup = 0;		/* default to 0 on reset */

	/* The address bits are past bit 25-31. Set the address */
	tmp = readl(&udc->op_regs->deviceaddr);
	tmp &= ~(USB_DEVICE_ADDRESS_MASK);
	writel(tmp, &udc->op_regs->deviceaddr);

	/* Clear all the setup token semaphores */
	tmp = readl(&udc->op_regs->epsetupstat);
	writel(tmp, &udc->op_regs->epsetupstat);

	/* Clear all the endpoint complete status bits */
	tmp = readl(&udc->op_regs->epcomplete);
	writel(tmp, &udc->op_regs->epcomplete);

	/* wait until all endptprime bits cleared */
	loops = LOOPS(PRIME_TIMEOUT);
	while (readl(&udc->op_regs->epprime) & 0xFFFFFFFF) {
		if (loops == 0) {
			dev_err(&udc->dev->dev,
				"Timeout for ENDPTPRIME = 0x%x\n",
				readl(&udc->op_regs->epprime));
			break;
		}
		loops--;
		udelay(LOOPS_USEC);
	}

	/* Write 1s to the Flush register */
	writel((u32)~0, &udc->op_regs->epflush);

	if (readl(&udc->op_regs->portsc[0]) & PORTSCX_PORT_RESET) {
		dev_info(&udc->dev->dev, "usb bus reset\n");
		udc->usb_state = USB_STATE_DEFAULT;
		/* reset all the queues, stop all USB activities */
		stop_activity(udc, udc->driver);
	} else {
		dev_info(&udc->dev->dev, "USB reset portsc 0x%x\n",
			readl(&udc->op_regs->portsc));

		/*
		 * re-initialize
		 * controller reset
		 */
		udc_reset(udc);

		/* reset all the queues, stop all USB activities */
		stop_activity(udc, udc->driver);

		/* reset ep0 dQH and endptctrl */
		ep0_reset(udc);

		/* enable interrupt and set controller to run state */
		udc_start(udc);

		udc->usb_state = USB_STATE_ATTACHED;
	}
}

static void handle_bus_resume(struct mv_udc *udc)
{
	udc->usb_state = udc->resume_state;
	udc->resume_state = 0;

	/* report resume to the driver */
	if (udc->driver) {
		if (udc->driver->resume) {
			spin_unlock(&udc->lock);
			udc->driver->resume(&udc->gadget);
			spin_lock(&udc->lock);
		}
	}
}

static void irq_process_suspend(struct mv_udc *udc)
{
#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	udc->stats.interrupts.suspend++;
#endif
	udc->resume_state = udc->usb_state;
	udc->usb_state = USB_STATE_SUSPENDED;

	if (udc->driver->suspend) {
		spin_unlock(&udc->lock);
		udc->driver->suspend(&udc->gadget);
		spin_lock(&udc->lock);
	}
}

static void irq_process_port_change(struct mv_udc *udc)
{
	u32 portsc;

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	udc->stats.interrupts.port_change++;
#endif

	portsc = readl(&udc->op_regs->portsc[0]);
	if (!(portsc & PORTSCX_PORT_RESET)) {
		/* Get the speed */
		u32 speed = portsc & PORTSCX_PORT_SPEED_MASK;
		switch (speed) {
		case PORTSCX_PORT_SPEED_HIGH:
			udc->gadget.speed = USB_SPEED_HIGH;
			break;
		case PORTSCX_PORT_SPEED_FULL:
			udc->gadget.speed = USB_SPEED_FULL;
			break;
		case PORTSCX_PORT_SPEED_LOW:
			udc->gadget.speed = USB_SPEED_LOW;
			break;
		default:
			udc->gadget.speed = USB_SPEED_UNKNOWN;
			break;
		}
	}

	if (portsc & PORTSCX_PORT_SUSPEND) {
		udc->resume_state = udc->usb_state;
		udc->usb_state = USB_STATE_SUSPENDED;
		if (udc->driver->suspend) {
			spin_unlock(&udc->lock);
			udc->driver->suspend(&udc->gadget);
			spin_lock(&udc->lock);
		}
	}

	if (!(portsc & PORTSCX_PORT_SUSPEND)
		&& udc->usb_state == USB_STATE_SUSPENDED) {
		handle_bus_resume(udc);
	}

	if (!udc->resume_state)
		udc->usb_state = USB_STATE_DEFAULT;
}

static void irq_process_error(struct mv_udc *udc)
{
	/* Increment the error count */
	udc->errors++;
#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	udc->stats.interrupts.err++;
#endif
}

static irqreturn_t mv_udc_irq(int irq, void *dev)
{
	struct mv_udc *udc = (struct mv_udc *)dev;
	u32 status, intr;

#ifdef CONFIG_USB_GADGET_DEBUG_FILES
	udc->stats.interrupts.total++;
#endif
	spin_lock(&udc->lock);

	/* Disable ISR when stopped bit is set */
	if (udc->stopped) {
		spin_unlock(&udc->lock);
		return IRQ_NONE;
	}

	status = readl(&udc->op_regs->usbsts);
	intr = readl(&udc->op_regs->usbintr);
	status &= intr;

	if (status == 0) {
		spin_unlock(&udc->lock);
		return IRQ_NONE;
	}

	/* Clear all the interrupts occurred */
	writel(status, &udc->op_regs->usbsts);

	if (status & USBSTS_ERR)
		irq_process_error(udc);

	if (status & USBSTS_RESET)
		irq_process_reset(udc);

	if (status & USBSTS_PORT_CHANGE)
		irq_process_port_change(udc);

	if (status & USBSTS_SUSPEND)
		irq_process_suspend(udc);

	if (status & USBSTS_INT)
		irq_process_tr_complete(udc, USBSTS_INT);

	if (status & USBSTS_IT0) {
		rx_opt_process_short_timeout(udc);
		irq_process_tr_complete(udc, USBSTS_IT0);
	}

	if (status & USBSTS_IT1) {
		rx_opt_process_long_timeout(udc);
		irq_process_tr_complete(udc, USBSTS_IT1);
	}

	spin_unlock(&udc->lock);

	return IRQ_HANDLED;
}

static BLOCKING_NOTIFIER_HEAD(mv_udc_notifier_list);

/* For any user that care about USB udc events, for example the charger*/
int mv_udc_register_client(struct notifier_block *nb)
{
	struct mv_udc *udc = the_controller;
	int ret = 0;

	ret = blocking_notifier_chain_register(&mv_udc_notifier_list, nb);
	if (ret)
		return ret;

	if (!udc)
		return -ENODEV;

	if (udc->charger_type)
		call_charger_notifier(udc);

	return 0;
}
EXPORT_SYMBOL(mv_udc_register_client);

int mv_udc_unregister_client(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&mv_udc_notifier_list, nb);
}
EXPORT_SYMBOL(mv_udc_unregister_client);

static void call_charger_notifier(struct mv_udc *udc)
{
	/* notify the interested guy the charger type is ready */
	power_supply_changed(&udc->udc_psy);
}

static void do_delayed_charger_work(struct work_struct *work)
{
	u32 portsc;
	struct mv_udc *udc = NULL;
	udc = container_of(work, struct mv_udc, delayed_charger_work.work);

	/* if still see DEFAULT_CHARGER, check again */
	if (udc->charger_type == DEFAULT_CHARGER) {
		/* check LINE STATUS to detect DCP */
		portsc = readl(&udc->op_regs->portsc[0]);
		if (PORTSCX_LINE_STATUS_MASK == (portsc & PORTSCX_LINE_STATUS_MASK))
			udc->charger_type = DCP_CHARGER;
		else
			udc->charger_type = NONE_STANDARD_CHARGER;
	}

	dev_info(&udc->dev->dev, "final charger type: %s\n",
				charger_type(udc->charger_type));

	call_charger_notifier(udc);

	/* SDP or CDP need transfer data, hold wake lock */
	if ((udc->charger_type == SDP_CHARGER) ||
	    (udc->charger_type == CDP_CHARGER)) {
		pm_stay_awake(&udc->dev->dev);
		pm_qos_update_request(&udc->qos_idle, udc->lpm_qos);
	/* NULL, DEFAULT, DCP, UNKNOW chargers don't need wake lock */
	} else {
		pm_qos_update_request(&udc->qos_idle,
				PM_QOS_CPUIDLE_BLOCK_DEFAULT_VALUE);
		/* leave some delay for charger driver to do something */
		pm_wakeup_event(&udc->dev->dev, 1000);

		/* disable udc for DCP charger */
		if (udc->charger_type == DCP_CHARGER)
			mv_udc_disable(udc);
	}
}

static int mv_udc_vbus_notifier_call(struct notifier_block *nb,
					unsigned long val, void *v)
{
	struct mv_udc *udc = container_of(nb, struct mv_udc, notifier);

	/* polling VBUS and init phy may cause too much time*/
	if (udc->qwork)
		queue_work(udc->qwork, &udc->vbus_work);

	return 0;
}

static void mv_udc_vbus_work(struct work_struct *work)
{
	struct mv_udc *udc;
	unsigned int vbus = 0;

	udc = container_of(work, struct mv_udc, vbus_work);

	vbus = extcon_get_cable_state(udc->extcon, "VBUS");
	dev_info(&udc->dev->dev, "vbus is %d\n", vbus);

	mv_udc_vbus_session(&udc->gadget, vbus);
}


/*-------------------------------------------------------------------------
		PROC File System Support
-------------------------------------------------------------------------*/
#ifdef CONFIG_USB_GADGET_DEBUG_FILES

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static const char proc_filename[] = "driver/mv_udc";

static int mv_proc_read(struct seq_file *m, void *v)
{
	unsigned long flags;
	int i;
	u32 tmp_reg;
	struct mv_ep *ep = NULL;
	struct mv_req *req;

	struct mv_udc *udc = the_controller;

	spin_lock_irqsave(&udc->lock, flags);

	/* ------basic driver information ---- */
	seq_printf(m,
			DRIVER_DESC "\n"
			"%s version: %s\n"
			"Gadget driver: %s\n\n",
			driver_name, DRIVER_VERSION,
			udc->driver ? udc->driver->driver.name : "(none)");

	/* ------ DR Registers ----- */
	tmp_reg = readl(&udc->op_regs->usbcmd);
	seq_printf(m,
			"USBCMD reg:\n"
			"SetupTW: %d\n"
			"Run/Stop: %s\n\n",
			(tmp_reg & USBCMD_SETUP_TRIPWIRE_SET) ? 1 : 0,
			(tmp_reg & USBCMD_RUN_STOP) ? "Run" : "Stop");

	tmp_reg = readl(&udc->op_regs->usbsts);
	seq_printf(m,
			"USB Status Reg:\n"
			"USB Suspend: %d Reset Received: %d System Error: %s "
			"USB Error Interrupt: %s USB Interrupt: %d\n\n",
			(tmp_reg & USBSTS_SUSPEND) ? 1 : 0,
			(tmp_reg & USBSTS_RESET) ? 1 : 0,
			(tmp_reg & USBSTS_SYS_ERR) ? "Err" : "Normal",
			(tmp_reg & USBSTS_ERR) ? "Err detected" : "No err",
			(tmp_reg & USBSTS_INT) ? 1 : 0);

	tmp_reg = readl(&udc->op_regs->usbintr);
	seq_printf(m,
			"USB Interrupt Enable Reg:\n"
			"Sleep Enable: %d SOF Received Enable: %d "
			"Reset Enable: %d\n"
			"System Error Enable: %d "
			"Port Change Detected Enable: %d\n"
			"USB Error Intr Enable: %d USB Intr Enable: %d"
			"gptimer 0 enable: %d gptimer 1 enable: %d\n\n",
			(tmp_reg & USBINTR_DEVICE_SUSPEND) ? 1 : 0,
			(tmp_reg & USBINTR_SOF_UFRAME_EN) ? 1 : 0,
			(tmp_reg & USBINTR_RESET_EN) ? 1 : 0,
			(tmp_reg & USBINTR_SYS_ERR_EN) ? 1 : 0,
			(tmp_reg & USBINTR_PORT_CHANGE_DETECT_EN) ? 1 : 0,
			(tmp_reg & USBINTR_ERR_INT_EN) ? 1 : 0,
			(tmp_reg & USBINTR_INT_EN) ? 1 : 0,
			(tmp_reg & USBINTR_GPTIMER0_EN) ? 1 : 0,
			(tmp_reg & USBINTR_GPTIMER1_EN) ? 1 : 0);

	tmp_reg = readl(&udc->op_regs->frindex);
	seq_printf(m,
			"USB Frame Index Reg: Frame Number is 0x%x\n\n",
			(tmp_reg & USB_FRINDEX_MASKS));

	tmp_reg = readl(&udc->op_regs->deviceaddr);
	seq_printf(m,
			"USB Device Address Reg: Device Addr is 0x%x\n\n",
			(tmp_reg & USB_DEVICE_ADDRESS_MASK));

	tmp_reg = readl(&udc->op_regs->eplistaddr);
	seq_printf(m,
			"USB Endpoint List Address Reg: "
			"Device Addr is 0x%x\n\n",
			(tmp_reg & USB_EP_LIST_ADDRESS_MASK));

	tmp_reg = readl(&udc->op_regs->portsc[0]);
	seq_printf(m,
		"USB Port Status&Control Reg:\n"
		"Port Transceiver Type : %s Port Speed: %s\n"
		"PHY Low Power Suspend: %s Port Reset: %s "
		"Port Suspend Mode: %s\n"
		"Over-current Change: %s "
		"Port Enable/Disable Change: %s\n"
		"Port Enabled/Disabled: %s "
		"Current Connect Status: %s\n\n", ({
			const char *s;
			switch (tmp_reg & PORTSCX_PAR_XCVR_SELECT) {
			case PORTSCX_PTS_UTMI:
				s = "UTMI"; break;
			case PORTSCX_PTS_ULPI:
				s = "ULPI "; break;
			case PORTSCX_PTS_FSLS:
				s = "FS/LS Serial"; break;
			default:
				s = "None"; break;
			}
			s; }),
		usb_speed_string(udc->gadget.speed),
		(tmp_reg & PORTSCX_PHY_LOW_POWER_SPD) ?
		"Normal PHY mode" : "Low power mode",
		(tmp_reg & PORTSCX_PORT_RESET) ? "In Reset" :
		"Not in Reset",
		(tmp_reg & PORTSCX_PORT_SUSPEND) ? "In " : "Not in",
		(tmp_reg & PORTSCX_OVER_CURRENT_CHG) ? "Detected" :
		"No",
		(tmp_reg & PORTSCX_PORT_EN_DIS_CHANGE) ? "Disable" :
		"Not change",
		(tmp_reg & PORTSCX_PORT_ENABLE) ? "Enable" :
		"Not correct",
		(tmp_reg & PORTSCX_CURRENT_CONNECT_STATUS) ?
		"Attached" : "Not-Att");

	tmp_reg = readl(&udc->op_regs->usbmode);
	seq_printf(m,
			"USB Mode Reg: Controller Mode is: %s\n\n", ({
				const char *s;
				switch (tmp_reg & USBMODE_CTRL_MODE_HOST) {
				case USBMODE_CTRL_MODE_IDLE:
					s = "Idle"; break;
				case USBMODE_CTRL_MODE_DEVICE:
					s = "Device Controller"; break;
				case USBMODE_CTRL_MODE_HOST:
					s = "Host Controller"; break;
				default:
					s = "None"; break;
				}
				s;
			}));

	tmp_reg = readl(&udc->op_regs->epsetupstat);
	seq_printf(m,
			"Endpoint Setup Status Reg: SETUP on ep 0x%x\n\n",
			(tmp_reg & EP_SETUP_STATUS_MASK));

	for (i = 0; i < udc->max_eps ; i++) {
		tmp_reg = readl(&udc->op_regs->epctrlx[i]);
		seq_printf(m, "EP Ctrl Reg [0x%x]: = [0x%x]\n", i, tmp_reg);
	}
	tmp_reg = readl(&udc->op_regs->epprime);
	seq_printf(m, "EP Prime Reg = [0x%x]\n\n", tmp_reg);

	seq_printf(m, "USB Interrupts Statistics\n"
		      "total:%d, tr_complete:%d, err:%d, reset:%d, suspend:%d, "
		      "port_change:%d\n\n",
		      udc->stats.interrupts.total,
		      udc->stats.interrupts.tr_complete,
		      udc->stats.interrupts.err,
		      udc->stats.interrupts.reset,
		      udc->stats.interrupts.suspend,
		      udc->stats.interrupts.port_change);

	/* ------mv_udc, mv_ep, mv_request structure information ----- */
	seq_puts(m, "USB endpoints statistics\n");
	ep = &udc->eps[0];
	seq_printf(m, "For %s Maxpkt is 0x%x index is 0x%x\n",
			ep->ep.name, ep_maxpacket(ep), ep_index(ep));
	seq_printf(m, "Interrupts: setup:%d, complete:%d\n",
				       ep->stats.interrupts.setup,
				       ep->stats.interrupts.complete);
	seq_printf(m, "queue:%d, dequeue:%d, enable:%d, disable:%d, flush:%d\n",
		   ep->stats.queue, ep->stats.dequeue, ep->stats.enable,
		   ep->stats.disable, ep->stats.flush);
	if (list_empty(&ep->queue)) {
		seq_puts(m, "its req queue is empty\n\n");
	} else {
		list_for_each_entry(req, &ep->queue, queue) {
			seq_printf(m,
				"req %p actual 0x%x length 0x%x buf %p\n",
				&req->req, req->req.actual,
				req->req.length, req->req.buf);
		}
	}

	/* other gadget->eplist ep */
	list_for_each_entry(ep, &udc->gadget.ep_list, ep.ep_list) {
		if (ep->ep.desc) {
			seq_printf(m,
					"\nFor %s Maxpkt is 0x%x "
					"index is 0x%x\n",
					ep->ep.name, ep_maxpacket(ep),
					ep_index(ep));
			seq_printf(m, "Interrupts: setup:%d, complete:%d\n",
				       ep->stats.interrupts.setup,
				       ep->stats.interrupts.complete);
			seq_printf(m, "queue:%d, dequeue:%d, enable:%d, "
				      "disable:%d, flush:%d\n",
				       ep->stats.queue, ep->stats.dequeue,
				       ep->stats.enable, ep->stats.disable,
				       ep->stats.flush);
			if (list_empty(&ep->queue)) {
				seq_puts(m, "its req queue is empty\n\n");
			} else {
				list_for_each_entry(req, &ep->queue, queue) {
					seq_printf(m,
						"req %p actual 0x%x length "
						"0x%x  buf %p\n",
						&req->req, req->req.actual,
						req->req.length, req->req.buf);
				}	/* end for each_entry of ep req */
			}	/* end for else */
		}	/* end for if(ep->queue) */
	}	/* end (ep->desc) */

	spin_unlock_irqrestore(&udc->lock, flags);
	return 0;
}

static ssize_t mv_proc_write(struct file *f, const char __user *buf,
			      size_t count, loff_t *off)
{
	struct mv_udc *udc = the_controller;
	struct mv_ep *ep = NULL;
	unsigned long flags;

	spin_lock_irqsave(&udc->lock, flags);
	memset(&udc->stats, 0, sizeof(udc->stats));
	memset(&udc->eps[0].stats, 0, sizeof(udc->eps[0].stats));
	list_for_each_entry(ep, &udc->gadget.ep_list, ep.ep_list)
		memset(&ep->stats, 0, sizeof(ep->stats));
	spin_unlock_irqrestore(&udc->lock, flags);
	return count;
}

/*
 * seq_file wrappers for procfile show routines.
 */
static int mv_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, mv_proc_read, NULL);
}

static const struct file_operations mv_proc_fops = {
	.open		= mv_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= mv_proc_write,
};

#define create_proc_file() proc_create(proc_filename, 0, NULL, &mv_proc_fops)
#define remove_proc_file() remove_proc_entry(proc_filename, NULL)

#else				/* !CONFIG_USB_GADGET_DEBUG_FILES */

#define create_proc_file() do {} while (0)
#define remove_proc_file() do {} while (0)

#endif				/* CONFIG_USB_GADGET_DEBUG_FILES */

/* release device structure */
static void gadget_release(struct device *_dev)
{
	struct mv_udc *udc;

	udc = dev_get_drvdata(_dev);

	complete(udc->done);
}

static int mv_udc_remove(struct platform_device *pdev)
{
	struct mv_udc *udc;

	device_init_wakeup(&pdev->dev, 0);
	udc = platform_get_drvdata(pdev);

	power_supply_unregister(&udc->udc_psy);

	usb_del_gadget_udc(&udc->gadget);

	if (udc->pdata && (udc->pdata->extern_attr & MV_USB_HAS_VBUS_DETECTION)
		&& udc->clock_gating && udc->transceiver == NULL)
		extcon_unregister_interest(&udc->vbus_dev);

	if (udc->qwork) {
		flush_workqueue(udc->qwork);
		destroy_workqueue(udc->qwork);
	}

	remove_proc_file();

#ifdef CONFIG_USB_MV_UDC_RX_INT_OPT_SYS_FS
	sysfs_remove_group(&udc->gadget.dev.kobj, &mv_udc_attr_group);
#endif

	mv_udc_rx_opt_exit(udc);

	/* free memory allocated in probe */
	if (udc->dtd_pool)
		dma_pool_destroy(udc->dtd_pool);

	if (udc->ep_dqh)
		dma_free_coherent(&pdev->dev, udc->ep_dqh_size,
			udc->ep_dqh, udc->ep_dqh_dma);

	mv_udc_disable(udc);

	clk_unprepare(udc->clk);

	/* free dev, wait for the release() finished */
	wait_for_completion(udc->done);

	pm_qos_remove_request(&udc->qos_idle);

	the_controller = NULL;

	return 0;
}

static int mv_udc_dt_parse(struct platform_device *pdev,
			struct mv_usb_platform_data *pdata)
{
	struct device_node *np = pdev->dev.of_node;

	if (of_property_read_string(np, "marvell,udc-name",
			&((pdev->dev).init_name)))
		return -EINVAL;

	if (of_property_read_u32(np, "marvell,udc-mode", &(pdata->mode)))
		return -EINVAL;

	if (of_property_read_u32(np, "marvell,dev-id", &(pdata->id)))
		pdata->id = PXA_USB_DEV_OTG;

	of_property_read_u32(np, "marvell,extern-attr", &(pdata->extern_attr));
	pdata->otg_force_a_bus_req = of_property_read_bool(np,
					"marvell,otg-force-a-bus-req");
	pdata->disable_otg_clock_gating = of_property_read_bool(np,
						"marvell,disable-otg-clock-gating");

	return 0;
}

static int mv_udc_psy_get_property(struct power_supply *psy,
				   enum power_supply_property psp,
				   union power_supply_propval *val)
{
	struct mv_udc *udc;
	udc = container_of(psy, struct mv_udc, udc_psy);
	/* convert the private charger type to stanard power_supply_type */

	switch (psp) {
	case POWER_SUPPLY_PROP_PRESENT:
		val->intval = udc->vbus_active;
		break;
	case POWER_SUPPLY_PROP_TYPE:
		val->intval = map_charger_type(udc->charger_type);
		break;
	default:
		return -EINVAL;
	}

	/* this function is used by charger driver to obtain the charger type*/
	return 0;
}

static int mv_udc_psy_set_property(struct power_supply *psy,
				  enum power_supply_property psp,
				  const union power_supply_propval *val)
{
	struct mv_udc *udc;
	udc = container_of(psy, struct mv_udc, udc_psy);
	/* set the charger type */
	switch (psp) {
	case POWER_SUPPLY_PROP_TYPE:
		psy->type = val->intval;

		switch (psy->type) {
		case POWER_SUPPLY_TYPE_UNKNOWN:
			udc->charger_type = NULL_CHARGER;
			break;
		case POWER_SUPPLY_TYPE_USB_DCP:
			udc->charger_type = DCP_CHARGER;
			break;
		case POWER_SUPPLY_TYPE_USB_CDP:
			udc->charger_type = CDP_CHARGER;
			break;
		case POWER_SUPPLY_TYPE_USB:
			udc->charger_type = SDP_CHARGER;
			break;
		default:
			udc->charger_type = NONE_STANDARD_CHARGER;
			break;
		}

		break;
	default:
		break;

	}

	/* notify the charger driver the charger type is ready */
	power_supply_changed(&udc->udc_psy);

	return 0;
}

static void mv_udc_psy_external_power_changed(struct power_supply *psy)
{
	/* seems no one supplies me ? */
}

static int mv_udc_psy_property_is_writeable(struct power_supply *psy,
					    enum power_supply_property psp)
{
	return 1;
}

static char *mv_udc_psy_supplied_to[] = {
	"88pm88x-charger",
};

static enum power_supply_property mv_udc_psy_props[] = {
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_TYPE,
};

static int mv_udc_psy_register(struct mv_udc *udc)
{
	int ret;
	if (!udc)
		return -EINVAL;

	udc->udc_psy.name = "mv-udc-psy";
	udc->udc_psy.type = POWER_SUPPLY_TYPE_UNKNOWN;
	udc->udc_psy.supplied_to = mv_udc_psy_supplied_to;
	udc->udc_psy.num_supplicants = ARRAY_SIZE(mv_udc_psy_supplied_to);
	udc->udc_psy.properties = mv_udc_psy_props;
	udc->udc_psy.num_properties = ARRAY_SIZE(mv_udc_psy_props);
	udc->udc_psy.get_property = mv_udc_psy_get_property;
	udc->udc_psy.set_property = mv_udc_psy_set_property;
	udc->udc_psy.external_power_changed = mv_udc_psy_external_power_changed;
	udc->udc_psy.property_is_writeable = mv_udc_psy_property_is_writeable;

	ret = power_supply_register(&udc->dev->dev, &udc->udc_psy);
	if (ret < 0) {
		dev_err(&udc->dev->dev, "%s: fail to register psy.\n", __func__);
		return ret;
	}

	return ret;
}

static void mv_udc_psy_unregister(struct mv_udc *udc)
{
	power_supply_unregister(&udc->udc_psy);
}

static int mv_udc_probe(struct platform_device *pdev)
{
	struct mv_usb_platform_data *pdata;
	struct mv_udc *udc;
	int retval = 0;
	struct resource *r;
	size_t size;
	struct device_node *np = pdev->dev.of_node;
	const __be32 *prop;
	unsigned int proplen;

	unsigned char *regbase;

	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
	if (pdata == NULL) {
		dev_err(&pdev->dev, "failed to allocate memory for platform_data\n");
		return -ENODEV;
	}
	mv_udc_dt_parse(pdev, pdata);
	udc = devm_kzalloc(&pdev->dev, sizeof(*udc), GFP_KERNEL);
	if (udc == NULL) {
		dev_err(&pdev->dev, "failed to allocate memory for udc\n");
		return -ENOMEM;
	}

	the_controller = udc;

	udc->done = &release_done;
	udc->pdata = pdata;
	spin_lock_init(&udc->lock);

	udc->dev = pdev;

	if (pdata->mode == MV_USB_MODE_OTG) {
		udc->transceiver = devm_usb_get_phy_dev(&pdev->dev,
							MV_USB2_OTG_PHY_INDEX);
		/* try again */
		if (IS_ERR_OR_NULL(udc->transceiver))
			return -EPROBE_DEFER;
	}

	/* udc only have one sysclk. */
	udc->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(udc->clk))
		return PTR_ERR(udc->clk);
	clk_prepare(udc->clk);

	r = platform_get_resource(udc->dev, IORESOURCE_MEM, 0);
	if (r == NULL) {
		dev_err(&pdev->dev, "no I/O memory resource defined\n");
		return -ENODEV;
	}

	regbase = (unsigned char *)
		devm_ioremap(&pdev->dev, r->start, resource_size(r));
	if (regbase == NULL) {
		dev_err(&pdev->dev, "failed to map I/O memory\n");
		return -EBUSY;
	}

	udc->timer_regs = (struct mv_timer_regs __iomem *)
		((unsigned long)regbase + USB_GPTIMER_REG_OFFSET);

	udc->cap_regs = (struct mv_cap_regs __iomem *)
		((unsigned long)regbase + USB_CAP_REG_OFFSET);

	udc->phy = devm_usb_get_phy_dev(&pdev->dev, MV_USB2_PHY_INDEX);
	if (IS_ERR_OR_NULL(udc->phy))
		return -EPROBE_DEFER;

	/* we will acces controller register, so enable the clk */
	retval = mv_udc_enable_internal(udc);
	if (retval)
		return retval;

	udc->op_regs =
		(struct mv_op_regs __iomem *)((unsigned long)udc->cap_regs
		+ (readl(&udc->cap_regs->caplength_hciversion)
			& CAPLENGTH_MASK));
	udc->max_eps = readl(&udc->cap_regs->dccparams) & DCCPARAMS_DEN_MASK;

	/*
	 * some platform will use usb to download image, it may not disconnect
	 * usb gadget before loading kernel. So first stop udc here.
	 */
	udc_stop(udc);
	writel(0xFFFFFFFF, &udc->op_regs->usbsts);

	size = udc->max_eps * sizeof(struct mv_dqh) *2;
	size = (size + DQH_ALIGNMENT - 1) & ~(DQH_ALIGNMENT - 1);
	udc->ep_dqh = dma_alloc_coherent(&pdev->dev, size,
					&udc->ep_dqh_dma, GFP_KERNEL);

	if (udc->ep_dqh == NULL) {
		dev_err(&pdev->dev, "allocate dQH memory failed\n");
		retval = -ENOMEM;
		goto err_disable_clock;
	}
	udc->ep_dqh_size = size;

	/* create dTD dma_pool resource */
	udc->dtd_pool = dma_pool_create("mv_dtd",
			&pdev->dev,
			sizeof(struct mv_dtd),
			DTD_ALIGNMENT,
			DMA_BOUNDARY);

	if (!udc->dtd_pool) {
		retval = -ENOMEM;
		goto err_free_dma;
	}

	size = udc->max_eps * sizeof(struct mv_ep) *2;
	udc->eps = devm_kzalloc(&pdev->dev, size, GFP_KERNEL);
	if (udc->eps == NULL) {
		dev_err(&pdev->dev, "allocate ep memory failed\n");
		retval = -ENOMEM;
		goto err_destroy_dma;
	}

	/* initialize ep0 status request structure */
	udc->status_req = devm_kzalloc(&pdev->dev, sizeof(struct mv_req),
					GFP_KERNEL);
	if (!udc->status_req) {
		dev_err(&pdev->dev, "allocate status_req memory failed\n");
		retval = -ENOMEM;
		goto err_destroy_dma;
	}
	INIT_LIST_HEAD(&udc->status_req->queue);

	/* allocate a small amount of memory to get valid address */
	udc->status_req->req.buf = kzalloc(8, GFP_KERNEL);
	udc->status_req->req.dma = DMA_ADDR_INVALID;

	udc->resume_state = USB_STATE_NOTATTACHED;
	udc->usb_state = USB_STATE_POWERED;
	udc->ep0_dir = EP_DIR_OUT;
	udc->remote_wakeup = 0;

	r = platform_get_resource(udc->dev, IORESOURCE_IRQ, 0);
	if (r == NULL) {
		dev_err(&pdev->dev, "no IRQ resource defined\n");
		retval = -ENODEV;
		goto err_destroy_dma;
	}
	udc->irq = r->start;
	if (devm_request_irq(&pdev->dev, udc->irq, mv_udc_irq,
		IRQF_SHARED, driver_name, udc)) {
		dev_err(&pdev->dev, "Request irq %d for UDC failed\n",
			udc->irq);
		retval = -ENODEV;
		goto err_destroy_dma;
	}

	/* initialize gadget structure */
	udc->gadget.ops = &mv_ops;	/* usb_gadget_ops */
	udc->gadget.ep0 = &udc->eps[0].ep;	/* gadget ep0 */
	INIT_LIST_HEAD(&udc->gadget.ep_list);	/* ep_list */
	udc->gadget.speed = USB_SPEED_UNKNOWN;	/* speed */
	udc->gadget.max_speed = USB_SPEED_HIGH;	/* support dual speed */

	/* the "gadget" abstracts/virtualizes the controller */
	udc->gadget.name = driver_name;		/* gadget name */

	eps_init(udc);

	/* used to tell user space when usb cable plug in and out */
	INIT_WORK(&udc->event_work, uevent_worker);

	INIT_DELAYED_WORK(&udc->delayed_charger_work, do_delayed_charger_work);
	udc->charger_type = NULL_CHARGER;

	/*--------------------handle vbus-----------------------------*/
	/* TODO: use device tree to parse extcon device name */
	udc->extcon = extcon_get_extcon_dev("88pm88x-extcon");
	if (!udc->extcon)
		return -EPROBE_DEFER;
	if ((pdata->extern_attr & MV_USB_HAS_VBUS_DETECTION)
	    || udc->transceiver)
		udc->clock_gating = 1;

	if ((pdata->extern_attr & MV_USB_HAS_VBUS_DETECTION)
	    && udc->transceiver == NULL) {

		udc->notifier.notifier_call = mv_udc_vbus_notifier_call;
		retval = extcon_register_interest(&udc->vbus_dev,
						  "88pm88x-extcon",
						  "VBUS", &udc->notifier);
		if (retval)
			return retval;

		udc->vbus_active = extcon_get_cable_state(udc->extcon, "VBUS");
		udc->qwork = create_singlethread_workqueue("mv_udc_queue");
		if (!udc->qwork) {
			dev_err(&pdev->dev, "cannot create workqueue\n");
			retval = -ENOMEM;
			goto err_create_workqueue;
		}

		INIT_WORK(&udc->vbus_work, mv_udc_vbus_work);
	}

	retval = mv_udc_psy_register(udc);
	if (retval < 0) {
		dev_err(&pdev->dev, "%s: Register udc psy fails.\n", __func__);
		goto err_destroy_dma;
	}

	 /*
	  * When clock gating is supported, we can disable clk and phy.
	  * If not, it means that VBUS detection is not supported, we
	  * have to enable vbus active all the time to let controller work.
	  */
	if (udc->clock_gating)
		mv_udc_disable_internal(udc);
	else
		udc->vbus_active = 1;

	retval = usb_add_gadget_udc_release(&pdev->dev, &udc->gadget,
			gadget_release);
	if (retval)
		goto err_create_workqueue;

	platform_set_drvdata(pdev, udc);
	device_init_wakeup(&pdev->dev, 1);

	prop = of_get_property(np, "lpm-qos", &proplen);
	if (!prop) {
		pr_err("lpm-qos config in DT for mv_udc is not defined\n");
		goto err_create_workqueue;
	} else
		udc->lpm_qos = be32_to_cpup(prop);

	udc->qos_idle.name = udc->dev->name;
	pm_qos_add_request(&udc->qos_idle, PM_QOS_CPUIDLE_BLOCK,
			PM_QOS_CPUIDLE_BLOCK_DEFAULT_VALUE);

	retval = mv_udc_rx_opt_init(udc);
	if (retval) {
		pr_err("rx interrutp optimization failed\n");
		goto err_create_workqueue;

	}

#ifdef CONFIG_USB_MV_UDC_RX_INT_OPT_SYS_FS
	retval = sysfs_create_group(&udc->gadget.dev.kobj, &mv_udc_attr_group);
	if (retval) {
		pr_err("mv_udc: sysfs_create_group failed\n");
		goto err_rx_opt_exit;
	}
#endif

	if (udc->transceiver) {
		retval = otg_set_peripheral(udc->transceiver->otg,
						&udc->gadget);
		if (retval) {
			dev_err(&udc->dev->dev,
				"unable to register peripheral to otg\n");
			return retval;
		}
	}

	dev_info(&pdev->dev, "successful probe UDC device %s clock gating.\n",
		udc->clock_gating ? "with" : "without");

	create_proc_file();
	return 0;

#ifdef CONFIG_USB_MV_UDC_RX_INT_OPT_SYS_FS
err_rx_opt_exit:
	mv_udc_rx_opt_exit(udc);
#endif
err_create_workqueue:
	mv_udc_psy_unregister(udc);

	if (udc->qwork) {
		flush_workqueue(udc->qwork);
		destroy_workqueue(udc->qwork);
	}
	extcon_unregister_interest(&udc->vbus_dev);
err_destroy_dma:
	dma_pool_destroy(udc->dtd_pool);
err_free_dma:
	dma_free_coherent(&pdev->dev, udc->ep_dqh_size,
			udc->ep_dqh, udc->ep_dqh_dma);
err_disable_clock:
	mv_udc_disable_internal(udc);
	the_controller = NULL;
	return retval;
}

#ifdef CONFIG_PM
static int mv_udc_suspend(struct device *dev)
{
	struct mv_udc *udc;

	udc = dev_get_drvdata(dev);

	/* if OTG is enabled, the following will be done in OTG driver*/
	if (udc->transceiver)
		return 0;

	if (!udc->clock_gating) {
		spin_lock_irq(&udc->lock);
		/* stop all usb activities */
		udc_stop(udc);
		stop_activity(udc, udc->driver);
		spin_unlock_irq(&udc->lock);

		mv_udc_disable_internal(udc);
	}

	return 0;
}

static int mv_udc_resume(struct device *dev)
{
	struct mv_udc *udc;
	int retval;

	udc = dev_get_drvdata(dev);

	/* if OTG is enabled, the following will be done in OTG driver*/
	if (udc->transceiver)
		return 0;

	if (!udc->clock_gating) {
		retval = mv_udc_enable_internal(udc);
		if (retval)
			return retval;

		if (udc->driver && udc->softconnect) {
			udc_reset(udc);
			ep0_reset(udc);
			udc_start(udc);
		}
	}

	return 0;
}

static const struct dev_pm_ops mv_udc_pm_ops = {
	.suspend	= mv_udc_suspend,
	.resume		= mv_udc_resume,
};
#endif

static void mv_udc_shutdown(struct platform_device *pdev)
{
	struct mv_udc *udc = the_controller;

	if (!udc)
		return;
	mv_udc_pullup(&udc->gadget, 0);
}

static const struct of_device_id mv_udc_dt_match[] = {
	{ .compatible = "marvell,mv-udc" },
	{},
};
MODULE_DEVICE_TABLE(of, mv_udc_dt_match);

static struct platform_driver udc_driver = {
	.probe		= mv_udc_probe,
	.remove		= mv_udc_remove,
	.shutdown	= mv_udc_shutdown,
	.driver		= {
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(mv_udc_dt_match),
		.name	= "mv-udc",
#ifdef CONFIG_PM
		.pm	= &mv_udc_pm_ops,
#endif
	},
};

module_platform_driver(udc_driver);
MODULE_ALIAS("platform:mv-udc");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_AUTHOR("Chao Xie <chao.xie@marvell.com>");
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");
