/*
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
#include <linux/version.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include <linux/pxa9xx_amipc.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "portqueue.h"
#include "msocket.h"
#include "shm.h"
#include "shm_share.h"
#include "pxa_m3_rm.h"

#define TX_RESUME		0x9
#define TX_STOP			0x81

static int m3_grp_init(void);
static int m3_grp_exit(void);
static int m3_grp_open(void);
static int m3_grp_close(void);
static void m3_grp_notify_fc(void);
static void m3_grp_connect(void);
static void m3_grp_disconnect(void);
static bool m3_synced(void);

static struct wakeup_source amipc_wakeup;

static bool m3_is_synced;
static DECLARE_COMPLETION(m3_peer_sync);

/* port queue priority definition */
static const int portq_m3_priority[PORTQ_M3_NUM_MAX] = {
	10,			/* 0: GPS_COMM_PORT */
	10,			/* 1: SENSOR_HUB_PORT */
	40,			/* 2: M3_TEST_PORT */
};

static void amipc_notify_peer_sync(void)
{
	if (amipc_datasend(AMIPC_SHM_PACKET_NOTIFY, PEER_SYNC,
		0, 0) != AMIPC_RC_OK)
		pr_err_ratelimited("%s: notify m3 failed\n", __func__);
}

/* notify m3 that new packet available in the socket buffer */
static void amipc_notify_packet_sent(void)
{
	if (amipc_datasend(AMIPC_SHM_PACKET_NOTIFY, PACKET_SENT,
		0, 0) != AMIPC_RC_OK)
		pr_err_ratelimited("%s: notify m3 failed\n", __func__);
}

/* notify m3 that m3 can continue transmission */
static void amipc_notify_m3_tx_resume(void)
{
	pr_warn("MSOCK: amipc_notify_m3_tx_resume!!!\n");
	if (amipc_datasend(AMIPC_RINGBUF_FC, TX_RESUME,
		0, 0) != AMIPC_RC_OK)
		pr_err_ratelimited("%s: notify m3 failed\n", __func__);
}

/*notify m3 that ap transmission is stopped, please resume me later */
static void amipc_notify_ap_tx_stopped(void)
{
	pr_warn("MSOCK: amipc_notify_ap_tx_stopped!!!\n");
	if (amipc_datasend(AMIPC_RINGBUF_FC, TX_STOP,
		0, 0) != AMIPC_RC_OK)
		pr_err_ratelimited("%s: notify m3 failed\n", __func__);
}

static struct portq_op m3_op = {
		.init = m3_grp_init,
		.exit = m3_grp_exit,
		.open = m3_grp_open,
		.close = m3_grp_close,
		.connect = m3_grp_connect,
		.disconnect = m3_grp_disconnect,
		.notify_sent = amipc_notify_packet_sent,
		.notify_fc_change = m3_grp_notify_fc,
		.tx_resume = amipc_notify_m3_tx_resume,
		.tx_stop = amipc_notify_ap_tx_stopped,
		.is_synced = m3_synced
};

struct portq_group pgrp_m3 = {
		.name = "m3",
		.grp_type = portq_grp_m3,
		.port_cnt = PORTQ_M3_NUM_MAX,
		.port_offset = PORTQ_M3_PORT_OFFSET,
		.priority = portq_m3_priority,
		.ipc_ws = &amipc_wakeup,
		.ops = &m3_op
};

static struct shm_callback portq_m3_shm_cb = {
	.get_packet_length = shm_get_packet_length,
};

static struct shm_rbctl portq_m3_rbctl = {
	.name = "m3-portq",
	.cbs = &portq_m3_shm_cb,
	.priv = &pgrp_m3,
	.va_lock = __MUTEX_INITIALIZER(portq_m3_rbctl.va_lock),
};

static void m3_peer_sync_cb(void)
{
	amipc_notify_peer_sync();
	m3_is_synced = true;
	pr_info("msocket connection sync with M3 O.K.!\n");
	complete_all(&m3_peer_sync);
}

/* new packet arrival interrupt */
static u32 amipc_cb(u32 status)
{
	u32 data = 0;
	u16 event;

	amipc_dataread(AMIPC_SHM_PACKET_NOTIFY, &data, NULL);
	event = data;

	switch (event) {
	case PACKET_SENT: /* remote sent a packet */
		portq_packet_recv_cb(&pgrp_m3);
		break;

	case PEER_SYNC: /* remote sync complete */
		m3_peer_sync_cb();
		break;

	default:
		break;
	}

	return 0;
}

/* flow control interrupt */
static u32 amipc_cb_fc(u32 status)
{
	u32 data = 0;
	u16 event;

	amipc_dataread(AMIPC_RINGBUF_FC, &data, NULL);
	event = data;

	switch (event) {
	case TX_STOP:
		portq_rb_stop_cb(&pgrp_m3);
		break;

	case TX_RESUME:
		portq_rb_resume_cb(&pgrp_m3);
		break;

	default:
		break;
	}

	return 0;
}

static int m3_grp_init(void)
{
	pgrp_m3.rbctl = &portq_m3_rbctl;
	return 0;
}

static int m3_grp_exit(void)
{
	m3_shm_ch_deinit();
	return 0;
}

static int m3_grp_open(void)
{
	amipc_eventbind(AMIPC_SHM_PACKET_NOTIFY, amipc_cb);
	amipc_eventbind(AMIPC_RINGBUF_FC, amipc_cb_fc);
	wakeup_source_init(&amipc_wakeup, "amipc_wakeup");
	return 0;
}

static int m3_grp_close(void)
{
	amipc_eventunbind(AMIPC_RINGBUF_FC);
	amipc_eventunbind(AMIPC_SHM_PACKET_NOTIFY);
	wakeup_source_trash(&amipc_wakeup);
	return 0;
}

static void m3_grp_connect(void)
{
	return;
}

static void m3_grp_disconnect(void)
{
	m3_is_synced = false;
}

static void m3_grp_notify_fc(void)
{
	return;
}

static bool m3_synced(void)
{
	return m3_is_synced;
}


static int m3_shm_param_init(const struct rm_m3_addr *addr)
{
	if (!addr)
		return -1;

	portq_m3_rbctl.skctl_pa = addr->m3_rb_ctrl_start_addr;

	pr_info("M3 RB PA: 0x%08lx\n", portq_m3_rbctl.skctl_pa);

	portq_m3_rbctl.tx_skbuf_size = M3_SHM_SKBUF_SIZE;
	portq_m3_rbctl.rx_skbuf_size = M3_SHM_SKBUF_SIZE;

	pr_info("M3 RB PACKET TX SIZE: %d, RX SIZE: %d\n",
		portq_m3_rbctl.tx_skbuf_size,
		portq_m3_rbctl.rx_skbuf_size);

	portq_m3_rbctl.tx_pa = addr->m3_ddr_mb_start_addr;
	portq_m3_rbctl.tx_skbuf_num = M3_SHM_AP_TX_MAX_NUM;
	portq_m3_rbctl.tx_total_size =
		portq_m3_rbctl.tx_skbuf_num *
		portq_m3_rbctl.tx_skbuf_size;


	portq_m3_rbctl.rx_pa = portq_m3_rbctl.tx_pa +
		portq_m3_rbctl.tx_total_size;
	portq_m3_rbctl.rx_skbuf_num = M3_SHM_AP_RX_MAX_NUM;
	portq_m3_rbctl.rx_total_size =
		portq_m3_rbctl.rx_skbuf_num *
		portq_m3_rbctl.rx_skbuf_size;

	portq_m3_rbctl.tx_skbuf_low_wm =
		(portq_m3_rbctl.tx_skbuf_num + 1) / 4;
	portq_m3_rbctl.rx_skbuf_low_wm =
		(portq_m3_rbctl.rx_skbuf_num + 1) / 4;

	return 0;
}


int m3_shm_ch_init(const struct rm_m3_addr *addr)
{
	int rc;

	if (pgrp_m3.is_open) {
		pr_info("%s: channel is already inited\n", __func__);
		return 0;
	}

	/* share memory area init */
	m3_shm_param_init(addr);
	rc = shm_rb_init(&portq_m3_rbctl, msocket_debugfs_root_dir);
	if (rc < 0) {
		pr_err("%s: shm init failed %d\n", __func__, rc);
		return rc;
	}

	/* port queue group init */
	rc = portq_grp_open(portq_grp_m3);
	if (rc < 0) {
		pr_err("%s: portq group init failed %d\n", __func__, rc);
		goto portq_err;
	}

	pr_info("%s: shm channel init success\n", __func__);
	return 0;

portq_err:
	shm_rb_exit(&portq_m3_rbctl);

	return rc;
}
EXPORT_SYMBOL(m3_shm_ch_init);

void m3_shm_ch_deinit(void)
{
	if (!pgrp_m3.is_open)
		return;

	/* reverse order of initialization */
	portq_grp_disconnect(portq_grp_m3);
	portq_grp_close(portq_grp_m3);
	shm_rb_exit(&portq_m3_rbctl);
}
EXPORT_SYMBOL(m3_shm_ch_deinit);

int m3_ioctl_handler(unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case MSOCKET_IOC_M3_ERRTO: /* m3 timeout */
		pr_info("MSOCK: MSOCKET_IOC_ERRTO is received!\n");
		amipc_dump_debug_info();
		portq_grp_disconnect(portq_grp_m3);
		portq_broadcast_msg(portq_grp_m3, MsocketLinkdownProcId);
		return 0;

	case MSOCKET_IOC_M3_RECOVERY: /* m3 recovery */
		reinit_completion(&m3_peer_sync);
		portq_grp_connect(portq_grp_m3);
		pr_info("MSOCK: MSOCKET_IOC_RECOVERY is received!\n");
		if (wait_for_completion_timeout(&m3_peer_sync, 5 * HZ) == 0) {
			pr_info("MSOCK: sync with M3 FAIL\n");
			return -1;
		}
		portq_broadcast_msg(portq_grp_m3, MsocketLinkupProcId);
		return 0;
	default:
		return -ENOIOCTLCMD;
	}
}

#ifndef CONFIG_PXA9XX_AMIPC
enum amipc_return_code amipc_setbase(phys_addr_t base_addr, int len)
{
	return AMIPC_RC_OK;
}

enum amipc_return_code amipc_eventbind(u32 user_event,
					     amipc_rec_event_callback cb)
{
	return AMIPC_RC_OK;
}

enum amipc_return_code amipc_eventunbind(u32 user_event)
{
	return AMIPC_RC_OK;
}

enum amipc_return_code amipc_eventset(enum amipc_events user_event,
						int timeout_ms)
{
	return AMIPC_RC_OK;
}

enum amipc_return_code amipc_datasend(enum amipc_events user_event,
				u32 data1, u32 data2, int timeout_ms)
{
	return AMIPC_RC_OK;
}

enum amipc_return_code amipc_dataread(enum amipc_events user_event,
					u32 *data1, u32 *data2)
{
	return AMIPC_RC_OK;
}

enum amipc_return_code amipc_dump_debug_info(void)
{
	return AMIPC_RC_OK;
}
#endif
