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
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif
#include <linux/debugfs.h>
#ifdef CONFIG_DDR_DEVFREQ
#include <linux/devfreq.h>
#endif
#include <linux/pm_qos.h>
#include <linux/pxa9xx_acipc.h>
#include <linux/clk/mmpcpdvc.h>

#include "portqueue.h"
#include "msocket.h"
#include "shm.h"
#include "shm_share.h"
#include "common_regs.h"
#include "shm_map.h"
#include "pxa_cp_load.h"
#include "pxa_cp_load_ioctl.h"
#include "debugfs.h"
#include "lib.h"

/* port queue priority definition */
static const int portq_cp_priority[PORTQ_CP_NUM_MAX] = {
	0,			/* 0: NOT USED */
	10,			/* 1: CISTUB_PORT */
	10,			/* 2: NVMSRV_PORT */
	50,			/* 3: CIDATASTUB_PORT */
	0,			/* 4: NOT USED */
	30,			/* 5: AUDIOSTUB_PORT */
	40,			/* 6: CICSDSTUB_PORT */
#ifdef CONFIG_SSIPC_SUPPORT
	70,			/* 7: RAW_AT_PORT */
#else
	0,			/* 7: NOT USED */
#endif
	70,			/* 8: TEST_PORT */
	40,			/* 9: CIIMSSTUB_PORT */
#ifdef CONFIG_SSIPC_SUPPORT
	70,			/*10: RAW_AT_DUN_PORT */
	70,			/*11: RAW_AT_PROD_PORT */
	70,			/*12: RAW_AT_SIMAL_PORT */
	70,			/*13: RAW_AT_CLIENT_SOL_PORT */
	70,			/*14: RAW_AT_CLIENT_UNSOL_PORT */
	70,			/*15: RAW_AT_RESERVERED_PORT */
	70,			/*16: RAW_AT_GPS_PORT */
	70,			/*17: RAW_AT_RESERVERED2_PORT */
	70,			/*20: TEST_PORT2 */
	70,			/*21: RAW_AT_DUN_PORT2 */
	70,			/*22: RAW_AT_PROD_PORT2 */
	70,			/*23: RAW_AT_SIMAL_PORT2 */
	70,			/*24: RAW_AT_CLIENT_SOL_PORT2 */
	70,			/*25: RAW_AT_CLIENT_UNSOL_PORT2 */
	70,			/*26: RAW_AT_RESERVERED_PORT2 */
	70,			/*27: RAW_AT_RESERVERED2_PORT2 */
	70,			/*28: RAW_AT_GPS_PORT2 */
#endif
};

/*----------------- cp group --------------------*/
static int cp_grp_init(void);
static int cp_grp_exit(void);
static int cp_grp_open(void);
static int cp_grp_close(void);
static void cp_grp_connect(void);
static void cp_grp_disconnect(void);
static bool cp_synced(void);
static void cp_sync_worker(struct work_struct *work);
static void cp_deinit(void);
static int cp_mem_set_notifier_func(struct notifier_block *this,
	unsigned long code, void *cmd);

/*------------- acipc --------------------*/
static void acipc_notify_port_fc(void);
static void acipc_notify_packet_sent(void);
static void acipc_notify_cp_tx_resume(void);
static void acipc_notify_ap_tx_stopped(void);

struct wakeup_source acipc_wakeup; /* used to ensure Workqueue scheduled. */

#define RESET_CP_REQUEST 0x544F4F42
#define RESET_CP_REQUEST_DONE 0x454E4F44

#define REQ_AP_D2_STATUS  0x544F4F41  /* can enter D2 status */
#define REQ_AP_ND2_STATUS 0x533F3F31  /*  can't enter D2 status */
static DECLARE_COMPLETION(reset_cp_confirm);

static u32 pm_qos_cpuidle_block_axi	= PM_QOS_CPUIDLE_BLOCK_DEFAULT_VALUE;
static struct pm_qos_request cp_block_cpuidle_axi = {
	.name = "cp_block_cpuidle_axi",
};

#ifdef CONFIG_DDR_DEVFREQ
static struct pm_qos_request modem_ddr_cons = {
	.name = "cp",
};
static struct workqueue_struct *acipc_wq;
static struct work_struct acipc_modem_ddr_freq_update;

#define MODEM_DDRFREQ_HI	400
#define MODEM_DDRFREQ_MID	312
#define MODEM_DDRFREQ_LOW	156
#define MHZ_TO_KHZ		1000
#endif

/*------------- cp param --------------------*/
enum ddr_dfc_level {
	idle,
	active,
	high,
};

struct cpmsa_dvc_info_v1 {
/* D: 0x44, V: 0x56, C: 0x43, the last byte represent the version: 01 */
#define DVC_MAGIC_V1 0x44564301
	volatile unsigned int dvc_magic;
#define MAX_CPDVC_NUM_V1 5
	volatile unsigned int cp_freq[MAX_CPDVC_NUM_V1];
	volatile unsigned int cp_vol[MAX_CPDVC_NUM_V1];

	volatile unsigned int cpaxi_freq[MAX_CPDVC_NUM_V1];
	volatile unsigned int cpaxi_vol[MAX_CPDVC_NUM_V1];

	volatile unsigned int lteaxi_freq[MAX_CPDVC_NUM_V1];
	volatile unsigned int lteaxi_vol[MAX_CPDVC_NUM_V1];

	volatile unsigned int msa_freq[MAX_CPDVC_NUM_V1];
	volatile unsigned int msa_vol[MAX_CPDVC_NUM_V1];
};

struct cp_keysection {
#define PMIC_MASTER_FLAG	0x4D415354
	/* PMIC SSP master status setting query */
	volatile unsigned int ap_pcm_master;
	volatile unsigned int cp_pcm_master;
	volatile unsigned int modem_ddrfreq;

	/* DIAG specific info */
	volatile unsigned int diag_header_ptr;
	volatile unsigned int diag_cp_db_ver;
	volatile unsigned int diag_ap_db_ver;

	volatile unsigned int reset_request;
	volatile unsigned int ap_pm_status_request;
	volatile unsigned int profile_number;

	/* dvc voltage table number */
	volatile unsigned int dvc_vol_tbl_num;
	volatile unsigned int dvc_vol_tbl[16];

#define VERSION_MAGIC_FLAG 0x56455253
#define VERSION_NUMBER_FLAG 0x1
	volatile unsigned int version_magic;
	volatile unsigned int version_number;

	volatile unsigned int dfc_dclk_num;
	volatile unsigned int dfc_dclk[16];

	/*L+G or G+L*/
	volatile unsigned int network_mode;

	/* uuid reserved for SSIPC solution */
	volatile unsigned int uuid_high;
	volatile unsigned int uuid_low;

#define MAX_CPDVC_NUM 4
	/* dvc voltage and frequency */
	volatile unsigned int cp_freq[MAX_CPDVC_NUM];
	volatile unsigned int cp_vol[MAX_CPDVC_NUM];
	volatile unsigned int msa_dvc_vol;

#define DFC_MAGIC_FLAG 0x4446434C
	volatile unsigned int dfc_magic;
#define MAX_DFCLVL_NUM 5
	/* dfc level */
	/* 0 - idle, 1 - active, 2 - high, 3, 4 reserve */
	volatile unsigned int dfc_lvl[MAX_DFCLVL_NUM];

	/* new cp msa dvc information */
	struct cpmsa_dvc_info_v1 dvc_info;
};

static struct cp_keysection *cpks;
static DEFINE_MUTEX(cpks_lock);
static struct dentry *cpks_rootdir;
static bool cp_recv_up_ioc;
static bool cp_is_sync_canceled;
static DECLARE_COMPLETION(cp_peer_sync);
static DECLARE_WORK(sync_work, cp_sync_worker);
static DEFINE_SPINLOCK(cp_sync_lock);

DEFINE_BLOCKING_NOTIFIER(cp_link_status);
bool cp_is_synced;
EXPORT_SYMBOL(cp_is_synced);

static struct portq_op cp_op = {
		.init = cp_grp_init,
		.exit = cp_grp_exit,
		.open = cp_grp_open,
		.close = cp_grp_close,
		.connect = cp_grp_connect,
		.disconnect = cp_grp_disconnect,
		.notify_sent = acipc_notify_packet_sent,
		.notify_fc_change = acipc_notify_port_fc,
		.tx_resume = acipc_notify_cp_tx_resume,
		.tx_stop = acipc_notify_ap_tx_stopped,
		.is_synced = cp_synced
};

struct portq_group pgrp_cp = {
		.name = "cp_main",
		.grp_type = portq_grp_cp_main,
		.port_cnt = PORTQ_CP_NUM_MAX,
		.port_offset = 0,
		.priority = portq_cp_priority,
		.ipc_ws = &acipc_wakeup,
		.ops = &cp_op
};

static struct shm_callback portq_cp_shm_cb = {
	.get_packet_length = shm_get_packet_length,
};

static struct shm_rbctl portq_cp_rbctl = {
	.name = "cp-portq",
	.cbs = &portq_cp_shm_cb,
	.priv = &pgrp_cp,
	.va_lock = __MUTEX_INITIALIZER(portq_cp_rbctl.va_lock),
};

/*------------- acipc --------------------*/
#ifdef CONFIG_DDR_DEVFREQ
static void acipc_modem_ddr_freq_update_handler(struct work_struct *work)
{
	static int cur_ddrfreq;

	pr_info("acipc_cb_modem_ddrfreq_update: %d\n",
	       (unsigned int)cpks->modem_ddrfreq);
	if ((unsigned int)cpks->modem_ddrfreq == MODEM_DDRFREQ_HI) {
		if (cur_ddrfreq == MODEM_DDRFREQ_HI)
			return;
		pr_info("DDRFreq set to High\n");
		pm_qos_update_request(&modem_ddr_cons, MODEM_DDRFREQ_HI * MHZ_TO_KHZ);
		cur_ddrfreq = MODEM_DDRFREQ_HI;
	}

	if ((unsigned int)cpks->modem_ddrfreq == MODEM_DDRFREQ_MID) {
		if (cur_ddrfreq == MODEM_DDRFREQ_MID)
			return;
		pr_info("DDRFreq set to Mid\n");
		pm_qos_update_request(&modem_ddr_cons, MODEM_DDRFREQ_MID * MHZ_TO_KHZ);
		cur_ddrfreq = MODEM_DDRFREQ_MID;
	}

	if ((unsigned int)cpks->modem_ddrfreq == MODEM_DDRFREQ_LOW) {
		if (cur_ddrfreq == MODEM_DDRFREQ_LOW)
			return;
		pr_info("DDRFreq set to Low\n");
		pm_qos_update_request(&modem_ddr_cons, PM_QOS_DEFAULT_VALUE);
		cur_ddrfreq = MODEM_DDRFREQ_LOW;
	}
	return;
}
#endif

static u32 acipc_cb_block_cpuidle_axi(u32 status)
{
	bool block = false;
	u32 pm_status = 0;

	pm_status = cpks->ap_pm_status_request;
	if (pm_status == REQ_AP_D2_STATUS) {
		block = false;
	} else if (pm_status == REQ_AP_ND2_STATUS) {
		block = true;
	} else {
		pr_info("acipc: unknow status %d!!!\n", pm_status);
		return 0;
	}

	acipc_ap_block_cpuidle_axi(block);
	return 0;
}

#ifdef CONFIG_DDR_DEVFREQ
static u32 acipc_cb_modem_ddrfreq_update(u32 status)
{
	queue_work(acipc_wq, &acipc_modem_ddr_freq_update);
	return 0;
}
#endif

static u32 acipc_cb_reset_cp_confirm(u32 status)
{
	if (cpks->reset_request == RESET_CP_REQUEST_DONE)
		complete(&reset_cp_confirm);

	cpks->reset_request = 0;
	return 0;
}

static u32 acipc_cb_event_notify(u32 status)
{
	acipc_cb_reset_cp_confirm(status);
#ifdef CONFIG_DDR_DEVFREQ
	acipc_cb_modem_ddrfreq_update(status);
#endif
	return 0;
}

/*notify cp that ap will reset cp to let cp exit WFI state */
static inline void acipc_notify_reset_cp_request(void)
{
	pr_warn("MSOCK: acipc_notify_reset_cp_request!!!\n");
	acipc_event_set(ACIPC_MODEM_DDR_UPDATE_REQ);
}

static void acipc_reset_cp_request(void)
{
	mutex_lock(&cpks_lock);
	if (!cpks) {
		mutex_unlock(&cpks_lock);
		return;
	}
	cpks->reset_request = RESET_CP_REQUEST;
	reinit_completion(&reset_cp_confirm);
	acipc_notify_reset_cp_request();
	mutex_unlock(&cpks_lock);
	if (wait_for_completion_timeout(&reset_cp_confirm, 2 * HZ))
		pr_info("reset cp request success!\n");
	else
		pr_err("reset cp request fail!\n");

	mutex_lock(&cpks_lock);
	if (!cpks) {
		mutex_unlock(&cpks_lock);
		return;
	}
	cpks->reset_request = 0;
	mutex_unlock(&cpks_lock);
	return;
}

void acipc_ap_block_cpuidle_axi(bool block)
{
	pm_qos_update_request(&cp_block_cpuidle_axi,
		(block ? pm_qos_cpuidle_block_axi
			   : PM_QOS_CPUIDLE_BLOCK_DEFAULT_VALUE));
}
EXPORT_SYMBOL(acipc_ap_block_cpuidle_axi);

/* notify cp that flow control state has been changed */
static void acipc_notify_port_fc(void)
{
	acipc_event_set(ACIPC_PORT_FLOWCONTROL);
}

/* notify cp that new packet available in the socket buffer */
static void acipc_notify_packet_sent(void)
{
	acipc_data_send(ACIPC_MUDP_KEY, PACKET_SENT << 8);
}

/* notify cp that cp can continue transmission */
static void acipc_notify_cp_tx_resume(void)
{
	pr_warn("MSOCK: acipc_notify_cp_tx_resume!!!\n");
	acipc_event_set(ACIPC_RINGBUF_TX_RESUME);
}

/*notify cp that ap transmission is stopped, please resume me later */
static void acipc_notify_ap_tx_stopped(void)
{
	pr_warn("MSOCK: acipc_notify_ap_tx_stopped!!!\n");
	acipc_event_set(ACIPC_RINGBUF_TX_STOP);
}

/* generate peer sync interrupt */
static inline void acipc_notify_peer_sync(void)
{
	acipc_data_send(ACIPC_MUDP_KEY, PEER_SYNC << 8);
}

/* cp xmit stopped notify interrupt */
static u32 acipc_cb_rb_stop(u32 status)
{
	portq_rb_stop_cb(&pgrp_cp);
	return 0;
}

/* cp wakeup ap xmit interrupt */
static u32 acipc_cb_rb_resume(u32 status)
{
	portq_rb_resume_cb(&pgrp_cp);
	return 0;
}

/* cp notify ap port flow control */
static u32 acipc_cb_port_fc(u32 status)
{
	portq_port_fc_cb(&pgrp_cp);
	return 0;
}

static void cp_peer_sync_cb(void)
{
	complete_all(&cp_peer_sync);
}

/* new packet arrival interrupt */
static u32 acipc_cb(u32 status)
{
	u32 data;
	u16 event;

	acipc_data_read(&data);
	event = (data & 0xFF00) >> 8;

	switch (event) {
	case PACKET_SENT: /* remote sent a packet */
		portq_packet_recv_cb(&pgrp_cp);
		break;

	case PEER_SYNC: /* remote sync complete */
		cp_peer_sync_cb();
		break;

	default:
		break;
	}

	return 0;
}

/* acipc_init is used to register interrupt call-back function */
static int acipc_init(u32 lpm_qos)
{
	wakeup_source_init(&acipc_wakeup, "acipc_wakeup");

	/* we do not check any return value */
	acipc_event_bind(ACIPC_MODEM_DDR_UPDATE_REQ, acipc_cb_event_notify,
		       ACIPC_CB_NORMAL, NULL);

	acipc_event_bind(ACIPC_IPM, acipc_cb_block_cpuidle_axi,
		       ACIPC_CB_NORMAL, NULL);

	pm_qos_cpuidle_block_axi = lpm_qos;
	pm_qos_add_request(&cp_block_cpuidle_axi, PM_QOS_CPUIDLE_BLOCK,
		PM_QOS_CPUIDLE_BLOCK_DEFAULT_VALUE);

#ifdef CONFIG_DDR_DEVFREQ
	pm_qos_add_request(&modem_ddr_cons, PM_QOS_DDR_DEVFREQ_MIN,
		PM_QOS_DEFAULT_VALUE);
	INIT_WORK(&acipc_modem_ddr_freq_update,
		acipc_modem_ddr_freq_update_handler);
	acipc_wq = alloc_workqueue("ACIPC_WQ", WQ_HIGHPRI, 0);
#endif

	return 0;
}

/* acipc_exit used to unregister interrupt call-back function */
static void acipc_exit(void)
{
	acipc_event_unbind(ACIPC_MODEM_DDR_UPDATE_REQ);
	acipc_event_unbind(ACIPC_IPM);

	pm_qos_remove_request(&cp_block_cpuidle_axi);

	wakeup_source_trash(&acipc_wakeup);

#ifdef CONFIG_DDR_DEVFREQ
	destroy_workqueue(acipc_wq);
	pm_qos_remove_request(&modem_ddr_cons);
#endif
}

/* acipc_init is used to register interrupt call-back function */
static int portq_acipc_init(void)
{
	/* we do not check any return value */
	acipc_event_bind(ACIPC_MUDP_KEY, acipc_cb, ACIPC_CB_NORMAL, NULL);
	acipc_event_bind(ACIPC_RINGBUF_TX_STOP, acipc_cb_rb_stop,
		       ACIPC_CB_NORMAL, NULL);
	acipc_event_bind(ACIPC_RINGBUF_TX_RESUME, acipc_cb_rb_resume,
		       ACIPC_CB_NORMAL, NULL);
	acipc_event_bind(ACIPC_PORT_FLOWCONTROL, acipc_cb_port_fc,
		       ACIPC_CB_NORMAL, NULL);

	return 0;
}

/* acipc_exit used to unregister interrupt call-back function */
static void portq_acipc_exit(void)
{
	acipc_event_unbind(ACIPC_PORT_FLOWCONTROL);
	acipc_event_unbind(ACIPC_RINGBUF_TX_RESUME);
	acipc_event_unbind(ACIPC_RINGBUF_TX_STOP);
	acipc_event_unbind(ACIPC_MUDP_KEY);
}



static int cp_link_status_notifier_func(struct notifier_block *this,
	unsigned long code, void *cmd)
{
	portq_broadcast_msg(portq_grp_cp_main, (int)code);
	return 0;
}

static struct notifier_block cp_link_status_notifier = {
	.notifier_call = cp_link_status_notifier_func,
};

static struct notifier_block cp_mem_set_notifier = {
	.notifier_call = cp_mem_set_notifier_func,
};

static int reboot_notifier_func(struct notifier_block *this,
	unsigned long code, void *cmd)
{
	pr_info("reboot notifier, notify CP\n");
	pr_info("%s: APMU_DEBUG byte3 %02x\n", __func__,
	       __raw_readb(APMU_DEBUG + 3));
	if (cp_is_synced)
		acipc_reset_cp_request();
	return 0;
}

static struct notifier_block reboot_notifier = {
	.notifier_call = reboot_notifier_func,
};

static BLOCKING_NOTIFIER_HEAD(cp_sync_notifier_list);

int register_first_cp_synced(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&cp_sync_notifier_list, nb);
}
EXPORT_SYMBOL(register_first_cp_synced);

static void notify_first_cp_synced(void)
{
	blocking_notifier_call_chain(&cp_sync_notifier_list, 1, NULL);
}

/*------------- cp group --------------------*/
#define APMU_DEBUG_BUS_PROTECTION (1 << 4)
static int cp_grp_init(void)
{
	u8 apmu_debug_byte3;

	pgrp_cp.rbctl = &portq_cp_rbctl;
	/* map common register base address */
	if (!map_apmu_base_va()) {
		pr_err("error to ioremap APMU_BASE_ADDR\n");
		return -ENOENT;
	}
	/*enable bus protection*/
	apmu_debug_byte3 = __raw_readb(APMU_DEBUG + 3);
	apmu_debug_byte3 |= APMU_DEBUG_BUS_PROTECTION;
	__raw_writeb(apmu_debug_byte3, APMU_DEBUG + 3);
	register_cp_mem_set_notifier(&cp_mem_set_notifier);
	return 0;
}

static int cp_grp_exit(void)
{
	unregister_cp_mem_set_notifier(&cp_mem_set_notifier);
	cp_deinit();
	return 0;
}

static int cp_grp_open(void)
{
	register_reboot_notifier(&reboot_notifier);
	register_cp_link_status_notifier(&cp_link_status_notifier);
	portq_acipc_init();
	return 0;
}

static int cp_grp_close(void)
{
	unregister_reboot_notifier(&reboot_notifier);
	unregister_cp_link_status_notifier(&cp_link_status_notifier);
	portq_acipc_exit();
	return 0;
}

static void cp_grp_connect(void)
{
	spin_lock(&cp_sync_lock);
	cp_is_sync_canceled = false;
	spin_unlock(&cp_sync_lock);

	queue_work(pgrp_cp.wq, &sync_work);
}

static void cp_grp_disconnect(void)
{
	spin_lock(&cp_sync_lock);
	/* flag used to cancel any new packet activity */
	cp_is_synced = false;
	/* flag used to cancel potential peer sync worker */
	cp_is_sync_canceled = true;
	spin_unlock(&cp_sync_lock);
}

static bool cp_synced(void)
{
	return cp_is_synced;
}

static void cp_sync_worker(struct work_struct *work)
{
	bool cb_notify = false, link_notify = false;

	/* acquire lock first */
	spin_lock(&cp_sync_lock);

	while (!cp_is_sync_canceled) {
		/* send peer sync notify */
		acipc_notify_peer_sync();

		/* unlock before wait completion */
		spin_unlock(&cp_sync_lock);

		if (wait_for_completion_timeout(&cp_peer_sync, HZ)) {
			/* we get CP sync response here */
			pr_info("msocket connection sync with CP O.K.!\n");
			/* acquire lock again */
			spin_lock(&cp_sync_lock);

			if (!cp_is_sync_canceled) {
				/* if no one cancel me */
				cp_is_synced = true;
				/* only when we have received linkup ioctl
				 * can we report the linkup message */
				if (cp_recv_up_ioc) {
					cp_recv_up_ioc = false;
					link_notify = true;
				} else
					cb_notify  = true;
			}
			break;
		}
		/* acquire lock again */
		spin_lock(&cp_sync_lock);
	}

	/* unlock before return */
	spin_unlock(&cp_sync_lock);

	if (cb_notify)
		notify_first_cp_synced();
	else if (link_notify)
		notify_cp_link_status(MsocketLinkupProcId, NULL);
}

/*------------- cp init --------------------*/
#define SHM_SKBUF_SIZE		2048	/* maximum packet size */
static int cp_shm_param_init(const struct cpload_cp_addr *addr)
{
	if (!addr)
		return -1;

	/* main ring buffer */
	portq_cp_rbctl.skctl_pa = addr->main_skctl_pa;

	portq_cp_rbctl.tx_skbuf_size = SHM_SKBUF_SIZE;
	portq_cp_rbctl.rx_skbuf_size = SHM_SKBUF_SIZE;

	portq_cp_rbctl.tx_pa = addr->main_tx_pa;
	portq_cp_rbctl.rx_pa = addr->main_rx_pa;

	portq_cp_rbctl.tx_total_size = addr->main_tx_total_size;
	portq_cp_rbctl.rx_total_size = addr->main_rx_total_size;

	portq_cp_rbctl.tx_skbuf_num =
		portq_cp_rbctl.tx_total_size /
		portq_cp_rbctl.tx_skbuf_size;
	portq_cp_rbctl.rx_skbuf_num =
		portq_cp_rbctl.rx_total_size /
		portq_cp_rbctl.rx_skbuf_size;

	portq_cp_rbctl.tx_skbuf_low_wm =
		(portq_cp_rbctl.tx_skbuf_num + 1) / 4;
	portq_cp_rbctl.rx_skbuf_low_wm =
		(portq_cp_rbctl.rx_skbuf_num + 1) / 4;

	return 0;
}

static int cpks_debugfs_init(struct dentry *parent)
{
	cpks_rootdir = debugfs_create_dir("cpks", parent);
	if (IS_ERR_OR_NULL(cpks_rootdir))
		return -ENOMEM;

	if (IS_ERR_OR_NULL(debugfs_create_uint(
				"ap_pcm_master", S_IRUGO | S_IWUSR,
				cpks_rootdir,
				(unsigned int *)
				&cpks->ap_pcm_master)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_uint(
				"cp_pcm_master", S_IRUGO | S_IWUSR,
				cpks_rootdir,
				(unsigned int *)
				&cpks->cp_pcm_master)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_uint(
				"modem_ddrfreq", S_IRUGO | S_IWUSR,
				cpks_rootdir,
				(unsigned int *)
				&cpks->modem_ddrfreq)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_uint(
				"reset_request", S_IRUGO | S_IWUSR,
				cpks_rootdir,
				(unsigned int *)
				&cpks->reset_request)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_uint(
				"diag_header_ptr", S_IRUGO | S_IWUSR,
				cpks_rootdir,
				(unsigned int *)
				&cpks->diag_header_ptr)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_uint(
				"diag_cp_db_ver", S_IRUGO | S_IWUSR,
				cpks_rootdir,
				(unsigned int *)
				&cpks->diag_cp_db_ver)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_uint(
				"diag_ap_db_ver", S_IRUGO | S_IWUSR,
				cpks_rootdir,
				(unsigned int *)
				&cpks->diag_ap_db_ver)))
		goto error;

	return 0;

error:
	debugfs_remove_recursive(cpks_rootdir);
	cpks_rootdir = NULL;
	return -1;
}

static int cpks_debugfs_exit(void)
{
	debugfs_remove_recursive(cpks_rootdir);
	cpks_rootdir = NULL;
	return 0;
}

static void get_dvc_info(void)
{
	struct cpmsa_dvc_info dvc_vol_info;
	int i = 0;
	int sz_tel, sz_ap, sz;

	getcpdvcinfo(&dvc_vol_info);
	for (i = 0; i < MAX_CPDVC_NUM; i++) {
		cpks->cp_freq[i] = dvc_vol_info.cpdvcinfo[i].cpfreq;
		cpks->cp_vol[i] = dvc_vol_info.cpdvcinfo[i].cpvl;
	}
	cpks->msa_dvc_vol = dvc_vol_info.msadvcvl[0].cpvl;

	cpks->dvc_info.dvc_magic = DVC_MAGIC_V1;
	sz_tel = sizeof(cpks->dvc_info.cp_freq)/sizeof(cpks->dvc_info.cp_freq[0]);
	sz_ap = sizeof(dvc_vol_info.cpdvcinfo)/sizeof(dvc_vol_info.cpdvcinfo[0]);
	sz = sz_tel < sz_ap ? sz_tel : sz_ap;
	/* get new cp msa dvc info */
	for (i = 0; i < sz; i++) {
		cpks->dvc_info.cp_freq[i] = dvc_vol_info.cpdvcinfo[i].cpfreq;
		cpks->dvc_info.cp_vol[i] = dvc_vol_info.cpdvcinfo[i].cpvl;

		cpks->dvc_info.cpaxi_freq[i] = dvc_vol_info.cpaxidvcinfo[i].cpfreq;
		cpks->dvc_info.cpaxi_vol[i] = dvc_vol_info.cpaxidvcinfo[i].cpvl;

		cpks->dvc_info.lteaxi_freq[i] = dvc_vol_info.lteaxidvcinfo[i].cpfreq;
		cpks->dvc_info.lteaxi_vol[i] = dvc_vol_info.lteaxidvcinfo[i].cpvl;

		cpks->dvc_info.msa_freq[i] = dvc_vol_info.msadvcvl[i].cpfreq;
		cpks->dvc_info.msa_vol[i] = dvc_vol_info.msadvcvl[i].cpvl;
	}
}

static void get_dfc_info(void)
{
	struct ddr_dfc_info dfc_info;

	getddrdfcinfo(&dfc_info);
	cpks->dfc_magic = DFC_MAGIC_FLAG;
	cpks->dfc_lvl[idle] = dfc_info.ddr_idle;
	cpks->dfc_lvl[active] = dfc_info.ddr_active;
	cpks->dfc_lvl[high] = dfc_info.ddr_high;
}

static void cp_keysection_data_init(void)
{
	unsigned int network_mode;

	mutex_lock(&cpks_lock);
	if (cpks) {
		network_mode = cpks->network_mode;
		memset_aligned(cpks, 0, sizeof(*cpks));
		cpks->network_mode = network_mode;
		cpks->ap_pcm_master = PMIC_MASTER_FLAG;
	}
	mutex_unlock(&cpks_lock);
	cpks->version_magic = VERSION_MAGIC_FLAG;
	cpks->version_number = VERSION_NUMBER_FLAG;

	get_dvc_info();
	get_dfc_info();
}

static int cp_keysection_init(const struct cpload_cp_addr *addr)
{
	mutex_lock(&cpks_lock);
	cpks = shm_map(addr->main_skctl_pa +
		sizeof(struct shm_skctl),
		sizeof(struct cp_keysection));
	mutex_unlock(&cpks_lock);
	if (!cpks)
		return -1;

	if (cpks_debugfs_init(msocket_debugfs_root_dir) < 0)
		goto exit;

	return 0;

exit:
	mutex_lock(&cpks_lock);
	if (cpks)
		shm_unmap(addr->main_skctl_pa + sizeof(struct shm_skctl), cpks);
	cpks = NULL;
	mutex_unlock(&cpks_lock);
	return -1;
}

static void cp_keysection_exit(void)
{
	cpks_debugfs_exit();
	mutex_lock(&cpks_lock);
	if (cpks)
		shm_unmap(portq_cp_rbctl.skctl_pa + sizeof(struct shm_skctl), cpks);
	cpks = NULL;
	mutex_unlock(&cpks_lock);
}

static int cp_shm_init(const struct cpload_cp_addr *addr)
{
	int ret;

	ret = cp_shm_param_init(addr);
	if (ret < 0) {
		pr_err("%s: init cp portq shm param failed\n", __func__);
		return -1;
	}

	if (cp_keysection_init(addr) < 0) {
		pr_err("%s: init cp key section failed\n", __func__);
		return -1;
	}

	if (shm_rb_init(&portq_cp_rbctl,
			msocket_debugfs_root_dir) < 0) {
		pr_err("%s: init cp portq ring buffer failed\n", __func__);
		goto rb_exit;
	}

	cp_keysection_data_init();

	return 0;

rb_exit:
	cp_keysection_exit();

	return -1;
}

static void cp_shm_exit(void)
{
	shm_rb_exit(&portq_cp_rbctl);
	cp_keysection_exit();
}

static int cp_init(const struct cpload_cp_addr *addr, u32 lpm_qos)
{
	int rc;

	if (pgrp_cp.is_open) {
		pr_info("%s: channel is already inited\n", __func__);
		return 0;
	}

	/* share memory area init */
	rc = cp_shm_init(addr);
	if (rc < 0) {
		pr_err("%s: shm init failed %d\n", __func__, rc);
		return rc;
	}

	/* acipc init */
	rc = acipc_init(lpm_qos);
	if (rc < 0) {
		pr_err("%s: acipcd init failed %d\n", __func__, rc);
		goto acipc_err;
	}

	rc = portq_grp_open(portq_grp_cp_main);
	if (rc < 0) {
		pr_err("%s: portq group init failed %d\n", __func__, rc);
		goto portq_err;
	}

	/* start peer sync */
	portq_grp_connect(portq_grp_cp_main);
	pr_info("%s: shm channel init success\n", __func__);
	return 0;

portq_err:
	acipc_exit();
acipc_err:
	cp_shm_exit();

	return rc;
}

static void cp_deinit(void)
{
	if (!pgrp_cp.is_open)
		return;

	/* reverse order of initialization */
	portq_grp_disconnect(portq_grp_cp_main);
	acipc_exit();
	portq_grp_close(portq_grp_cp_main);
	cp_shm_exit();
	unmap_apmu_base_va();
}

static int cp_mem_set_notifier_func(struct notifier_block *this,
	unsigned long code, void *cmd)
{
	struct cpload_cp_addr *addr = (struct cpload_cp_addr *)cmd;
	u32 lpm_qos = (u32)code;

	if (addr->first_boot) {
		cp_init(addr, lpm_qos);
	} else {
		cp_shm_exit();
		cp_shm_init(addr);
	}

	return 0;
}

int cp_ioctl_handler(unsigned int cmd, unsigned long arg)
{
	int status;

	switch (cmd) {
	case MSOCKET_IOC_CP_UP:
		pr_info("MSOCK: MSOCKET_UP is received!\n");
		/*
		 * in the case AP initiative reset CP, AP will first
		 * make msocket linkdown then hold, so CP still can
		 * send packet to share memory in this interval
		 * cleanup share memory one more time in msocket linkup
		 */
		shm_rb_data_init(&portq_cp_rbctl);
		spin_lock(&cp_sync_lock);
		cp_recv_up_ioc = true;
		spin_unlock(&cp_sync_lock);
		/* ensure completion cleared before start */
		reinit_completion(&cp_peer_sync);
		portq_grp_connect(portq_grp_cp_main);
		if (wait_for_completion_timeout(&cp_peer_sync, 5 * HZ) == 0) {
			pr_info("MSOCK: sync with CP FAIL\n");
			return -1;
		}
		return 0;

	case MSOCKET_IOC_CP_DOWN:
		pr_info("MSOCK: MSOCKET_DOWN is received!\n");
		if (likely(pgrp_cp.is_open)) {
			portq_grp_dump(portq_grp_cp_main);
			portq_grp_disconnect(portq_grp_cp_main);
		}
		/* ok! the world's silent then notify the upper layer */
		notify_cp_link_status(MsocketLinkdownProcId, NULL);
		return 0;

	case MSOCKET_IOC_CP_PMIC_QUERY:
		pr_info("MSOCK: MSOCKET_PMIC_QUERY is received!\n");
		status = cpks->cp_pcm_master == PMIC_MASTER_FLAG;
		if (copy_to_user((void *)arg, &status, sizeof(int)))
			return -1;
		else
			return 0;

	case MSOCKET_IOC_CP_CONNECT:
		pr_info("MSOCK: MSOCKET_IOC_CONNECT is received!\n");
		portq_grp_connect(portq_grp_cp_main);
		return 0;

	case MSOCKET_IOC_CP_RESET_REQUEST:
		pr_info("MSOCK: MSOCKET_IOC_RESET_CP_REQUEST is received!\n");
		acipc_reset_cp_request();
		return 0;
	case MSOCKET_IOC_CP_NETWORK_MODE_NOTIFY:
		/*notify CP network mode*/
		mutex_lock(&cpks_lock);
		if (cpks) {
			cpks->network_mode = (int)arg;
			pr_info("MSOCK: network mode:%d\n",
				(int)arg);
		}
		mutex_unlock(&cpks_lock);
		return 0;
	default:
		return -ENOIOCTLCMD;
	}
}
