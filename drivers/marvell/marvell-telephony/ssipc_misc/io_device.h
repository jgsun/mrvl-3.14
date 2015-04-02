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

#ifndef _IO_DEVICE_H_
#define _IO_DEVICE_H_

#include <linux/workqueue.h>
#include <linux/skbuff.h>

struct _long_packet_header {
	u16 total_len;
	u16 seq;
};

struct _long_packet {
	int total_len;
	int cur_len;
	int cur_seq;
	struct sk_buff *long_skb;
};

struct io_device {
	char *name;
	int   port;
	char *app;
	struct device *dev;
	int minor;
	struct list_head list;
	wait_queue_head_t wq;
	struct sk_buff_head sk_rx_q;
	int sock_fd;
	int channel_inited;

	/* reference count */
	atomic_t opened;

	/* support recv long packet*/
	int long_packet_enable;
	struct _long_packet *long_packet;

	/* support buffer packet offline*/
	int buffer_offline_enable;

	/*channel status*/
	int channel_status;

	/* hook function*/
	void (*init_hook)(struct io_device *);
	void (*deinit_hook)(struct io_device *);
	int	(*rx_fixup)(struct sk_buff *skb);
	ssize_t (*tx_fixup)(struct io_device *iod,
		const char __user *data,
		size_t count,
		struct sk_buff_head *txq,
		u16 hdr_reserved);
	long (*ioctl_hook)(struct io_device *,
			unsigned int cmd,
			unsigned long arg);

	/* proc id */
	int start_id;
	int data_id;
	int linkdown_id;
	int linkup_id;

	/* init work */
	struct delayed_work init_work;
	struct workqueue_struct *workq;
};

/* modem state report for SSIPC use
 * currently only report OFFLINE/ONLINE/CRASH_RESET
 */

enum modem_state {
	STATE_OFFLINE,
	STATE_CRASH_RESET,
	STATE_CRASH_EXIT,
	STATE_BOOTING,
	STATE_ONLINE,
	STATE_NV_REBUILDING,
	STATE_LOADER_DONE,
	STATE_SIM_ATTACH,
	STATE_SIM_DETACH,
};

/* using to build some control node */
#define PORT_NO_USE_START 100

void io_channel_init(struct io_device *iod);
void io_channel_deinit(struct io_device *iod);
int io_device_register(struct io_device *iod);
int io_device_deregister(struct io_device *iod);

const char *get_modem_state_str(int state);
int if_msocket_connect(void);
int get_modem_state(struct io_device *iod);

extern int read_ee_config_b_cp_reset(void);
extern int trigger_modem_crash(int force_reset, const char *disc);

#endif /* _IO_DEVICE_H_ */
