/*
    msocket.h Created on: Aug 2, 2010, Jinhua Huang <jhhuang@marvell.com>

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

#ifndef MSOCKET_H_
#define MSOCKET_H_

#include <linux/skbuff.h>
#include "portq_cp.h"
#include "portq_m3.h"

#define MSOCKET_IOC_MAGIC       0xD2
#define MSOCKET_IOC_CP_MAGIC       0xD1
#define MSOCKET_IOC_M3_MAGIC       0xD0

#define MSOCKET_IOC_BIND	_IO(MSOCKET_IOC_MAGIC, 1)

#define MSOCKET_IOC_CP_UP		_IO(MSOCKET_IOC_CP_MAGIC, 1)
#define MSOCKET_IOC_CP_DOWN	_IO(MSOCKET_IOC_CP_MAGIC, 2)
#define MSOCKET_IOC_CP_PMIC_QUERY	_IOR(MSOCKET_IOC_CP_MAGIC, 3, int)
#define MSOCKET_IOC_CP_CONNECT	_IO(MSOCKET_IOC_CP_MAGIC, 4)
#define MSOCKET_IOC_CP_RESET_REQUEST _IO(MSOCKET_IOC_CP_MAGIC, 5)
#define MSOCKET_IOC_CP_NETWORK_MODE_NOTIFY _IOW(MSOCKET_IOC_CP_MAGIC, 6, int)

#define MSOCKET_IOC_M3_ERRTO	_IO(MSOCKET_IOC_M3_MAGIC, 7)
#define MSOCKET_IOC_M3_RECOVERY	_IO(MSOCKET_IOC_M3_MAGIC, 8)

/* flags for msend/mrecv */
#define MSOCKET_KERNEL		0	/* can be blocked in kernel context */
#define MSOCKET_ATOMIC		1	/* should be atomic in interrupt */

enum portq_grp_type {
	portq_grp_cp_main,
	portq_grp_m3,

	portq_grp_cnt
};

extern int msocket(int port);
extern int msocket_with_cb(int port,
		void (*clbk)(struct sk_buff *, void *), void *arg);
extern int mclose(int sock);
extern int msend(int sock, const void *buf, int len, int flags);
extern int mrecv(int sock, void *buf, int len, int flags);
extern int msendskb(int sock, struct sk_buff *skb, int len, int flags);
extern struct sk_buff *mrecvskb(int sock, int len, int flags);
extern void msocket_recv_throttled(int sock);
extern void msocket_recv_unthrottled(int sock);
/* designed for future use, not used here */
/*
 * extern void msched_work(struct work_struct *work);
 * extern int msend_skb(int sock, struct sk_buff *skb, int flags);
 * extern int mrecv_skb(int sock, struct sk_buff **pskb, int flags);
*/

extern struct dentry *msocket_debugfs_root_dir;

#endif /* MSOCKET_H_ */
