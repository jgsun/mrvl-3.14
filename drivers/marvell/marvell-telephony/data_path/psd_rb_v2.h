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

#ifndef PSD_RB_V2_H_
#define PSD_RB_V2_H_

#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/spinlock.h>
#include "shm_common.h"
#include "psd_shm_v2.h"

struct chan_info {
	volatile void *desc;
	volatile u16 *wptr;
	volatile u16 *rptr;
	unsigned count;
	unsigned index; /* for dumper */
};

struct psd_rbctl {
	/*
	 * name
	 */
	const char *name;

	/*
	 * private, owned by upper layer
	 */
	void *priv;

	/*
	 * debugfs dir
	 */
	struct dentry *rbdir;

	/*
	 * key section pointer
	 */
	unsigned long     skctl_pa;
	volatile struct psd_skctl  *skctl_va;

	/*
	 * TX buffer
	 */
	unsigned long  tx_pa;
	void          *tx_va;
	int            tx_total_size;
	bool           tx_cacheable;

	/*
	 * RX buffer
	 */
	unsigned long  rx_pa;
	void          *rx_va;
	int            rx_total_size;
	bool           rx_cacheable;

	/*
	 * queue mask
	 * a mirror to the same parameter in key section
	 */
	unsigned long ap_chan_status;
	spinlock_t queue_lock;

	/*
	 * lock for virtual address mapping
	 */
	struct mutex va_lock;

	/*
	 * locks for queues
	 */
	spinlock_t free_lock;
	spinlock_t reclaim_lock;

	/* local copies of AP-write ptrs */
	atomic_t local_dl_free_wptr;
	atomic_t local_committed_dl_free_wptr;
	int local_ul_defl_wptr[PSD_UL_CH_CNT];
	int local_ul_high_wptr[PSD_UL_CH_CNT];
	int local_ul_free_rptr;
	int local_dl_rptr;

	/* ul channel info */
	u16 ul_defl_chan_len[PSD_UL_CH_CNT];
	u16 ul_high_chan_len[PSD_UL_CH_CNT];

	struct chan_info ul_defl_chan[PSD_UL_CH_CNT];
	struct chan_info ul_high_chan[PSD_UL_CH_CNT];
	struct chan_info ul_free_chan;
	struct chan_info dl_chan;
	struct chan_info dl_free_chan;
};

int psd_rb_init(struct psd_rbctl *rbctl, struct dentry *parent);
int psd_rb_exit(struct psd_rbctl *rbctl);
void psd_rb_data_init(struct psd_rbctl *rbctl);

#endif /* PSD_RB_V2_H_ */
