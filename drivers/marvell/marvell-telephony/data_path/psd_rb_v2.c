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
#include <linux/version.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/ctype.h>
#include <linux/printk.h>
#include "debugfs.h"
#include "data_path_common.h"
#include "psd_shm_v2.h"
#include "psd_rb_v2.h"
#include "shm_map.h"
#include "lib.h"

static int debugfs_show_info(struct seq_file *s, void *data)
{
	struct psd_rbctl *rbctl = s->private;
	int ret = 0;

	ret += seq_printf(s, "skctl_pa\t: 0x%p\n", (void *)rbctl->skctl_pa);
	ret += seq_printf(s, "skctl_va\t: 0x%p\n", rbctl->skctl_va);
	ret += seq_printf(s, "tx_pa\t\t: 0x%p\n", (void *)rbctl->tx_pa);
	ret += seq_printf(s, "tx_va\t\t: 0x%p\n", rbctl->tx_va);
	ret += seq_printf(s, "tx_total_size\t: %d\n",
		rbctl->tx_total_size);
	ret += seq_printf(s, "tx_cacheable\t: %c\n",
		rbctl->tx_cacheable ? 'Y' : 'N');
	ret += seq_printf(s, "rx_pa\t\t: 0x%p\n", (void *)rbctl->rx_pa);
	ret += seq_printf(s, "rx_va\t\t: 0x%p\n", rbctl->rx_va);
	ret += seq_printf(s, "rx_total_size\t: %d\n",
		rbctl->rx_total_size);
	ret += seq_printf(s, "rx_cacheable\t: %c\n",
		rbctl->rx_cacheable ? 'Y' : 'N');
	ret += seq_printf(s, "ap_chan_status\t: 0x%04lx\n",
		rbctl->ap_chan_status);

	return ret;
}

static int debugfs_show_ci(struct seq_file *s, void *data)
{
	volatile struct psd_skctl *skctl = s->private;
	int ret = 0;
	int i = 0;

	ret += seq_printf(s, "ap_chan_status\t: 0x%04x\n",
		skctl->ci.ap_chan_status);
	ret += seq_printf(s, "cp_chan_status\t: 0x%04x\n",
		skctl->ci.cp_chan_status);

	ret += seq_puts(s, "cid map\n");
	ret += seq_puts(s, "|queue|");
	for (i = 0; i < PSD_UL_CH_CNT; i++)
		ret += seq_printf(s, "%3d|", i);
	ret += seq_puts(s, "\n");
	ret += seq_puts(s, "| cid |");
	for (i = 0; i < PSD_UL_CH_CNT; i++)
		ret += seq_printf(s, "%3d|", skctl->ci.chan_cid[i]);
	ret += seq_puts(s, "\n");

	ret += seq_puts(s, "qci map\n");
	ret += seq_puts(s, "|queue|");
	for (i = 0; i < PSD_DL_CH_CNT; i++)
		ret += seq_printf(s, "%2d|", i);
	ret += seq_puts(s, "\n");
	ret += seq_puts(s, "| qci |");
	for (i = 0; i < PSD_DL_CH_CNT; i++)
		ret += seq_printf(s, "%2d|", skctl->ci.chan_qci[i]);
	ret += seq_puts(s, "\n");

	ret += seq_puts(s, "ul default priority channel length\n");
	ret += seq_puts(s, "|queue|");
	for (i = 0; i < PSD_DL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", i);
	ret += seq_puts(s, "\n");
	ret += seq_puts(s, "| len |");
	for (i = 0; i < PSD_DL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", skctl->ci.ul_defl_chan_len[i]);
	ret += seq_puts(s, "\n");

	ret += seq_puts(s, "ul high priority channel length\n");
	ret += seq_puts(s, "|queue|");
	for (i = 0; i < PSD_DL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", i);
	ret += seq_puts(s, "\n");
	ret += seq_puts(s, "| len |");
	for (i = 0; i < PSD_DL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", skctl->ci.ul_high_chan_len[i]);
	ret += seq_puts(s, "\n");
	return ret;
}

static int debugfs_show_ul_skctl(struct seq_file *s, void *data)
{
	volatile struct psd_skctl *skctl = s->private;
	int ret = 0;
	int i = 0;

	ret += seq_printf(s, "active\t: %c\n",
		skctl->us.active ? 'Y' : 'N');

	ret += seq_puts(s, "default queue\n");
	ret += seq_puts(s, "|queue|");
	for (i = 0; i < PSD_UL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", i);
	ret += seq_puts(s, "\n");
	ret += seq_puts(s, "| wptr|");
	for (i = 0; i < PSD_UL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", skctl->us.defl_wptr[i]);
	ret += seq_puts(s, "\n");
	ret += seq_puts(s, "| rptr|");
	for (i = 0; i < PSD_UL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", skctl->us.defl_rptr[i]);
	ret += seq_puts(s, "\n");

	ret += seq_puts(s, "high priority queue\n");
	ret += seq_puts(s, "|queue|");
	for (i = 0; i < PSD_UL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", i);
	ret += seq_puts(s, "\n");
	ret += seq_puts(s, "| wptr|");
	for (i = 0; i < PSD_UL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", skctl->us.high_wptr[i]);
	ret += seq_puts(s, "\n");
	ret += seq_puts(s, "| rptr|");
	for (i = 0; i < PSD_UL_CH_CNT; i++)
		ret += seq_printf(s, "%4d|", skctl->us.high_rptr[i]);
	ret += seq_puts(s, "\n");

	ret += seq_puts(s, "free queue\n");
	ret += seq_puts(s, "|queue|   0|\n");
	ret += seq_printf(s, "| wptr|%4d|\n", skctl->us.free_wptr);
	ret += seq_printf(s, "| rptr|%4d|\n", skctl->us.free_rptr);

	return ret;
}

static int debugfs_show_dl_skctl(struct seq_file *s, void *data)
{
	volatile struct psd_skctl *skctl = s->private;
	int ret = 0;

	ret += seq_printf(s, "active\t: %c\n",
		skctl->ds.active ? 'Y' : 'N');

	ret += seq_puts(s, "queue\n");
	ret += seq_puts(s, "|queue|   0|\n");
	ret += seq_printf(s, "| wptr|%4d|\n", skctl->ds.wptr);
	ret += seq_printf(s, "| rptr|%4d|\n", skctl->ds.rptr);

	ret += seq_puts(s, "free queue\n");
	ret += seq_puts(s, "|queue|   0|\n");
	ret += seq_printf(s, "| wptr|%4d|\n", skctl->ds.free_wptr);
	ret += seq_printf(s, "| rptr|%4d|\n", skctl->ds.free_rptr);

	return ret;
}

TEL_DEBUG_ENTRY(info);
TEL_DEBUG_ENTRY(ci);
TEL_DEBUG_ENTRY(ul_skctl);
TEL_DEBUG_ENTRY(dl_skctl);

enum {
	ul_desc_dump = 0,
	dl_desc_dump,
	free_desc_dump,
};

static ssize_t read_desc(struct file *file, char __user *ubuf,
	size_t count, loff_t *ppos, int type)
{
	struct chan_info *dumper = file->private_data;
	struct page *page;
	char *buf;
	char *p;
	int ret;
	int len;

	if (dumper->index >= dumper->count) {
		pr_err("%s: incorrect index %u\n", __func__, dumper->index);
		return -ENOMEM;
	}

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		pr_err("%s: cannot get memory\n", __func__);
		return -ENOMEM;
	}

	buf = page_address(page);
	p = buf;

	p += sprintf(p, "desc %u\n", dumper->index);

#define DUMP_DESC(p, desc, buf) do { \
	p += sprintf(p, "buffer_offset\t: %u\n", desc->buffer_offset); \
	p += sprintf(p, "exhdr_length\t: %u\n", desc->exhdr_length); \
	p += sprintf(p, "packet_offset\t: %u\n", desc->packet_offset); \
	p += sprintf(p, "packet_length\t: %u\n", desc->packet_length); \
	p += sprintf(p, "cid\t\t: %u\n", desc->cid); \
	p += sprintf(p, "simid\t\t: %u\n", desc->simid); \
	p += sprintf(p, "binary dump:\n"); \
	hex_dump_to_buffer((void *)desc, sizeof(*desc), 16, 1, p, \
		PAGE_SIZE - (p - buf), false); \
} while (0)

	switch (type) {
	case ul_desc_dump:
	{
		volatile struct ul_descriptor *desc;

		desc = (struct ul_descriptor *)dumper->desc + dumper->index;
		DUMP_DESC(p, desc, buf);
	}
	break;
	case dl_desc_dump:
	{
		volatile struct dl_descriptor *desc;

		desc = (struct dl_descriptor *)dumper->desc + dumper->index;
		DUMP_DESC(p, desc, buf);
	}
	break;
	case free_desc_dump:
	{
		volatile struct free_descriptor *desc;

		desc = (struct free_descriptor *)dumper->desc + dumper->index;
		p += sprintf(p, "buffer_offset\t: %u\n", desc->buffer_offset);
		p += sprintf(p, "length\t: %u\n", desc->length);
		p += sprintf(p, "binary dump:\n");
		hex_dump_to_buffer((void *)desc, sizeof(*desc), 16, 1, p,
			PAGE_SIZE - (p - buf), false);
	}
	break;
	}

	len = strlen(buf);
	buf[len] = '\n';

	ret = simple_read_from_buffer(ubuf, count, ppos, buf, len + 1);

	__free_page(page);

	return ret;
}

static ssize_t read_ul_desc(struct file *file, char __user *ubuf,
	size_t count, loff_t *ppos)
{
	return read_desc(file, ubuf, count, ppos, ul_desc_dump);
}

static ssize_t read_dl_desc(struct file *file, char __user *ubuf,
	size_t count, loff_t *ppos)
{
	return read_desc(file, ubuf, count, ppos, dl_desc_dump);
}

static ssize_t read_free_desc(struct file *file, char __user *ubuf,
	size_t count, loff_t *ppos)
{
	return read_desc(file, ubuf, count, ppos, free_desc_dump);
}

static ssize_t write_desc(struct file *file, const char __user *ubuf,
	size_t count, loff_t *ppos)
{
	struct chan_info *dumper = file->private_data;
	unsigned val;
	int ret;

	ret = kstrtouint_from_user(ubuf, count, 0, &val);
	if (ret)
		return ret;

	if (val >= dumper->count) {
		pr_err("%s: invalid index %u, expect less than %u\n",
			__func__, val, dumper->count);
		return -EFAULT;
	}

	dumper->index = val;

	return count;
}

static const struct file_operations fops_ul_desc = {
	.read =		read_ul_desc,
	.write =	write_desc,
	.open =		simple_open,
	.llseek =	default_llseek,
};

static const struct file_operations fops_dl_desc = {
	.read =		read_dl_desc,
	.write =	write_desc,
	.open =		simple_open,
	.llseek =	default_llseek,
};

static const struct file_operations fops_free_desc = {
	.read =		read_free_desc,
	.write =	write_desc,
	.open =		simple_open,
	.llseek =	default_llseek,
};

static int psd_rb_debugfs_init(struct psd_rbctl *rbctl,
	struct dentry *parent)
{
	struct dentry *ksdir;
	int i;

	rbctl->rbdir = debugfs_create_dir(rbctl->name ? rbctl->name : "psd-shm",
		parent);
	if (IS_ERR_OR_NULL(rbctl->rbdir))
		return -ENOMEM;

	if (IS_ERR_OR_NULL(debugfs_create_file("info", S_IRUGO,
				rbctl->rbdir, rbctl, &fops_info)))
		goto error;

	ksdir = debugfs_create_dir("key_section", rbctl->rbdir);
	if (IS_ERR_OR_NULL(ksdir))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_file("chan_info", S_IRUGO,
				ksdir, (void *)rbctl->skctl_va, &fops_ci)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_file("ul_skctl", S_IRUGO,
				ksdir, (void *)rbctl->skctl_va,
				&fops_ul_skctl)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_file("dl_skctl", S_IRUGO,
				ksdir, (void *)rbctl->skctl_va,
				&fops_dl_skctl)))
		goto error;

	for (i = 0; i < PSD_UL_CH_CNT; i++) {
		char buf[32];

		sprintf(buf, "ul_default_desc%d", i);
		if (IS_ERR_OR_NULL(debugfs_create_file(buf,
					S_IRUGO | S_IWUSR,
					ksdir, (void *)&rbctl->ul_defl_chan[i],
					&fops_ul_desc)))
			goto error;

		sprintf(buf, "ul_high_priority_desc%d", i);
		if (IS_ERR_OR_NULL(debugfs_create_file(buf,
					S_IRUGO | S_IWUSR,
					ksdir, (void *)&rbctl->ul_high_chan[i],
					&fops_ul_desc)))
			goto error;
	}

	if (IS_ERR_OR_NULL(debugfs_create_file("ul_free_desc",
				S_IRUGO | S_IWUSR,
				ksdir, (void *)&rbctl->ul_free_chan,
				&fops_free_desc)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_file("dl_desc",
				S_IRUGO | S_IWUSR,
				ksdir, (void *)&rbctl->dl_chan,
				&fops_dl_desc)))
		goto error;

	if (IS_ERR_OR_NULL(debugfs_create_file("dl_free_desc",
				S_IRUGO | S_IWUSR,
				ksdir, (void *)&rbctl->dl_free_chan,
				&fops_free_desc)))
		goto error;

	return 0;

error:
	debugfs_remove_recursive(rbctl->rbdir);
	rbctl->rbdir = NULL;
	return -1;
}

static int psd_rb_debugfs_exit(struct psd_rbctl *rbctl)
{
	debugfs_remove_recursive(rbctl->rbdir);
	rbctl->rbdir = NULL;
	return 0;
}

void psd_rb_data_init(struct psd_rbctl *rbctl)
{
	int i;
	int defl_len = 0, high_len = 0;
	volatile struct psd_skctl *skctl = rbctl->skctl_va;
	volatile struct ul_descriptor *defl_desc;
	volatile struct ul_descriptor *high_desc;

	mutex_lock(&rbctl->va_lock);
	memset_aligned((void *)skctl, 0, sizeof(*skctl));

	for (i = 0; i < PSD_UL_CH_CNT; i++) {
		defl_len += rbctl->ul_defl_chan_len[i];
		high_len += rbctl->ul_high_chan_len[i];
	}

	BUG_ON(defl_len + high_len != PSD_UL_CH_TOTAL_LEN);

	defl_desc = skctl->us.desc;
	high_desc = skctl->us.desc + defl_len;

	for (i = 0; i < PSD_UL_CH_CNT; i++) {
		rbctl->skctl_va->ci.chan_cid[i] = INVALID_CID;
		rbctl->ul_defl_chan[i].desc = defl_desc;
		rbctl->ul_defl_chan[i].wptr = &skctl->us.defl_wptr[i];
		rbctl->ul_defl_chan[i].rptr = &skctl->us.defl_rptr[i];
		rbctl->ul_defl_chan[i].count = rbctl->ul_defl_chan_len[i];
		rbctl->ul_defl_chan[i].index = 0;
		defl_desc += rbctl->ul_defl_chan_len[i];

		rbctl->ul_high_chan[i].desc = high_desc;
		rbctl->ul_high_chan[i].wptr = &skctl->us.high_wptr[i];
		rbctl->ul_high_chan[i].rptr = &skctl->us.high_rptr[i];
		rbctl->ul_high_chan[i].count = rbctl->ul_high_chan_len[i];
		rbctl->ul_high_chan[i].index = 0;
		high_desc += rbctl->ul_high_chan_len[i];
	}
	rbctl->ul_free_chan.desc = skctl->us.free_desc;
	rbctl->ul_free_chan.wptr = &skctl->us.free_wptr;
	rbctl->ul_free_chan.rptr = &skctl->us.free_rptr;
	rbctl->ul_free_chan.count = PSD_UF_CH_TOTAL_LEN;
	rbctl->ul_free_chan.index = 0;

	rbctl->dl_chan.desc = skctl->ds.desc;
	rbctl->dl_chan.wptr = &skctl->ds.wptr;
	rbctl->dl_chan.rptr = &skctl->ds.rptr;
	rbctl->dl_chan.count = PSD_DL_CH_TOTAL_LEN;
	rbctl->dl_chan.index = 0;

	rbctl->dl_free_chan.desc = skctl->ds.free_desc;
	rbctl->dl_free_chan.wptr = &skctl->ds.free_wptr;
	rbctl->dl_free_chan.rptr = &skctl->ds.free_rptr;
	rbctl->dl_free_chan.count = PSD_DF_CH_TOTAL_LEN;
	rbctl->dl_free_chan.index = 0;

	/* copy ul channel length to share memory */
	memcpy((void *)skctl->ci.ul_defl_chan_len,
		rbctl->ul_defl_chan_len,
		sizeof(rbctl->ul_defl_chan_len));
	memcpy((void *)skctl->ci.ul_high_chan_len,
		rbctl->ul_high_chan_len,
		sizeof(rbctl->ul_high_chan_len));

	atomic_set(&rbctl->local_dl_free_wptr, 0);
	atomic_set(&rbctl->local_committed_dl_free_wptr, 0);

	memset(rbctl->local_ul_defl_wptr, 0, sizeof(rbctl->local_ul_defl_wptr));
	memset(rbctl->local_ul_high_wptr, 0, sizeof(rbctl->local_ul_high_wptr));
	rbctl->local_ul_free_rptr = 0;
	rbctl->local_dl_rptr = 0;

	/* make sure chan_len is copied before we start */
	wmb();

	mutex_unlock(&rbctl->va_lock);
}

static inline void psd_rb_dump(struct psd_rbctl *rbctl)
{
	pr_info(
		"ring buffer %s:\n"
		"\tskctl_pa: 0x%08lx, skctl_va: 0x%p\n"
		"\ttx_pa: 0x%08lx, tx_va: 0x%p\n"
		"\ttx_total_size: 0x%08x\n"
		"\trx_pa: 0x%08lx, rx_va: 0x%p\n"
		"\trx_total_size: 0x%08x\n",
		rbctl->name ? rbctl->name : "psd shm",
		rbctl->skctl_pa, rbctl->skctl_va,
		rbctl->tx_pa, rbctl->tx_va,
		rbctl->tx_total_size,
		rbctl->rx_pa, rbctl->rx_va,
		rbctl->rx_total_size
	);
}

int psd_rb_init(struct psd_rbctl *rbctl, struct dentry *parent)
{
	mutex_lock(&rbctl->va_lock);
	/* map to non-cache virtual address */
	rbctl->skctl_va =
	    shm_map(rbctl->skctl_pa, sizeof(struct psd_skctl));
	if (!rbctl->skctl_va)
		goto exit1;

	/* map ring buffer to cacheable memeory, if it is DDR */
	if (pfn_valid(__phys_to_pfn(rbctl->tx_pa))) {
		rbctl->tx_cacheable = true;
		rbctl->tx_va = phys_to_virt(rbctl->tx_pa);
	} else {
		rbctl->tx_cacheable = false;
		rbctl->tx_va = shm_map(rbctl->tx_pa, rbctl->tx_total_size);
	}

	if (!rbctl->tx_va)
		goto exit2;

	if (pfn_valid(__phys_to_pfn(rbctl->rx_pa))) {
		rbctl->rx_cacheable = true;
		rbctl->rx_va = phys_to_virt(rbctl->rx_pa);
	} else {
		rbctl->rx_cacheable = false;
		rbctl->rx_va = shm_map(rbctl->rx_pa, rbctl->rx_total_size);
	}

	if (!rbctl->rx_va)
		goto exit3;

	mutex_unlock(&rbctl->va_lock);
	psd_rb_data_init(rbctl);
	psd_rb_dump(rbctl);

	if (psd_rb_debugfs_init(rbctl, parent) < 0)
		goto exit4;

	return 0;

exit4:
	psd_rb_debugfs_exit(rbctl);
	mutex_lock(&rbctl->va_lock);
	if (!rbctl->rx_cacheable)
		shm_unmap(rbctl->rx_pa, rbctl->rx_va);
	rbctl->rx_cacheable = false;
exit3:
	if (!rbctl->tx_cacheable)
		shm_unmap(rbctl->tx_pa, rbctl->tx_va);
	rbctl->tx_cacheable = false;
exit2:
	shm_unmap(rbctl->skctl_pa, (void *)rbctl->skctl_va);
exit1:
	mutex_unlock(&rbctl->va_lock);
	return -1;
}

int psd_rb_exit(struct psd_rbctl *rbctl)
{
	void *skctl_va = (void *)rbctl->skctl_va;
	void *tx_va = rbctl->tx_va;
	void *rx_va = rbctl->rx_va;

	psd_rb_debugfs_exit(rbctl);
	/* release memory */
	mutex_lock(&rbctl->va_lock);
	rbctl->skctl_va = NULL;
	rbctl->tx_va = NULL;
	rbctl->rx_va = NULL;
	mutex_unlock(&rbctl->va_lock);
	shm_unmap(rbctl->skctl_pa, skctl_va);
	if (!rbctl->tx_cacheable)
		shm_unmap(rbctl->tx_pa, tx_va);
	rbctl->tx_cacheable = false;
	if (!rbctl->rx_cacheable)
		shm_unmap(rbctl->rx_pa, rx_va);
	rbctl->rx_cacheable = false;

	return 0;
}
