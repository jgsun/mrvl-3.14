/*
 * linux/drivers/devfreq/mck_memorybus.c
 *
 *  Copyright (C) 2012 Marvell International Ltd.
 *  All rights reserved.
 *
 *  2012-03-16	Yifan Zhang <zhangyf@marvell.com>
 *		Zhoujie Wu<zjwu@marvell.com>
 *		Qiming Wu<wuqm@marvell.com>
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License. See the file COPYING in the main directory of this archive for
 * more details.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/devfreq.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/mck_memorybus.h>
#include <linux/platform_device.h>
#include <linux/pm_qos.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/of_address.h>
#include <trace/events/pxa.h>
#ifdef CONFIG_DEVFREQ_GOV_THROUGHPUT
#include <linux/ddr_upthreshold.h>
#include <linux/sysfs.h>
#endif
#include <linux/clk/mmpdcstat.h>
#include <linux/clk-provider.h>


#define DDR_DEVFREQ_UPTHRESHOLD 65
#define DDR_DEVFREQ_DOWNDIFFERENTIAL 5

#define KHZ_TO_HZ   1000

#ifdef CONFIG_DEVFREQ_GOV_THROUGHPUT
static struct ddr_devfreq_data *ddrfreq_driver_data;

/* default using 65% as upthreshold and 5% as downdifferential */
static struct devfreq_throughput_data devfreq_throughput_data = {
	.upthreshold = DDR_DEVFREQ_UPTHRESHOLD,
	.downdifferential = DDR_DEVFREQ_DOWNDIFFERENTIAL,
};

static inline void __update_dev_upthreshold(unsigned int upthrd,
		struct devfreq_throughput_data *gov_data)
{
	int i;

	for (i = 0; i < gov_data->table_len; i++) {
		gov_data->throughput_table[i].up =
			upthrd * gov_data->freq_table[i] / 100;
		gov_data->throughput_table[i].down =
			(upthrd - gov_data->downdifferential) *
			gov_data->freq_table[i] / 100;
	}
}
#endif /* CONFIG_DDR_DEVFREQ_GOV_THROUGHPUT */

static void __iomem *iomap_register(const char *reg_name)
{
	void __iomem *reg_virt_addr;
	struct device_node *node;

	BUG_ON(!reg_name);
	node = of_find_compatible_node(NULL, NULL, reg_name);
	BUG_ON(!node);
	reg_virt_addr = of_iomap(node, 0);
	BUG_ON(!reg_virt_addr);

	return reg_virt_addr;
}

static void __iomem *get_apmu_base_va(void)
{
	static void __iomem *apmu_virt_addr;
	if (unlikely(!apmu_virt_addr))
		apmu_virt_addr = iomap_register("marvell,mmp-pmu-apmu");
	return apmu_virt_addr;
}

static int ddr_max;

static int __init ddr_max_setup(char *str)
{
	int freq;

	if (!get_option(&str, &freq))
		return 0;
	ddr_max = freq;
	return 1;
}

__setup("ddr_max=", ddr_max_setup);

static int ddr_min = 156000;

static int __init ddr_min_setup(char *str)
{
	int freq;

	if (!get_option(&str, &freq))
		return 0;
	ddr_min = freq;
	return 1;
}

__setup("ddr_min=", ddr_min_setup);

static void write_static_register(unsigned int val, unsigned int expected_val,
				  void *reg, unsigned int ver)
{
	int max_try = 1000;
	unsigned int temp;
	unsigned long flags;
	void __iomem *apmu_base = get_apmu_base_va();

	if (ver == MCK4) {
		get_fc_spinlock();
		local_irq_save(flags);
		get_fc_lock(apmu_base, 1);
		while (max_try-- > 0) {
			writel(val, reg);
			temp = readl(reg);
			if (expected_val == temp)
				break;
		}
		if (!max_try)
			pr_err("Can't write register %p with value %X\n", reg, val);
		put_fc_lock(apmu_base);
		local_irq_restore(flags);
		put_fc_spinlock();
	} else if (ver == MCK5)
		writel(val, reg);
	else
		/* this should never happen */
		BUG_ON(1);
}

static unsigned int read_static_register(void *reg, unsigned int ver)
{
	unsigned int ret;
	unsigned long flags;
	void __iomem *apmu_base = get_apmu_base_va();

	if (ver == MCK4) {
		get_fc_spinlock();
		local_irq_save(flags);
		get_fc_lock(apmu_base, 1);
		ret = readl(reg);
		put_fc_lock(apmu_base);
		local_irq_restore(flags);
		put_fc_spinlock();
	} else if (ver == MCK5)
		ret = readl(reg);
	else
		/* this should never happen */
		BUG_ON(1);
	return ret;
}

static void stop_ddr_performance_counter(struct ddr_devfreq_data *data)
{
	void __iomem *mc_base = data->dmc.hw_base;
	struct mck_pmu_regs_offset *regs = &data->dmc.mck_regs;
	unsigned int ver = data->dmc.version;

	/*
	 * Write to Performance Counter Configuration Register to
	 * disable counters.
	 */
	write_static_register(0x0, 0x0, mc_base + regs->cfg, ver);
}

static void start_ddr_performance_counter(struct ddr_devfreq_data *data)
{
	void __iomem *mc_base = data->dmc.hw_base;
	struct mck_pmu_regs_offset *regs = &data->dmc.mck_regs;
	unsigned int ver = data->dmc.version;
	unsigned int val;

	/*
	 * Write to Performance Counter Configuration Register to
	 * enable counters and choose the events for counters.
	 */
	switch (ver) {
	case MCK4:
		/*
		 * cnt1, event=0x00, clock cycles
		 * cnt2, event=0x14, Read + Write command count
		 * cnt3, event=0x04, no bus utilization when not idle
		 */
		val = ((0x00 | 0x00) <<  0) | ((0x80 | 0x00) <<  8) |
		      ((0x80 | 0x14) << 16) | ((0x80 | 0x04) << 24);
		break;
	case MCK5:
		/*
		 * cnt1, event=0x00, clock cycles
		 * cnt2, event=0x1A, Read + Write command count
		 * cnt3, event=0x18, busy cycles
		 */
		val = ((0x00 | 0x00) <<  0) | ((0x80 | 0x00) <<  8) |
		      ((0x80 | 0x1A) << 16) | ((0x80 | 0x18) << 24);
		break;
	default:
		/* this should never happen */
		BUG_ON(1);
	}

	write_static_register(val, val, mc_base + regs->cfg, ver);
}

static void init_ddr_performance_counter(struct ddr_devfreq_data *data)
{
	unsigned int i;
	void __iomem *mc_base = data->dmc.hw_base;
	struct mck_pmu_regs_offset *regs = &data->dmc.mck_regs;
	unsigned int ver = data->dmc.version;

	/*
	 * Step1: Write to Performance Counter Configuration Register to
	 * disable counters.
	 */
	write_static_register(0x0, 0x0, mc_base + regs->cfg, ver);

	/*
	 * Step2: Write to Performance Counter Register to set the starting
	 * value.
	 */
	for (i = 0; i < data->dmc.pmucnt_in_use; i++) {
		write_static_register(0x0, 0x0,
			mc_base + regs->cnt_base + i * 4, ver);
	}

	/*
	 * Step3: Write to Performance Counter Status Register to clear
	 * overflow flag.
	 */
	write_static_register(0xf, 0x0, mc_base + regs->cnt_stat, ver);

	/*
	 * Step4: Write to Performance Counter Control Register to select
	 * the desired settings
	 * bit18:16 0x0 = Divide clock by 1
	 * bit4     0x1 = Continue counting on any counter overflow
	 * bit0     0x0 = Enabled counters begin counting
	 */
	write_static_register(0x10, 0x10, mc_base + regs->ctrl, ver);

	/* Step5: Enable Performance Counter interrupt */
	write_static_register(0x1, 0x1, mc_base + regs->intr_en, ver);
}

static int ddr_rate2_index(struct ddr_devfreq_data *data)
{
	unsigned int rate;
	int i;

	rate = clk_get_rate(data->ddr_clk) / KHZ_TO_HZ;
	for (i = 0; i < data->ddr_freq_tbl_len; i++)
		if (data->ddr_freq_tbl[i] == rate)
			return i;
	dev_err(&data->devfreq->dev, "unknow ddr rate %d\n", rate);
	return -1;
}

static unsigned int ddr_index2_rate(struct ddr_devfreq_data *data, int index)
{
	if ((index >= 0) && (index < data->ddr_freq_tbl_len))
		return data->ddr_freq_tbl[index];
	else {
		dev_err(&data->devfreq->dev,
			"unknow ddr index %d\n", index);
		return 0;
	}
}

/*
 * overflow: 1 means overflow shouled be handled, 0 means not.
 * start: 1 means performance counter is started after update, 0 means not.
 */
static void ddr_perf_cnt_update(struct ddr_devfreq_data *data, u32 overflow,
		u32 start)
{
	struct perf_counters *ddr_ticks = data->dmc.ddr_ticks;
	void *mc_base = (void *)data->dmc.hw_base;
	struct mck_pmu_regs_offset *regs = &data->dmc.mck_regs;
	unsigned int cnt, i, overflow_flag;
	unsigned int ddr_idx = data->cur_ddr_idx;
	unsigned long flags;
	unsigned int ver = data->dmc.version;

	if ((overflow != 1 && overflow != 0) || (start != 1 && start != 0)) {
		dev_err(&data->devfreq->dev, "%s: parameter is not correct.\n",
				__func__);
		return;
	}

	if (ddr_idx >= data->ddr_freq_tbl_len) {
		dev_err(&data->devfreq->dev, "%s: invalid ddr_idx %u\n",
				__func__, ddr_idx);
		return;
	}

	/*
	 * To make life simpler, only handle overflow case in IRQ->work path.
	 * So the overflow parameter will only be 1 in that path.
	 * If overflow is 0, keep polling here until that path complete if
	 * found overflow happen.
	 * The spin_unlock is to make sure the polling will not block the
	 * path we want to run.
	 */
	while (1) {
		spin_lock_irqsave(&data->lock, flags);

		/* stop counters, to keep data synchronized */
		stop_ddr_performance_counter(data);

		overflow_flag =
			read_static_register(mc_base + regs->cnt_stat, ver)
			& 0xf;

		/* If overflow, bypass the polling */
		if (overflow)
			break;

		/* If overflow happen right now, wait for handler finishing */
		if (!overflow_flag)
			break;

		spin_unlock_irqrestore(&data->lock, flags);

		/* Take a breath here to let overflow work to get cpu */
		usleep_range(100, 1000);
	}

	/* If overflow, clear pended overflow flag in MC */
	if (overflow)
		write_static_register(overflow_flag, 0x0,
				mc_base + regs->cnt_stat, ver);

	for (i = 0; i < data->dmc.pmucnt_in_use; i++) {
		cnt = read_static_register(mc_base + regs->cnt_base + i * 4,
				ver);

		if (overflow_flag & (1 << i)) {
			dev_dbg(&data->devfreq->dev,
					"DDR perf counter overflow!\n");
			ddr_ticks[ddr_idx].reg[i] += (1LLU << 32);
		}
		ddr_ticks[ddr_idx].reg[i] += cnt;

		/* reset performance counter to 0x0 */
		write_static_register(0x0, 0x0,
				mc_base + regs->cnt_base + i * 4, ver);
	}

	if (start)
		start_ddr_performance_counter(data);

	spin_unlock_irqrestore(&data->lock, flags);
}

static int __init ddr_perf_cnt_init(struct ddr_devfreq_data *data)
{
	unsigned long flags;

	spin_lock_irqsave(&data->lock, flags);
	init_ddr_performance_counter(data);
	start_ddr_performance_counter(data);
	spin_unlock_irqrestore(&data->lock, flags);

	data->cur_ddr_idx = ddr_rate2_index(data);

	return 0;
}

static inline void ddr_perf_cnt_restart(struct ddr_devfreq_data *data)
{
	unsigned long flags;

	spin_lock_irqsave(&data->lock, flags);
	start_ddr_performance_counter(data);
	spin_unlock_irqrestore(&data->lock, flags);
}

/*
 * get the mck total_ticks, data_ticks, speed.
 */
static void get_ddr_cycles(struct ddr_devfreq_data *data,
	unsigned long *total_ticks, unsigned long *data_ticks, int *speed)
{
	unsigned long flags;
	unsigned int diff_ms;
	unsigned long long time_stamp_cur;
	static unsigned long long time_stamp_old;
	struct perf_counters *ddr_ticks = data->dmc.ddr_ticks;
	struct devfreq_frequency_table *tbl;
	int i;
#ifdef CONFIG_64BIT
	u64 *total_ticks_base = data->ddr_profiler.total_ticks_base;
	u64 *data_ticks_base = data->ddr_profiler.data_ticks_base;
#else
	u32 *total_ticks_base = data->ddr_profiler.total_ticks_base;
	u32 *data_ticks_base = data->ddr_profiler.data_ticks_base;
#endif

	tbl = devfreq_frequency_get_table(DEVFREQ_DDR);

	spin_lock_irqsave(&data->lock, flags);
	*total_ticks = *data_ticks = 0;
	for (i = 0; i < data->ddr_freq_tbl_len; i++) {
		*total_ticks += ddr_ticks[i].reg[1] - total_ticks_base[i];
		/* Sanity check: clock driver should pass 0 or 1 for 4x mode enable */
		BUG_ON((tbl[i].mode_4x_en != 0) && (tbl[i].mode_4x_en != 1));
		*data_ticks +=
			(ddr_ticks[i].reg[2] - data_ticks_base[i]) / (2 << tbl[i].mode_4x_en);
		total_ticks_base[i] = ddr_ticks[i].reg[1];
		data_ticks_base[i] = ddr_ticks[i].reg[2];
	}
	*data_ticks = *data_ticks * data->bst_len / 2;
	spin_unlock_irqrestore(&data->lock, flags);

	time_stamp_cur = sched_clock();
	diff_ms = (unsigned int)div_u64(time_stamp_cur - time_stamp_old,
			1000000);
	time_stamp_old = time_stamp_cur;

	if (diff_ms != 0)
		*speed = *data_ticks / diff_ms;
	else
		*speed = -1;
}

static int ddr_get_dev_status(struct device *dev,
			       struct devfreq_dev_status *stat)
{
	struct ddr_devfreq_data *data = dev_get_drvdata(dev);
	struct devfreq *df = data->devfreq;
	unsigned int workload;
	unsigned long polling_jiffies;
	unsigned long now = jiffies;

	stat->current_frequency = clk_get_rate(data->ddr_clk) / KHZ_TO_HZ;
	/*
	 * ignore the profiling if it is not from devfreq_monitor
	 * or there is no profiling
	 */
	polling_jiffies = msecs_to_jiffies(df->profile->polling_ms);
	if (!polling_jiffies || (polling_jiffies && data->last_polled_at &&
		time_before(now, (data->last_polled_at + polling_jiffies)))) {
		dev_dbg(dev,
			"No profiling or interval is not expired %lu, %lu, %lu\n",
			polling_jiffies, now, data->last_polled_at);
		return -EINVAL;
	}

	ddr_perf_cnt_update(data, 0, 1);
	get_ddr_cycles(data, &stat->total_time,
			&stat->busy_time, &stat->throughput);
	data->last_polled_at = now;

	/* Ajust the workload calculation here to align with devfreq governor */
	if (stat->busy_time >= (1 << 24) || stat->total_time >= (1 << 24)) {
		stat->busy_time >>= 7;
		stat->total_time >>= 7;
	}

	workload = cal_workload(stat->busy_time, stat->total_time);

	dev_dbg(dev, "workload is %d precent\n", workload);
	dev_dbg(dev, "busy time is 0x%x, %u\n", (unsigned int)stat->busy_time,
		 (unsigned int)stat->busy_time);
	dev_dbg(dev, "total time is 0x%x, %u\n\n",
		(unsigned int)stat->total_time,
		(unsigned int)stat->total_time);
	dev_dbg(dev, "throughput is 0x%x, throughput * 8 (speed) is %u\n\n",
		(unsigned int)stat->throughput, 8 * stat->throughput);

	trace_pxa_ddr_workload(workload, stat->current_frequency,
				stat->throughput);

	return 0;
}

static unsigned long ddr_set_rate(struct ddr_devfreq_data *data,
			unsigned long tgt_rate)
{
	unsigned long cur_freq, tgt_freq;
	int ddr_idx;

	cur_freq = clk_get_rate(data->ddr_clk);
	tgt_freq = tgt_rate * KHZ_TO_HZ;

	if (cur_freq == tgt_freq)
		return tgt_rate;

	dev_dbg(&data->devfreq->dev, "%s: curfreq %lu, tgtfreq %lu\n",
		__func__, cur_freq, tgt_freq);

	/* update performance data before ddr clock change */
	ddr_perf_cnt_update(data, 0, 0);

	/* clk_set_rate will find a frequency larger or equal tgt_freq */
	clk_set_rate(data->ddr_clk, tgt_freq);

	/* re-init ddr performance counters after ddr clock change */
	ddr_perf_cnt_restart(data);

	ddr_idx = ddr_rate2_index(data);
	if (ddr_idx >= 0) {
		data->cur_ddr_idx = ddr_idx;
		return data->ddr_freq_tbl[ddr_idx];
	} else
		dev_err(&data->devfreq->dev, "Failed to do ddr freq change\n");

	return tgt_freq;
}

static void find_best_freq(struct ddr_devfreq_data *data, unsigned long *freq,
			   u32 flags)
{
	int i;
	unsigned long temp = *freq;

	u32 *freq_table = data->ddr_freq_tbl;
	u32 len = data->ddr_freq_tbl_len;

	if (*freq < freq_table[0]) {
		*freq = freq_table[0];
		return;
	}
	if (flags & DEVFREQ_FLAG_LEAST_UPPER_BOUND) {
		for (i = 1; i < len; i++)
			if (freq_table[i - 1] <= temp
			    && freq_table[i] > temp) {
				*freq = freq_table[i - 1];
				break;
			}
	} else {
		for (i = 0; freq_table[i]; i++)
			if (freq_table[i] >= temp) {
				*freq = freq_table[i];
				break;
			}
	}

	if (i == len)
		*freq = freq_table[i - 1];
}

static int ddr_target(struct device *dev, unsigned long *freq,
		unsigned int flags)
{
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;
	struct devfreq *df;
	unsigned int *ddr_freq_table, ddr_freq_len;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);

	/* in normal case ddr fc will NOT be disabled */
	if (unlikely(atomic_read(&data->is_disabled))) {
		df = data->devfreq;
		/*
		 * this function is called with df->locked, it is safe to
		 * read the polling_ms here
		 */
		if (df->profile->polling_ms)
			dev_err(dev, "[WARN] ddr ll fc is disabled from "
				"debug interface, suggest to disable "
				"the profiling at first!\n");
		*freq = clk_get_rate(data->ddr_clk) / KHZ_TO_HZ;
		return 0;
	}

	ddr_freq_table = &data->ddr_freq_tbl[0];
	ddr_freq_len = data->ddr_freq_tbl_len;
	dev_dbg(dev, "%s: %u\n", __func__, (unsigned int)*freq);

	find_best_freq(data, freq, flags);
	*freq = ddr_set_rate(data, *freq);

	return 0;
}

static int configure_mck_pmu_regs(struct ddr_devfreq_data *data)
{
	unsigned int ver = data->dmc.version;

	switch (ver) {
	case MCK4:
		data->dmc.mck_regs.cfg = MCK4_PERF_CONFIG;
		data->dmc.mck_regs.cnt_stat = MCK4_PERF_STATUS;
		data->dmc.mck_regs.ctrl = MCK4_PERF_CONTRL;
		data->dmc.mck_regs.cnt_base = MCK4_PERF_CNT_BASE;
		data->dmc.mck_regs.intr_stat = MCK4_INTR_STATUS;
		data->dmc.mck_regs.intr_en = MCK4_INTR_EN;
		return 0;
	case MCK5:
		data->dmc.mck_regs.cfg = MCK5_PERF_CONFIG;
		data->dmc.mck_regs.cnt_stat = MCK5_PERF_STATUS;
		data->dmc.mck_regs.ctrl = MCK5_PERF_CONTRL;
		data->dmc.mck_regs.cnt_base = MCK5_PERF_CNT_BASE;
		data->dmc.mck_regs.intr_stat = MCK5_INTR_STATUS;
		data->dmc.mck_regs.intr_en = MCK5_INTR_EN;
		return 0;
	default:
		return -EINVAL;
	}
}

static int ddr_get_cur_freq(struct device *dev, unsigned long *freq)
{
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);

	*freq = clk_get_rate(data->ddr_clk) / KHZ_TO_HZ;

	return 0;
}

static struct devfreq_dev_profile ddr_devfreq_profile = {
	.name = "devfreq-ddr",
	/* Profiler is not enabled by default */
	.polling_ms = 0,
	.target = ddr_target,
	.get_dev_status = ddr_get_dev_status,
	.get_cur_freq = ddr_get_cur_freq,
};

/* debug interface used to totally disable ddr fc */
static ssize_t disable_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t size)
{
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;
	int is_disabled;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);

	if (0x1 != sscanf(buf, "%d", &is_disabled)) {
		dev_err(dev, "<ERR> wrong parameter\n");
		return -E2BIG;
	}

	is_disabled = !!is_disabled;
	if (is_disabled == atomic_read(&data->is_disabled)) {
		dev_info(dev, "[WARNING] ddr fc is already %s\n",
			atomic_read(&data->is_disabled) ?
			"disabled" : "enabled");
		return size;
	}

	if (is_disabled)
		atomic_inc(&data->is_disabled);
	else
		atomic_dec(&data->is_disabled);

	dev_info(dev, "[WARNING]ddr fc is %s from debug interface!\n",
		atomic_read(&data->is_disabled) ? "disabled" : "enabled");
	return size;
}

static ssize_t disable_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);
	return sprintf(buf, "ddr fc is_disabled = %d\n",
		 atomic_read(&data->is_disabled));
}

/*
 * Debug interface used to change ddr rate.
 * It will ignore all devfreq and Qos requests.
 * Use interface disable_ddr_fc prior to it.
 */
static ssize_t ddr_freq_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t size)
{
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;
	int freq;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);

	if (!atomic_read(&data->is_disabled)) {
		dev_err(dev, "<ERR> It will change ddr rate,"
			"disable ddr fc at first\n");
		return -EPERM;
	}

	if (0x1 != sscanf(buf, "%d", &freq)) {
		dev_err(dev, "<ERR> wrong parameter, "
			"echo freq > ddr_freq to set ddr rate(unit Khz)\n");
		return -E2BIG;
	}

	/* Make ddr_min and ddr_max take effect even in debug interface */
	freq = (ddr_min && ddr_min > freq) ? ddr_min : freq;
	freq = (ddr_max && ddr_max < freq) ? ddr_max : freq;
	ddr_set_rate(data, freq);

	dev_dbg(dev, "ddr freq read back: %lu\n",
		clk_get_rate(data->ddr_clk) / KHZ_TO_HZ);

	return size;
}

static ssize_t ddr_freq_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);
	return sprintf(buf, "current ddr freq is: %lu\n",
		 clk_get_rate(data->ddr_clk) / KHZ_TO_HZ);
}

/* debug interface to enable/disable perf counter during AP suspend */
static ssize_t stop_perf_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;
	int is_stopped;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);

	if (0x1 != sscanf(buf, "%d", &is_stopped)) {
		dev_err(dev, "<ERR> wrong parameter\n");
		return -E2BIG;
	}

	is_stopped = !!is_stopped;
	if (is_stopped == atomic_read(&data->is_stopped)) {
		dev_info(dev, "perf counter has been already %s in suspend\n",
			atomic_read(&data->is_stopped) ? "off" : "on");
		return size;
	}

	if (is_stopped)
		atomic_inc(&data->is_stopped);
	else
		atomic_dec(&data->is_stopped);

	dev_info(dev, "perf counter is %s from debug interface!\n",
		atomic_read(&data->is_stopped) ? "off" : "on");
	return size;
}

static ssize_t stop_perf_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);
	return sprintf(buf, "perf counter is_stopped = %d\n",
		 atomic_read(&data->is_stopped));
}

static struct ddr_devfreq_data *ddrfreq_data;

/* used to collect ddr cnt during 20ms */
int ddr_profiling_show(struct clk_dc_stat_info *dc_stat_info)
{
	struct ddr_devfreq_data *data;
	struct perf_counters *ddr_ticks, *ddr_ticks_base, *ddr_ticks_diff;
	struct devfreq_frequency_table *tbl;
	int i, j, k, len = 0;
	unsigned long flags;
	unsigned int ver;
	unsigned int glob_ratio, idle_ratio, busy_ratio, data_ratio, util_ratio;
	unsigned int tmp_total, tmp_rw_cmd, tmp_no_util, tmp_busy;
	unsigned int tmp_data_cycle, cnttime_ms, cnttime_ms_ddr;
	u64 glob_ticks;

	tbl = devfreq_frequency_get_table(DEVFREQ_DDR);

	data = ddrfreq_data;
	ddr_ticks = data->dmc.ddr_ticks;
	ddr_ticks_base = data->ddr_stats.ddr_ticks_base;
	ddr_ticks_diff = data->ddr_stats.ddr_ticks_diff;
	ver = data->dmc.version;
	idle_ratio = busy_ratio = data_ratio = util_ratio = 0;

	/* If ddr stat is working, need get latest data */
	if (data->ddr_stats.is_ddr_stats_working) {
		getnstimeofday(&data->stop_ts);
		ddr_perf_cnt_update(data, 0, 1);
		spin_lock_irqsave(&data->lock, flags);
		for (i = 0; i < data->ddr_freq_tbl_len; i++)
			for (j = 0; j < data->dmc.pmucnt_in_use; j++)
				ddr_ticks_diff[i].reg[j] =
					ddr_ticks[i].reg[j] -
					ddr_ticks_base[i].reg[j];
		spin_unlock_irqrestore(&data->lock, flags);
	}
	cnttime_ms = (data->stop_ts.tv_sec - data->start_ts.tv_sec) * MSEC_PER_SEC +
		(data->stop_ts.tv_nsec - data->start_ts.tv_nsec) / NSEC_PER_MSEC;


	cnttime_ms_ddr = 0;
	for (i = 0; i < data->ddr_freq_tbl_len; i++) {
		cnttime_ms_ddr += div_u64(ddr_ticks_diff[i].reg[1],
				ddr_index2_rate(data, i));
	}

	/* ddr duty cycle show */
	glob_ticks = 0;

	spin_lock_irqsave(&data->lock, flags);

	for (i = 0; i < data->ddr_freq_tbl_len; i++)
		glob_ticks += ddr_ticks_diff[i].reg[1];

	k = 0;
	while ((glob_ticks >> k) > 0x7FFF)
		k++;

	for (i = 0; i < data->ddr_freq_tbl_len; i++) {
		if ((u32)(glob_ticks >> k) != 0)
			glob_ratio = (u32)(ddr_ticks_diff[i].reg[1] >> k)
				* 100000 / (u32)(glob_ticks >> k) + 5;
		else
			glob_ratio = 0;

		j = 0;
		while ((ddr_ticks_diff[i].reg[1] >> j) > 0x7FFF)
			j++;

		tmp_total = ddr_ticks_diff[i].reg[1] >> j;
		tmp_rw_cmd = ddr_ticks_diff[i].reg[2] >> j;

		if (ver == MCK4)
			tmp_no_util = ddr_ticks_diff[i].reg[3] >> j;
		else if (ver == MCK5)
			tmp_busy = ddr_ticks_diff[i].reg[3] >> j;
		else
			/* this should never happen */
			BUG_ON(1);

		if (tmp_total != 0) {
			/* Sanity check: clock driver should pass 0 or 1 for 4x mode enable */
			BUG_ON((tbl[i].mode_4x_en != 0) && (tbl[i].mode_4x_en != 1));
			tmp_data_cycle = tmp_rw_cmd * data->bst_len / (2 << tbl[i].mode_4x_en);

			data_ratio = tmp_data_cycle * 100000 / tmp_total + 5;

			if (ver == MCK4) {
				busy_ratio = (tmp_data_cycle + tmp_no_util)
					* 100000 / tmp_total + 5;

				idle_ratio = (tmp_total - tmp_data_cycle
					- tmp_no_util) * 100000 / tmp_total + 5;

				util_ratio = tmp_data_cycle * 100000
					/ (tmp_data_cycle + tmp_no_util) + 5;
			} else if (ver == MCK5) {
				busy_ratio = tmp_busy * 100000 / tmp_total + 5;

				idle_ratio = (tmp_total - tmp_busy)
					* 100000 / tmp_total + 5;

				util_ratio = tmp_data_cycle * 100000
					/ tmp_busy + 5;
			}
		} else {
			idle_ratio = 0;
			busy_ratio = 0;
			data_ratio = 0;
			util_ratio = 0;
		}

		dc_stat_info->ops_dcstat[i].ddr_glob_ratio = glob_ratio;
		dc_stat_info->ops_dcstat[i].ddr_idle_ratio = idle_ratio;
		dc_stat_info->ops_dcstat[i].ddr_busy_ratio = busy_ratio;
		dc_stat_info->ops_dcstat[i].ddr_data_ratio = data_ratio;
		dc_stat_info->ops_dcstat[i].ddr_util_ratio = util_ratio;
	}
	spin_unlock_irqrestore(&data->lock, flags);

	return len;
}

/* used to collect ddr cnt during a time */
int ddr_profiling_store(int start)
{
	struct ddr_devfreq_data *data;
	unsigned int cap_flag, i, j;
	unsigned long flags;
	struct perf_counters *ddr_ticks_base;
	struct perf_counters *ddr_ticks_diff;

	data = ddrfreq_data;
	ddr_ticks_base = data->ddr_stats.ddr_ticks_base;
	ddr_ticks_diff = data->ddr_stats.ddr_ticks_diff;

	cap_flag = start;

	if (cap_flag == 1) {
		ddr_perf_cnt_update(data, 0, 1);
		spin_lock_irqsave(&data->lock, flags);
		for (i = 0; i < data->ddr_freq_tbl_len; i++) {
			memcpy(ddr_ticks_base[i].reg,
					data->dmc.ddr_ticks[i].reg,
					sizeof(u64) * data->dmc.pmucnt_in_use);
		}
		spin_unlock_irqrestore(&data->lock, flags);
		getnstimeofday(&data->start_ts);
		data->ddr_stats.is_ddr_stats_working = 1;
	} else if (cap_flag == 0 && data->ddr_stats.is_ddr_stats_working == 1) {
		data->ddr_stats.is_ddr_stats_working = 0;
		getnstimeofday(&data->stop_ts);
		ddr_perf_cnt_update(data, 0, 1);
		/* When stop ddr stats, get a snapshot of current result */
		spin_lock_irqsave(&data->lock, flags);
		for (i = 0; i < data->ddr_freq_tbl_len; i++)
			for (j = 0; j < data->dmc.pmucnt_in_use; j++)
				ddr_ticks_diff[i].reg[j] =
					data->dmc.ddr_ticks[i].reg[j] -
					ddr_ticks_base[i].reg[j];
		spin_unlock_irqrestore(&data->lock, flags);
	}

	return 0;
}

static struct pm_qos_request ddrfreq_qos_boot_max;
static struct pm_qos_request ddrfreq_qos_boot_min;

static DEVICE_ATTR(stop_perf_in_suspend, S_IRUGO | S_IWUSR,
		stop_perf_show, stop_perf_store);
static DEVICE_ATTR(disable_ddr_fc, S_IRUGO | S_IWUSR,
		disable_show, disable_store);
static DEVICE_ATTR(ddr_freq, S_IRUGO | S_IWUSR,
		ddr_freq_show, ddr_freq_store);

/*
 * Overflow interrupt handler
 * Basing on DE's suggestion, the flow to clear interrutp is:
 * 1. Disable interrupt.
 * 2. Read interrupt status to clear it.
 * 3. Enable interrupt again.
 * But DE also suggest to clear overflow flag here. By confirming, the only
 * side effect not to clear the flag is the next overflow event, no matter
 * same event triggering the interrupt or not, will not trigger interrupt
 * again. Since the work will check all overflow events and clear, there
 * will be no issue not to clear the overflow event on top half.
 */
static irqreturn_t ddrc_overflow_handler(int irq, void *dev_id)
{
	struct ddr_devfreq_data *data = dev_id;
	void *mc_base = (void *)data->dmc.hw_base;
	struct mck_pmu_regs_offset *regs = &data->dmc.mck_regs;
	unsigned int ver = data->dmc.version;
	u32 int_flag;

	/*
	 * Step1: Write to SDRAM Interrupt Enable Register to disable
	 * interrupt
	 */
	write_static_register(0x0, 0x0, mc_base + regs->intr_en, ver);
	/* Step2: Read SDRAM Interrupt Status Register to clear interrupt */
	int_flag = read_static_register(mc_base + regs->intr_stat, ver) & 0x1;
	if (!int_flag) {
		pr_err("No pended MC interrupt when handling it.\n"
				"This should not happen.\n");
		BUG();
	}
	/*
	 * Step3: Write to SDRAM Interrupt Enable Register to enable
	 * interrupt again
	 */
	write_static_register(0x1, 0x1, mc_base + regs->intr_en, ver);

	schedule_work(&data->overflow_work);

	return IRQ_HANDLED;
}

/*
 * Queued work for overflow interrupt.
 * When update, the overflow flag will be checked and cleared.
 */
static void ddrc_overflow_worker(struct work_struct *work)
{
	struct ddr_devfreq_data *data = container_of(work,
			struct ddr_devfreq_data, overflow_work);
	u32 overflow_flag;
	void *mc_base = (void *)data->dmc.hw_base;
	struct mck_pmu_regs_offset *regs = &data->dmc.mck_regs;
	unsigned int ver = data->dmc.version;

	/* Check if there is unexpected behavior */
	overflow_flag = read_static_register(mc_base + regs->cnt_stat, ver)
		& 0xf;
	if (!overflow_flag) {
		if (ver == MCK4) {
			pr_err("No overflag pended when interrupt happen.\n"
				"This should not happen.\n");
			BUG();
		} else if (ver == MCK5) {
			pr_warn("No overflag pended when interrupt happen.\n"
				"This should rarely happen.\n");
		} else
			/* this should never happen */
			BUG_ON(1);
	}

	/* update stat and clear overflow flag */
	ddr_perf_cnt_update(data, 1, 1);
}

#ifdef CONFIG_DEVFREQ_GOV_THROUGHPUT
/**
 * qos_max_upthrd_notifier_call() - It is called when kernel driver has constraints
 */
static int qos_max_upthrd_notifier_call(struct notifier_block *nb,
					unsigned long value, void *devp)
{
	struct devfreq_throughput_data *ddr_throughput_data;
	struct ddr_devfreq_data *ddr_devfreq_data;
	struct devfreq *devfreq;
	unsigned int upthrd;
	int ret, i;

	ddr_throughput_data = &devfreq_throughput_data;
	ddr_devfreq_data = ddrfreq_driver_data;
	devfreq = ddr_devfreq_data->devfreq;

	upthrd = (unsigned int)value;

	mutex_lock(&devfreq->lock);

	if (upthrd > ddr_throughput_data->downdifferential) {
		ddr_devfreq_data->qos_max_upthrd = upthrd;
		for (i = 0; i < ddr_throughput_data->table_len; i++) {
			ddr_throughput_data->throughput_table[i].up =
				upthrd * ddr_throughput_data->freq_table[i] / 100;
			ddr_throughput_data->throughput_table[i].down =
				(upthrd - ddr_throughput_data->downdifferential)
				* ddr_throughput_data->freq_table[i] / 100;
		}
		ret = update_devfreq(devfreq);
	} else
		ret = 0;

	mutex_unlock(&devfreq->lock);

	return ret;
}

static ssize_t upthrd_usr_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", devfreq_throughput_data.upthreshold);
}

static ssize_t upthrd_usr_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct ddr_devfreq_data *ddr_devfreq_data = ddrfreq_driver_data;
	unsigned long upthrd_usr;
	int ret;

	ret = sscanf(buf, "%lu", &upthrd_usr);
	if ((upthrd_usr >= 100) || (ret != 1)) {
		pr_err("<ERR> wrong parameter.\n");
		pr_err("echo upthrd(0~100) > upthrd_usr\n");
		pr_err("For example: echo 30 > upthrd_usr\n");
		return -EINVAL;
	}

	devfreq_throughput_data.upthreshold = upthrd_usr;

	pm_qos_update_request(&ddr_devfreq_data->qos_req_upthrd_max, upthrd_usr);

	return count;
}

static struct kobj_attribute upthrd_usr_attr =
	__ATTR(upthrd_usr, 0644, upthrd_usr_show, upthrd_usr_store);

static ssize_t upthrd_downdiff_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", devfreq_throughput_data.downdifferential);
}

static ssize_t upthrd_downdiff_store(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct devfreq_throughput_data *ddr_throughput_data;
	struct ddr_devfreq_data *ddr_devfreq_data;
	struct devfreq *devfreq;
	struct pm_qos_object *qos_upthrd_max;
	unsigned int upthrd_downdiff;
	s32 target_upthrd_max = 0;

	ddr_throughput_data = &devfreq_throughput_data;
	ddr_devfreq_data = ddrfreq_driver_data;
	devfreq = ddr_devfreq_data->devfreq;

	qos_upthrd_max = pm_qos_array[PM_QOS_DDR_DEVFREQ_UPTHRD_MAX];
	target_upthrd_max = pm_qos_read_value(qos_upthrd_max->constraints);

	if (0x1 != sscanf(buf, "%u", &upthrd_downdiff)) {
		pr_err("%s: <ERR> wrong parameter\n", __func__);
		return -E2BIG;
	}

	if (upthrd_downdiff < target_upthrd_max) {
		ddr_throughput_data->downdifferential = upthrd_downdiff;
		mutex_lock(&devfreq->lock);
		__update_dev_upthreshold(target_upthrd_max, ddr_throughput_data);
		update_devfreq(devfreq);
		mutex_unlock(&devfreq->lock);
	} else
		pr_err("%s: <ERR> Value is bigger than up threshold.\n", __func__);

	return count;
}

static struct kobj_attribute upthrd_downdiff_attr =
	__ATTR(upthrd_downdiff, 0644, upthrd_downdiff_show,
	upthrd_downdiff_store);
#endif /* CONFIG_DEVFREQ_GOV_THROUGHPUT */

static int ddr_devfreq_probe(struct platform_device *pdev)
{
	int i = 0, res;
	int ret = 0;
	struct device *dev = &pdev->dev;
	struct ddr_devfreq_data *data = NULL;
	struct devfreq_frequency_table *tbl;
	unsigned int reg_info[2];
	unsigned int freq_qos = 0;
	unsigned int tmp, ver, pmucnt_in_use;
	struct resource *irqres;

	data = devm_kzalloc(dev, sizeof(struct ddr_devfreq_data), GFP_KERNEL);
	if (data == NULL) {
		dev_err(dev, "Cannot allocate memory for devfreq data.\n");
		return -ENOMEM;
	}

	data->ddr_clk = devm_clk_get(dev, NULL);
	if (IS_ERR(data->ddr_clk)) {
		dev_err(dev, "Cannot get clk ptr.\n");
		return PTR_ERR(data->ddr_clk);
	}

	if (IS_ENABLED(CONFIG_OF)) {
		if (of_property_read_u32_array(pdev->dev.of_node,
					       "reg", reg_info, 2)) {
			dev_err(dev, "Failed to get register info\n");
			return -ENODATA;
		}
	} else {
		reg_info[0] = DEFAULT_MCK_BASE_ADDR;
		reg_info[1] = DEFAULT_MCK_REG_SIZE;
	}

	data->dmc.hw_base = ioremap(reg_info[0], reg_info[1]);

	/* read MCK controller version */
	data->dmc.version = MCK_UNKNOWN;

	tmp = readl(data->dmc.hw_base);

	ver = (tmp & MCK5_VER_MASK) >> MCK5_VER_SHIFT;
	if (ver == MCK5) {
		data->dmc.version = ver;
		data->dmc.pmucnt_in_use = DEFAULT_PERCNT_IN_USE;
	} else {
		ver = (tmp & MCK4_VER_MASK) >> MCK4_VER_SHIFT;
		if (ver == MCK4) {
			data->dmc.version = ver;
			data->dmc.pmucnt_in_use = DEFAULT_PERCNT_IN_USE;
		}
	}

	if (data->dmc.version == MCK_UNKNOWN) {
		dev_err(dev, "Unsupported mck version!\n");
		return -EINVAL;
	}
	dev_info(dev, "mck%d controller is detected!\n", ver);

	configure_mck_pmu_regs(data);

	/* get ddr burst length */
	if (data->dmc.version == MCK4) {
		data->bst_len = 1 << ((read_static_register(data->dmc.hw_base +
			MCK4_SDRAM_CTRL4, ver) & MCK4_SDRAM_CTRL4_BL_MASK)
			>> MCK4_SDRAM_CTRL4_BL_SHIFT);
	} else if (data->dmc.version == MCK5) {
		data->bst_len = 1 << ((read_static_register(data->dmc.hw_base +
			MCK5_CH0_SDRAM_CFG1, ver) & MCK5_CH0_SDRAM_CFG1_BL_MASK)
			>> MCK5_CH0_SDRAM_CFG1_BL_SHIFT);
	}
	dev_info(dev, "ddr burst length = %d\n", data->bst_len);

	/* save ddr frequency tbl */
	i = 0;
	tbl = devfreq_frequency_get_table(DEVFREQ_DDR);
	if (tbl) {
		while (tbl->frequency != DEVFREQ_TABLE_END) {
			data->ddr_freq_tbl[i] = tbl->frequency;
			tbl++;
			i++;
		}
		data->ddr_freq_tbl_len = i;
	}

	ddr_devfreq_profile.initial_freq =
		clk_get_rate(data->ddr_clk) / KHZ_TO_HZ;

	/* set the frequency table of devfreq profile */
	if (data->ddr_freq_tbl_len) {
		ddr_devfreq_profile.freq_table = data->ddr_freq_tbl;
		ddr_devfreq_profile.max_state = data->ddr_freq_tbl_len;
		for (i = 0; i < data->ddr_freq_tbl_len; i++)
			dev_pm_opp_add(dev, data->ddr_freq_tbl[i], 1000);
	}

	/* allocate memory for performnace counter related arrays */
	pmucnt_in_use = data->dmc.pmucnt_in_use;
	for (i = 0; i < data->ddr_freq_tbl_len; i++) {
		data->dmc.ddr_ticks[i].reg = devm_kzalloc(dev,
			sizeof(u64) * pmucnt_in_use, GFP_KERNEL);
		if (data->dmc.ddr_ticks[i].reg == NULL) {
			dev_err(dev, "Cannot allocate memory for perf_cnt.\n");
			return -ENOMEM;
		}
		data->ddr_stats.ddr_ticks_base[i].reg = devm_kzalloc(dev,
			sizeof(u64) * pmucnt_in_use, GFP_KERNEL);
		if (data->ddr_stats.ddr_ticks_base[i].reg == NULL) {
			dev_err(dev, "Cannot allocate memory for ddr_stats.\n");
			return -ENOMEM;
		}
		data->ddr_stats.ddr_ticks_diff[i].reg = devm_kzalloc(dev,
			sizeof(u64) * pmucnt_in_use, GFP_KERNEL);
		if (data->ddr_stats.ddr_ticks_diff[i].reg == NULL) {
			dev_err(dev, "Cannot allocate memory for ddr_stats.\n");
			return -ENOMEM;
		}
	}

	irqres = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!irqres)
		return -ENODEV;
	data->irq = irqres->start;
	ret = request_irq(data->irq, ddrc_overflow_handler, 0, dev_name(dev),
			data);
	if (ret) {
		dev_err(dev, "Cannot request irq for MC!\n");
		return -ENODEV;
	}
	INIT_WORK(&data->overflow_work, ddrc_overflow_worker);

	/*
	 * Initilize the devfreq QoS if freq-qos flag is enabled.
	 * By default, the flag is disabled.
	 */
	freq_qos = 0;

	if (IS_ENABLED(CONFIG_OF)) {
		if (of_property_read_bool(pdev->dev.of_node, "marvell,qos"))
			freq_qos = 1;
	}

	if (freq_qos) {
		ddr_devfreq_profile.min_qos_type = PM_QOS_DDR_DEVFREQ_MIN;
		ddr_devfreq_profile.max_qos_type = PM_QOS_DDR_DEVFREQ_MAX;
	}
	/* by default, disable performance counter when AP enters suspend */
	atomic_set(&data->is_stopped, 1);

#ifdef CONFIG_DEVFREQ_GOV_THROUGHPUT
	devfreq_throughput_data.freq_table = data->ddr_freq_tbl;
	devfreq_throughput_data.table_len = data->ddr_freq_tbl_len;

	devfreq_throughput_data.throughput_table =
		kzalloc(devfreq_throughput_data.table_len
			* sizeof(struct throughput_threshold), GFP_KERNEL);
	if (NULL == devfreq_throughput_data.throughput_table) {
		dev_err(dev,
			"Cannot allocate memory for throughput table\n");
		return -ENOMEM;
	}

	for (i = 0; i < devfreq_throughput_data.table_len; i++) {
		devfreq_throughput_data.throughput_table[i].up =
		   devfreq_throughput_data.upthreshold
		   * devfreq_throughput_data.freq_table[i] / 100;
		devfreq_throughput_data.throughput_table[i].down =
		   (devfreq_throughput_data.upthreshold
		   - devfreq_throughput_data.downdifferential)
		   * devfreq_throughput_data.freq_table[i] / 100;
	}
#endif /* CONFIG_DEVFREQ_GOV_THROUGHPUT */

	spin_lock_init(&data->lock);

	data->devfreq = devfreq_add_device(&pdev->dev, &ddr_devfreq_profile,
				"throughput", &devfreq_throughput_data);
	if (IS_ERR(data->devfreq)) {
		dev_err(dev, "devfreq add error !\n");
		ret =  (unsigned long)data->devfreq;
		goto err_devfreq_add;
	}

	ddrfreq_data = data;

	/* init default devfreq min_freq and max_freq */
	data->devfreq->min_freq = data->devfreq->qos_min_freq =
		data->ddr_freq_tbl[0];
	data->devfreq->max_freq = data->devfreq->qos_max_freq =
		data->ddr_freq_tbl[data->ddr_freq_tbl_len - 1];
	data->last_polled_at = jiffies;

	res = device_create_file(&pdev->dev, &dev_attr_disable_ddr_fc);
	if (res) {
		dev_err(dev,
			"device attr disable_ddr_fc create fail: %d\n", res);
		ret = -ENOENT;
		goto err_file_create0;
	}

	res = device_create_file(&pdev->dev, &dev_attr_ddr_freq);
	if (res) {
		dev_err(dev, "device attr ddr_freq create fail: %d\n", res);
		ret = -ENOENT;
		goto err_file_create1;
	}

	res = device_create_file(&pdev->dev, &dev_attr_stop_perf_in_suspend);
	if (res) {
		dev_err(dev,
			"device attr stop_perf_in_suspend create fail: %d\n", res);
		ret = -ENOENT;
		goto err_file_create2;
	}

	platform_set_drvdata(pdev, data);
	ddr_perf_cnt_init(data);

#ifdef CONFIG_DEVFREQ_GOV_THROUGHPUT
	ddrfreq_driver_data = data;

	res = sysfs_create_file(ddr_upthrd_obj, &upthrd_usr_attr.attr);
	if (res) {
		dev_err(dev, "sysfs attr upthrd_usr create fail: %d\n", res);
		ret = -ENOENT;
		goto err_file_create3;
	}

	res = sysfs_create_file(ddr_upthrd_obj, &upthrd_downdiff_attr.attr);
	if (res) {
		dev_err(dev, "sysfs attr upthrd_downdiff create fail: %d\n", res);
		ret = -ENOENT;
		goto err_file_create4;
	}

	data->max_upthrd_qos_type = PM_QOS_DDR_DEVFREQ_UPTHRD_MAX;
	data->qos_max_upthrd_nb.notifier_call = qos_max_upthrd_notifier_call;
	pm_qos_add_notifier(data->max_upthrd_qos_type, &data->qos_max_upthrd_nb);

	data->qos_req_upthrd_max.name = "userspace";
	pm_qos_add_request(&data->qos_req_upthrd_max, data->max_upthrd_qos_type,
			devfreq_throughput_data.upthreshold);
#endif /* CONFIG_DEVFREQ_GOV_THROUGHPUT */

	if (ddr_max) {
		tmp = data->ddr_freq_tbl[data->ddr_freq_tbl_len - 1];
		for (i = 1; i < data->ddr_freq_tbl_len; i++)
			if ((data->ddr_freq_tbl[i - 1] <= ddr_max) &&
				(data->ddr_freq_tbl[i] > ddr_max)) {
				tmp = data->ddr_freq_tbl[i - 1];
				break;
			}

		ddrfreq_qos_boot_max.name = "boot_ddr_max";
		pm_qos_add_request(&ddrfreq_qos_boot_max,
			PM_QOS_DDR_DEVFREQ_MAX, tmp);
	}

	if (ddr_min) {
		tmp = data->ddr_freq_tbl[0];
		for (i = 1; i < data->ddr_freq_tbl_len + 1; i++)
			if (data->ddr_freq_tbl[i - 1] >= ddr_min) {
				tmp = data->ddr_freq_tbl[i - 1];
				break;
			}

		ddrfreq_qos_boot_min.name = "boot_ddr_min";
		pm_qos_add_request(&ddrfreq_qos_boot_min,
			PM_QOS_DDR_DEVFREQ_MIN, tmp);
	}

	return 0;

#ifdef CONFIG_DEVFREQ_GOV_THROUGHPUT
err_file_create4:
	sysfs_remove_file(ddr_upthrd_obj, &upthrd_usr_attr.attr);
#endif /* CONFIG_DEVFREQ_GOV_THROUGHPUT */

err_file_create3:
	device_remove_file(&pdev->dev, &dev_attr_stop_perf_in_suspend);
err_file_create2:
	device_remove_file(&pdev->dev, &dev_attr_ddr_freq);
err_file_create1:
	device_remove_file(&pdev->dev, &dev_attr_disable_ddr_fc);
err_file_create0:
	devfreq_remove_device(data->devfreq);
err_devfreq_add:

#ifdef CONFIG_DEVFREQ_GOV_THROUGHPUT
	kfree(devfreq_throughput_data.throughput_table);
#endif /* CONFIG_DEVFREQ_GOV_THROUGHPUT */

	free_irq(data->irq, data);

	return ret;
}

static int ddr_devfreq_remove(struct platform_device *pdev)
{
	struct ddr_devfreq_data *data = platform_get_drvdata(pdev);

	device_remove_file(&pdev->dev, &dev_attr_disable_ddr_fc);
	device_remove_file(&pdev->dev, &dev_attr_ddr_freq);
	device_remove_file(&pdev->dev, &dev_attr_stop_perf_in_suspend);

#ifdef CONFIG_DEVFREQ_GOV_THROUGHPUT
	if (data->max_upthrd_qos_type)
		pm_qos_remove_notifier(data->max_upthrd_qos_type,
			&data->qos_max_upthrd_nb);
	sysfs_remove_file(ddr_upthrd_obj, &upthrd_usr_attr.attr);
	sysfs_remove_file(ddr_upthrd_obj, &upthrd_downdiff_attr.attr);
	kfree(devfreq_throughput_data.throughput_table);
#endif /* CONFIG_DEVFREQ_GOV_THROUGHPUT */

	devfreq_remove_device(data->devfreq);

	free_irq(data->irq, data);
	cancel_work_sync(&data->overflow_work);

	return 0;
}

static const struct of_device_id devfreq_ddr_dt_match[] = {
	{.compatible = "marvell,devfreq-ddr" },
	{},
};
MODULE_DEVICE_TABLE(of, devfreq_ddr_dt_match);

#ifdef CONFIG_PM
static unsigned long saved_ddrclk;
static int mck_suspend(struct device *dev)
{
	struct list_head *list_min;
	struct plist_node *node;
	struct pm_qos_request *req;
	unsigned int qos_min, i = 0;
	unsigned long new_ddrclk, dip_request = 0;
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;
	unsigned long flags;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);

	new_ddrclk = data->ddr_freq_tbl[0];

	mutex_lock(&data->devfreq->lock);

	/* scaling to the min frequency before entering suspend */
	saved_ddrclk = clk_get_rate(data->ddr_clk) / KHZ_TO_HZ;
	qos_min = (unsigned int)pm_qos_request(PM_QOS_DDR_DEVFREQ_MIN);
	list_min = &pm_qos_array[PM_QOS_DDR_DEVFREQ_MIN]
			->constraints->list.node_list;
	list_for_each_entry(node, list_min, node_list) {
		req = container_of(node, struct pm_qos_request, node);
		if (req->name && !strcmp(req->name, "dip_ddr_min") &&
			(node->prio > data->ddr_freq_tbl[0])) {
			dev_info(dev, "%s request min qos\n",
				req->name);
			dip_request = 1;
			break;
		}
	}

	/* if dip request QOS min, set rate as dip request */
	if (dip_request) {
		do {
			if (node->prio == data->ddr_freq_tbl[i]) {
				new_ddrclk = data->ddr_freq_tbl[i];
				break;
			}
			i++;
		} while (i < data->ddr_freq_tbl_len);

		if (i == data->ddr_freq_tbl_len)
			dev_err(dev, "DDR qos value is wrong!\n");
	}

	ddr_set_rate(data, new_ddrclk);
	dev_info(dev, "Change ddr freq to lowest value. (cur: %luKhz)\n",
		clk_get_rate(data->ddr_clk) / KHZ_TO_HZ);

	if (atomic_read(&data->is_stopped)) {
		dev_dbg(dev, "disable perf_counter before suspend!\n");
		spin_lock_irqsave(&data->lock, flags);
		stop_ddr_performance_counter(data);
		spin_unlock_irqrestore(&data->lock, flags);
	}

	mutex_unlock(&data->devfreq->lock);

	return 0;
}

static int mck_resume(struct device *dev)
{
	struct platform_device *pdev;
	struct ddr_devfreq_data *data;
	unsigned long flags;

	pdev = container_of(dev, struct platform_device, dev);
	data = platform_get_drvdata(pdev);

	mutex_lock(&data->devfreq->lock);

	if (atomic_read(&data->is_stopped)) {
		dev_dbg(dev, "restart perf_counter after resume!\n");
		spin_lock_irqsave(&data->lock, flags);
		start_ddr_performance_counter(data);
		spin_unlock_irqrestore(&data->lock, flags);
	}

	/* scaling to saved frequency after exiting suspend */
	ddr_set_rate(data, saved_ddrclk);
	dev_info(dev, "Change ddr freq to saved value. (cur: %luKhz)\n",
		clk_get_rate(data->ddr_clk) / KHZ_TO_HZ);
	mutex_unlock(&data->devfreq->lock);
	return 0;
}

static const struct dev_pm_ops mck_pm_ops = {
	.suspend	= mck_suspend,
	.resume		= mck_resume,
};
#endif

static struct platform_driver ddr_devfreq_driver = {
	.probe = ddr_devfreq_probe,
	.remove = ddr_devfreq_remove,
	.driver = {
		.name = "devfreq-ddr",
		.of_match_table = of_match_ptr(devfreq_ddr_dt_match),
		.owner = THIS_MODULE,
#ifdef CONFIG_PM
		.pm	= &mck_pm_ops,
#endif
	},
};

static int __init ddr_devfreq_init(void)
{
	return platform_driver_register(&ddr_devfreq_driver);
}
fs_initcall(ddr_devfreq_init);

static void __exit ddr_devfreq_exit(void)
{
	platform_driver_unregister(&ddr_devfreq_driver);
}
module_exit(ddr_devfreq_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("mck memorybus devfreq driver");
