/*
 * pxa1936_thermal.c - Marvell pxa1936 TMU (Thermal Management Unit)
 *
 * Author:      Liang Chen <chl@marvell.com>
 * Copyright:   (C) 2014 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/module.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/clk.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/thermal.h>
#include <linux/of.h>
#ifdef CONFIG_CPU_FREQ
#include <linux/cpufreq.h>
#include <linux/cpu_cooling.h>
#endif
#include <linux/cooling_dev_mrvl.h>
#include <linux/delay.h>
#include <linux/cpu.h>
#include <linux/pm_qos.h>
#include <linux/cputype.h>
#include <linux/uaccess.h>

#include <linux/devfreq.h>
#include <linux/debugfs.h>
#include "voltage_mrvl.h"


#define APB_CLK_BASE (0xd4015000)
#define TSEN_PCTRL (0x0)
#define TSEN_LCTRL (0x4)
#define TSEN_PSTATUS (0x8)
#define TSEN_LSTATUS (0xC)
#define TSEN_RSTATUS (0x10)
#define TSEN_THD01 (0x14)
#define TSEN_THD23 (0x18)

/* TSEN_PCTRL */
#define TSEN_ISO_EN (1 << 3)
#define TSEN_EN (1 << 2)
#define TSEN_START (1 << 1)
#define TSEN_RESET (1 << 0)
/* TSEN_LCTRL */
#define TSEN_AUTO_INTERVAL_OFF (16)
#define TSEN_AUTO_INTERVAL_MASK (0xffff0000)
#define TSEN_RDY_INT_ENABLE (1 << 11)
#define TSEN_WDT_DIRECTION (1 << 9)
#define TSEN_WDT_ENABLE (1 << 8)
#define TSEN_INT2_DIRECTION (1 << 7)
#define TSEN_INT2_ENABLE (1 << 6)
#define TSEN_INT1_DIRECTION (1 << 5)
#define TSEN_INT1_ENABLE (1 << 4)
#define TSEN_INT0_DIRECTION (1 << 3)
#define TSEN_INT0_ENABLE (1 << 2)
#define TSEN_AUTO_MODE_OFF (0)
#define TSEN_AUTO_MODE_MASK (0x3)
/* TSEN_LSTATUS */
#define TSEN_INT2 (1 << 15)
#define TSEN_INT1 (1 << 14)
#define TSEN_INT0 (1 << 13)
#define TSEN_RDY_INT (1 << 12)
#define TSEN_DATA_LATCHED_OFF (0)
#define TSEN_DATA_LATCHED_MASK (0xfff)
/* TSEN_RSTATUS */
#define TSEN_WDT_FLAG (1 << 12)
#define TSEN_DATA_WDT_OFF (0)
#define TSEN_DATA_WDT_MASK (0xfff)
/* TSEN_THD01 */
#define TSEN_THD0_OFF (0)
#define TSEN_THD0_MASK (0xfff)
#define TSEN_THD1_OFF (12)
#define TSEN_THD1_MASK (0xfff000)
/* TSEN_THD23 */
#define TSEN_THD2_OFF (0)
#define TSEN_THD2_MASK (0xfff)
#define TSEN_WDT_THD_OFF (12)
#define TSEN_WDT_THD_MASK (0xfff000)

#define reg_read(off) readl(thermal_dev.base + (off))
#define reg_write(val, off) writel((val), thermal_dev.base + (off))
#define reg_clr_set(off, clr, set) \
	reg_write(((reg_read(off) & ~(clr)) | (set)), off)

unsigned int pxa_tsen_throttle_tbl[][THROTTLE_NUM][THERMAL_MAX_TRIPS+1] = {
	[POWER_SAVING_MODE] = {
		[THROTTLE_VL]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_CORE]		= { 1,
		0, 0, 2, 2, 3, 4, 4, 5, 5, 5,
		},
		[THROTTLE_CORE1]	= { 1,
		0, 0, 0, 1, 2, 2, 3, 4, 5, 6,
		},
		[THROTTLE_HOTPLUG]	= { 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_DDR]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_GC3D]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_GC2D]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_GCSH]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_VPU]	= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
	},
	[BENCHMARK_MODE] = {
		[THROTTLE_VL]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_CORE]		= { 1,
		0, 0, 2, 2, 3, 4, 4, 5, 5, 5,
		},
		[THROTTLE_CORE1]	= { 1,
		0, 0, 0, 1, 2, 2, 3, 4, 5, 6,
		},
		[THROTTLE_HOTPLUG]	= { 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_DDR]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_GC3D]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_GC2D]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_GCSH]		= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
		[THROTTLE_VPU]	= { 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		},
	},
};

enum trip_points {
	TRIP_POINT_0,
	TRIP_POINT_1,
	TRIP_POINT_2,
	TRIP_POINT_3,
	TRIP_POINT_4,
	TRIP_POINT_5,
	TRIP_POINT_6,
	TRIP_POINT_7,
	TRIP_POINT_8,
	TRIP_POINT_9,
	TRIP_POINTS_NUM,
	TRIP_POINTS_ACTIVE_NUM = TRIP_POINTS_NUM - 1,
};

struct cooling_device {
	struct thermal_cooling_device *combile_cool;
	int max_state, cur_state;
	struct thermal_cooling_device *cool_cpu_cluster0_freq;
	struct thermal_cooling_device *cool_cpu_cluster1_freq;
	unsigned long cpufreq_cstate[THERMAL_MAX_TRIPS];
	struct thermal_cooling_device *cool_cpuhotplug;
	unsigned long hotplug_cstate[THERMAL_MAX_TRIPS];
	struct thermal_cooling_device *cool_gc2dfreq;
	struct thermal_cooling_device *cool_gc3dfreq;
	struct thermal_cooling_device *cool_gcshfreq;
};

struct pxa28nm_thermal_device {
	struct thermal_zone_device *therm_cpu;
	struct thermal_zone_device *therm_gc;
	int trip_range;
	struct resource *mem;
	void __iomem *base;
	struct clk *therm_clk;
	struct cooling_device cdev;
	struct cooling_device gdev;
	int hit_trip_cnt[TRIP_POINTS_NUM];
	int irq;
	int ttemp_table[3/*2.0G,1.8G,1.5G*/][4];
	int cpu_num;
	int temp_max;
	struct tsen_cooling_device maxdev;
	struct pxa_voltage_thermal thermal_volt;
};

static struct pxa28nm_thermal_device thermal_dev;

static int trips_temp_benchmark[TRIP_POINTS_NUM] = {
	78000, /* TRIP_POINT_0 */
	79000, /* TRIP_POINT_1 */
	80000, /* TRIP_POINT_2 */
	81000, /* TRIP_POINT_3 */
	82000, /* TRIP_POINT_4 */
	83000, /* TRIP_POINT_5 */
	84000, /* TRIP_POINT_6 */
	85000, /* TRIP_POINT_7 */
	87000, /* TRIP_POINT_8 */
	110000, /* TRIP_POINT_9 */
};

static int trips_hyst_benchmark[TRIP_POINTS_NUM] = {
	76000, /* TRIP_POINT_0_D */
	77000, /* TRIP_POINT_1_D */
	78000, /* TRIP_POINT_2_D */
	79000, /* TRIP_POINT_3_D */
	80000, /* TRIP_POINT_4_D */
	81000, /* TRIP_POINT_5_D */
	82000, /* TRIP_POINT_6_D */
	83000, /* TRIP_POINT_7_D */
	85000, /* TRIP_POINT_8_D */
	110000, /* TRIP_POINT_9_D */
};

static int trips_temp_powersave[TRIP_POINTS_NUM] = {
	60000, /* TRIP_POINT_0 */
	64000, /* TRIP_POINT_1 */
	68000, /* TRIP_POINT_2 */
	72000, /* TRIP_POINT_3 */
	75000, /* TRIP_POINT_4 */
	78000, /* TRIP_POINT_5 */
	81000, /* TRIP_POINT_6 */
	85000, /* TRIP_POINT_7 */
	87000, /* TRIP_POINT_8 */
	110000, /* TRIP_POINT_9 */
};

static int trips_hyst_powersave[TRIP_POINTS_NUM] = {
	57000, /* TRIP_POINT_0_D */
	61000, /* TRIP_POINT_1_D */
	65000, /* TRIP_POINT_2_D */
	69000, /* TRIP_POINT_3_D */
	72000, /* TRIP_POINT_4_D */
	75000, /* TRIP_POINT_5_D */
	78000, /* TRIP_POINT_6_D */
	83000, /* TRIP_POINT_7_D */
	85000, /* TRIP_POINT_8_D */
	110000, /* TRIP_POINT_9_D */
};


#define THSEN_GAIN      3874
#define THSEN_OFFSET    2821
#define CONFIG_TSEN_MAX 1

static int pxa28nm_set_threshold(int range);

static int millicelsius_decode(u32 tcode)
{
	int cels;
	cels = (int)(tcode * THSEN_GAIN - THSEN_OFFSET * 1000) / 10000;
	if (cels < 0)
		cels--;
	else
		cels++;
	return cels * 1000;
}

static int millicelsius_encode(int mcels)
{
	u32 tcode;
	mcels /= 1000;
	tcode = (mcels * 10 + THSEN_OFFSET) * 1000 / (THSEN_GAIN);
	return tcode;
}

static ssize_t hit_trip_status_get(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int i;
	int ret = 0;
	u32 tmp;
	ret += sprintf(buf + ret, "Register dump:\n");
	ret += sprintf(buf + ret, "TSEN_PCTRL=0x%x\n", reg_read(TSEN_PCTRL));
	tmp = reg_read(TSEN_LCTRL);
	ret += sprintf(buf + ret, "TSEN_LCTRL=0x%x(int0_en:%d, int1_en:%d)\n",
		tmp, !!(tmp & TSEN_INT0_ENABLE), !!(tmp & TSEN_INT1_ENABLE));
	ret += sprintf(buf + ret, "TSEN_PSTATUS=0x%x\n",
			reg_read(TSEN_PSTATUS));
	tmp = reg_read(TSEN_LSTATUS);
	ret += sprintf(buf + ret, "TSEN_LSTATUS=0x%x(temp:%dmC)\n", tmp,
		millicelsius_decode((tmp & TSEN_DATA_LATCHED_MASK) >>
			TSEN_DATA_LATCHED_OFF));
	ret += sprintf(buf + ret, "TSEN_RSTATUS=0x%x\n",
			reg_read(TSEN_RSTATUS));
	tmp = reg_read(TSEN_THD01);
	ret += sprintf(buf + ret, "TSEN_THD01=0x%x(th0_u:%dmC, th1_d:%dmC)\n",
	tmp, millicelsius_decode((tmp & TSEN_THD0_MASK) >> TSEN_THD0_OFF),
		millicelsius_decode((tmp & TSEN_THD1_MASK) >> TSEN_THD1_OFF));
	tmp = reg_read(TSEN_THD23);
	ret += sprintf(buf + ret, "TSEN_THD23=0x%x(hw_r:%dmC, sw_r:%dmC)\n",
			tmp, millicelsius_decode((tmp & TSEN_WDT_THD_MASK) >>
			TSEN_WDT_THD_OFF), millicelsius_decode((tmp &
			TSEN_THD2_MASK) >> TSEN_THD2_OFF));
	for (i = 0; i < TRIP_POINTS_NUM; i++) {
		ret += sprintf(buf + ret, "trip %d: %d hits\n",
				thermal_dev.thermal_volt.tsen_trips_temp
				[thermal_dev.thermal_volt.therm_policy][i],
				thermal_dev.hit_trip_cnt[i]);
	}
	return ret;
}
static DEVICE_ATTR(hit_trip_status, 0444, hit_trip_status_get, NULL);

static struct attribute *thermal_attrs[] = {
	&dev_attr_hit_trip_status.attr,
	NULL,
};
static struct attribute_group thermal_attr_grp = {
	.attrs = thermal_attrs,
};

static int cpu_sys_get_temp(struct thermal_zone_device *thermal,
		int *temp)
{
	u32 tmp;
	if (!(reg_read(TSEN_PCTRL) & TSEN_RESET)) {
		tmp = reg_read(TSEN_LSTATUS);
		*temp = millicelsius_decode((tmp & TSEN_DATA_LATCHED_MASK) >>
				TSEN_DATA_LATCHED_OFF);
		/* unreasonable temperature */
		if (*temp > 120000 || *temp < -40000)
			*temp = 0;
	} else
		*temp = 0;
	thermal_dev.temp_max = *temp;
	return 0;
}

static int cpu_sys_get_trip_type(struct thermal_zone_device *thermal, int trip,
		enum thermal_trip_type *type)
{
	if ((trip >= 0) && (trip < TRIP_POINTS_ACTIVE_NUM))
		*type = THERMAL_TRIP_ACTIVE;
	else if (TRIP_POINTS_ACTIVE_NUM == trip)
		*type = THERMAL_TRIP_CRITICAL;
	else
		*type = (enum thermal_trip_type)(-1);
	return 0;
}

static int cpu_sys_get_trip_temp(struct thermal_zone_device *thermal, int trip,
		int *temp)
{
	if ((trip >= 0) && (trip < TRIP_POINTS_NUM))
		*temp = thermal_dev.thermal_volt.tsen_trips_temp
		[thermal_dev.thermal_volt.therm_policy][trip];
	else
		*temp = -1;
	return 0;
}

static int cpu_sys_get_trip_hyst(struct thermal_zone_device *thermal,
		int trip, int *temp)
{
	if ((trip >= 0) && (trip < TRIP_POINTS_NUM))
		*temp = thermal_dev.thermal_volt.tsen_trips_temp_d
		[thermal_dev.thermal_volt.therm_policy][trip];
	else
		*temp = -1;
	return 0;
}

static int cpu_sys_set_trip_temp(struct thermal_zone_device *thermal, int trip,
		int temp)
{
	u32 tmp;
	struct pxa28nm_thermal_device *cpu_thermal = thermal->devdata;
	if ((trip >= 0) && (trip < TRIP_POINTS_NUM))
		thermal_dev.thermal_volt.tsen_trips_temp
		[thermal_dev.thermal_volt.therm_policy][trip] = temp;
	if ((TRIP_POINTS_NUM - 1) == trip) {
		tmp = (millicelsius_encode(thermal_dev.thermal_volt.tsen_trips_temp
		[thermal_dev.thermal_volt.therm_policy][TRIP_POINTS_NUM - 1]) <<
					TSEN_THD2_OFF) & TSEN_THD2_MASK;
		reg_clr_set(TSEN_THD23, TSEN_THD2_MASK, tmp);
	} else
		pxa28nm_set_threshold(cpu_thermal->trip_range);
	return 0;
}

static int cpu_sys_set_trip_hyst(struct thermal_zone_device *thermal,
		int trip, int temp)
{
	struct pxa28nm_thermal_device *cpu_thermal = thermal->devdata;
	if ((trip >= 0) && (trip < TRIP_POINTS_ACTIVE_NUM))
		thermal_dev.thermal_volt.tsen_trips_temp_d
		[thermal_dev.thermal_volt.therm_policy][trip] = temp;
	if ((TRIP_POINTS_NUM - 1) == trip)
		pr_warn("critical down doesn't used\n");
	else
		pxa28nm_set_threshold(cpu_thermal->trip_range);
	return 0;
}

static int cpu_sys_get_crit_temp(struct thermal_zone_device *thermal,
		int *temp)
{
	return thermal_dev.thermal_volt.tsen_trips_temp
		[thermal_dev.thermal_volt.therm_policy][TRIP_POINTS_NUM - 1];
}

static struct thermal_zone_device_ops cpu_thermal_ops = {
	.get_temp = cpu_sys_get_temp,
	.get_trip_type = cpu_sys_get_trip_type,
	.get_trip_temp = cpu_sys_get_trip_temp,
	.get_trip_hyst = cpu_sys_get_trip_hyst,
	.set_trip_temp = cpu_sys_set_trip_temp,
	.set_trip_hyst = cpu_sys_set_trip_hyst,
	.get_crit_temp = cpu_sys_get_crit_temp,
};

#ifdef CONFIG_PM_SLEEP
static int thermal_suspend(struct device *dev)
{
	/* DE confirmed, enough for avoid leakage */
	reg_clr_set(TSEN_PCTRL, 0, TSEN_RESET);
	return 0;
}

static int thermal_resume(struct device *dev)
{
	reg_clr_set(TSEN_PCTRL, TSEN_RESET, 0);
	return 0;
}

static SIMPLE_DEV_PM_OPS(thermal_pm_ops,
		thermal_suspend, thermal_resume);
#define PXA_TMU_PM      (&thermal_pm_ops)
#else
#define PXA_TMU_PM      NULL
#endif


static int pxa_register_cooling(void)
{
	thermal_dev.thermal_volt.cool_pxa.cool_cpufreq = cpufreq_cool_register("cluster0");
	thermal_dev.thermal_volt.cool_pxa.cool_cpu1freq = cpufreq_cool_register("cluster1");
	thermal_dev.thermal_volt.cool_pxa.cool_cpuhotplug = cpuhotplug_cool_register("helan3");
	thermal_dev.thermal_volt.cool_pxa.cool_ddrfreq = ddrfreq_cool_register();
	thermal_dev.thermal_volt.cool_pxa.cool_gc2dfreq = gpufreq_cool_register("gc2d");
	thermal_dev.thermal_volt.cool_pxa.cool_gc3dfreq = gpufreq_cool_register("gc3d");
	thermal_dev.thermal_volt.cool_pxa.cool_gcshfreq = gpufreq_cool_register("gcsh");
	thermal_dev.thermal_volt.cool_pxa.cool_vpufreq = vpufreq_cool_register(DEVFREQ_VPU_0);
	return 0;
}

static int max_get_max_state(struct thermal_cooling_device *cdev,
		unsigned long *state)
{
	*state = thermal_dev.maxdev.max_state;
	return 0;
}

static int max_get_cur_state(struct thermal_cooling_device *cdev,
		unsigned long *state)
{
	*state = thermal_dev.maxdev.cur_state;
	return 0;
}

static int max_set_cur_state(struct thermal_cooling_device *cdev,
		unsigned long state)
{
	struct thermal_cooling_device *c_freq = thermal_dev.thermal_volt.cool_pxa.cool_cpufreq;
	struct thermal_cooling_device *core1_freq = thermal_dev.thermal_volt.cool_pxa.cool_cpu1freq;
	struct thermal_cooling_device *c_plug =
		thermal_dev.thermal_volt.cool_pxa.cool_cpuhotplug;
	struct thermal_cooling_device *ddr_freq = thermal_dev.thermal_volt.cool_pxa.cool_ddrfreq;
	struct thermal_cooling_device *gc2d_freq = thermal_dev.thermal_volt.cool_pxa.cool_gc2dfreq;
	struct thermal_cooling_device *gc3d_freq = thermal_dev.thermal_volt.cool_pxa.cool_gc3dfreq;
	struct thermal_cooling_device *gcsh_freq = thermal_dev.thermal_volt.cool_pxa.cool_gcshfreq;
	struct thermal_cooling_device *vpu_freq = thermal_dev.thermal_volt.cool_pxa.cool_vpufreq;
	unsigned long freq_state = 0, plug_state = 0, core1_freq_state = 0;
	unsigned long ddr_freq_state;
	unsigned long gc2d_freq_state = 0, gc3d_freq_state = 0, gcsh_freq_state = 0;
	unsigned long vpu_freq_state = 0;
	static u32 prev_state;
	if (state > thermal_dev.maxdev.max_state)
		return -EINVAL;
	thermal_dev.maxdev.cur_state = state;

	/* core related throttle */
	freq_state = thermal_dev.thermal_volt.tsen_throttle_tbl
	[thermal_dev.thermal_volt.therm_policy][THROTTLE_CORE][state + 1];
	core1_freq_state = thermal_dev.thermal_volt.tsen_throttle_tbl
	[thermal_dev.thermal_volt.therm_policy][THROTTLE_CORE1][state + 1];
	plug_state = thermal_dev.thermal_volt.tsen_throttle_tbl
	[thermal_dev.thermal_volt.therm_policy][THROTTLE_HOTPLUG][state + 1];
	if (c_freq)
		c_freq->ops->set_cur_state(c_freq, freq_state);
	if (core1_freq)
		core1_freq->ops->set_cur_state(core1_freq, core1_freq_state);
	if (c_plug)
		c_plug->ops->set_cur_state(c_plug, plug_state);

	/* ddr related throttle */
	ddr_freq_state = thermal_dev.thermal_volt.tsen_throttle_tbl
	[thermal_dev.thermal_volt.therm_policy][THROTTLE_DDR][state + 1];

	if (ddr_freq)
		ddr_freq->ops->set_cur_state(ddr_freq, ddr_freq_state);

	/* gc related throttle */
	gc3d_freq_state = thermal_dev.thermal_volt.tsen_throttle_tbl
	[thermal_dev.thermal_volt.therm_policy][THROTTLE_GC3D][state + 1];
	gc2d_freq_state = thermal_dev.thermal_volt.tsen_throttle_tbl
	[thermal_dev.thermal_volt.therm_policy][THROTTLE_GC2D][state + 1];
	gcsh_freq_state = thermal_dev.thermal_volt.tsen_throttle_tbl
	[thermal_dev.thermal_volt.therm_policy][THROTTLE_GCSH][state + 1];
	if (gc2d_freq)
		gc2d_freq->ops->set_cur_state(gc2d_freq, gc2d_freq_state);
	if (gc3d_freq)
		gc3d_freq->ops->set_cur_state(gc3d_freq, gc3d_freq_state);
	if (gcsh_freq)
		gcsh_freq->ops->set_cur_state(gcsh_freq, gcsh_freq_state);

	/* vpu related throttle */
	vpu_freq_state = thermal_dev.thermal_volt.tsen_throttle_tbl
	[thermal_dev.thermal_volt.therm_policy][THROTTLE_VPU][state + 1];
	if (vpu_freq)
		vpu_freq->ops->set_cur_state(vpu_freq, vpu_freq_state);

	pr_info("Thermal max temp: %d; CPU Throttle state %lu: cpu0freq qos %lu, cpu1freq qos %lu,\n\
	core_num qos %lu, ddrfreq qos %lu, gc2d qos %lu, gc3d qos %lu,gcsh qos %lu, vpu qos %lu\n",
	thermal_dev.temp_max, state, freq_state, core1_freq_state,
	plug_state,ddr_freq_state,gc2d_freq_state, gc3d_freq_state,
	gcsh_freq_state,vpu_freq_state);

	if (prev_state < state)
		pr_info("Thermal frequency limitation, performance impact expected!");
	prev_state = state;
	return 0;
}

static struct thermal_cooling_device_ops const max_cooling_ops = {
	.get_max_state = max_get_max_state,
	.get_cur_state = max_get_cur_state,
	.set_cur_state = max_set_cur_state,
};

/* Register with the in-kernel thermal management */
static int pxa_register_max_thermal(void)
{
	int i, trip_w_mask = 0;

	thermal_dev.maxdev.cool_tsen = thermal_cooling_device_register(
		"max-combine-cool", &thermal_dev, &max_cooling_ops);

	thermal_dev.maxdev.max_state = TRIP_RANGE_MAX;
	thermal_dev.maxdev.cur_state = 0;

	for (i = 0; i < TRIP_POINTS_NUM; i++)
		trip_w_mask |= (1 << i);

	thermal_dev.thermal_volt.therm_max = thermal_zone_device_register(
			"tsen_max", TRIP_POINTS_NUM, trip_w_mask,
			&thermal_dev, &cpu_thermal_ops, NULL, 0, 0);
	/*
	 * enable bi_direction state machine, then it didn't care
	 * whether up/down trip points are crossed or not
	 */
	thermal_dev.thermal_volt.therm_max->tzdctrl.state_ctrl = true;
	/* bind combine cooling */

		thermal_zone_bind_cooling_device(thermal_dev.thermal_volt.therm_max,
			0, thermal_dev.maxdev.cool_tsen,
			THERMAL_NO_LIMIT, THERMAL_NO_LIMIT);

	i = sysfs_create_group(&((thermal_dev.thermal_volt.therm_max->device).kobj),
			&thermal_attr_grp);
	if (i < 0)
		pr_err("Failed to register private thermal interface\n");

	return 0;
}

#ifndef CONFIG_TSEN_MAX
/* pxa1936 limit cpu freq  */
static int pxa1936_cluster0_freq_state[TRIP_POINTS_NUM] = {
	0, 1, 2, 3, 4, 5,
};

static int pxa1936_cluster1_freq_state[TRIP_POINTS_NUM] = {
	0, 2, 3, 4, 6, 7,
};

/* pxa1936 cpu num in every state */
static int pxa1936_cpu_plug_state[TRIP_POINTS_NUM] = {
	0, 1, 2, 3, 6, 7,
};

/* pxa1936 limit gc2d freq  */
static int pxa1936_gpu_freq_state[TRIP_POINTS_NUM] = {
	0, 1, 2, 3, 3, 3,
};
/* pxa1936 limit gc3d freq, limit a level gc3dfreq in every  thermal state*/
static int pxa1936_gc3d_freq_state[TRIP_POINTS_NUM] = {
	0, 2, 3, 4, 5, 5,
};
/* pxa1936 limit gcsh freq, limit a level gcshfreq in every thermal state */
static int pxa1936_gcsh_freq_state[TRIP_POINTS_NUM] = {
	0, 2, 3, 4, 5, 5,
};

static int gpu_get_max_state(struct thermal_cooling_device *gdev,
		unsigned long *state)
{
	*state = thermal_dev.gdev.max_state;
	return 0;
}

static int gpu_get_cur_state(struct thermal_cooling_device *gdev,
		unsigned long *state)
{
	*state = thermal_dev.gdev.cur_state;
	return 0;
}

static int gpu_set_cur_state(struct thermal_cooling_device *gdev,
		unsigned long state)
{
	struct thermal_cooling_device *gc2d_freq = thermal_dev.gdev.cool_gc2dfreq;
	struct thermal_cooling_device *gc3d_freq = thermal_dev.gdev.cool_gc3dfreq;
	struct thermal_cooling_device *gcsh_freq = thermal_dev.gdev.cool_gcshfreq;

	unsigned long gc2d_freq_state = 0, gc3d_freq_state = 0, gcsh_freq_state = 0;
	int temp;

	if (state > thermal_dev.gdev.max_state)
		return -EINVAL;
	thermal_dev.gdev.cur_state = state;

	gc2d_freq_state = pxa1936_gpu_freq_state[state];
	gc3d_freq_state = pxa1936_gc3d_freq_state[state];
	gcsh_freq_state = pxa1936_gcsh_freq_state[state];

	if (gc2d_freq)
		gc2d_freq->ops->set_cur_state(gc2d_freq, gc2d_freq_state);

	if (gc3d_freq)
		gc3d_freq->ops->set_cur_state(gc3d_freq, gc3d_freq_state);

	if (gcsh_freq)
		gcsh_freq->ops->set_cur_state(gcsh_freq, gcsh_freq_state);

	cpu_sys_get_temp(thermal_dev.therm_gc, &temp);

	pr_info("Thermal gc temp %d, state %lu, gc2d qos %lu, gc3d qos %lu, gcsh qos %lu\n",
			temp / 1000, state, gc2d_freq_state,
			gc3d_freq_state, gcsh_freq_state);

	return 0;
}

static struct thermal_cooling_device_ops const gpu_cooling_ops = {
	.get_max_state = gpu_get_max_state,
	.get_cur_state = gpu_get_cur_state,
	.set_cur_state = gpu_set_cur_state,
};

/* Register with the in-kernel thermal management */
static int pxa1936_register_gc_thermal(void)
{
	int i, trip_w_mask = 0;

	thermal_dev.gdev.cool_gc2dfreq = gpufreq_cool_register("gc2d");
	thermal_dev.gdev.cool_gc3dfreq = gpufreq_cool_register("gc3d");
	thermal_dev.gdev.cool_gcshfreq = gpufreq_cool_register("gcsh");

	thermal_dev.gdev.combile_cool = thermal_cooling_device_register(
			"gc-combile-cool", &thermal_dev, &gpu_cooling_ops);
	thermal_dev.gdev.max_state = TRIP_POINTS_ACTIVE_NUM;
	thermal_dev.gdev.cur_state = 0;

	for (i = 0; i < TRIP_POINTS_NUM; i++)
		trip_w_mask |= (1 << i);

	thermal_dev.therm_gc = thermal_zone_device_register(
			"thsens_gc", TRIP_POINTS_NUM, trip_w_mask,
			&thermal_dev, &cpu_thermal_ops, NULL, 0, 0);

	/*
	 * enable bi_direction state machine, then it didn't care
	 * whether up/down trip points are crossed or not
	 */
	thermal_dev.therm_gc->tzdctrl.state_ctrl = true;
	/* bind combile cooling */
	thermal_zone_bind_cooling_device(thermal_dev.therm_gc,
			0, thermal_dev.gdev.combile_cool,
			THERMAL_NO_LIMIT, THERMAL_NO_LIMIT);

	i = sysfs_create_group(&((thermal_dev.therm_gc->device).kobj),
			&thermal_attr_grp);
	if (i >= 0)
		pr_info("helan3: Kernel GC2d/GC3d/GCSH Thermal interface registered\n");

	return 0;
}


static int combile_get_max_state(struct thermal_cooling_device *cdev,
		unsigned long *state)
{
	struct pxa28nm_thermal_device *cpu_thermal = cdev->devdata;
	*state = cpu_thermal->cdev.max_state;
	return 0;
}

static int combile_get_cur_state(struct thermal_cooling_device *cdev,
		unsigned long *state)
{
	struct pxa28nm_thermal_device *cpu_thermal = cdev->devdata;
	*state = cpu_thermal->cdev.cur_state;
	return 0;
}

static int combile_set_cur_state(struct thermal_cooling_device *cdev,
		unsigned long state)
{
	struct pxa28nm_thermal_device *cpu_thermal = cdev->devdata;
	struct thermal_cooling_device *cluster0_freq = cpu_thermal->cdev.cool_cpu_cluster0_freq;
	struct thermal_cooling_device *cluster1_freq =
		cpu_thermal->cdev.cool_cpu_cluster1_freq;
	struct thermal_cooling_device *c_plug =
		cpu_thermal->cdev.cool_cpuhotplug;
	unsigned long cluster0_freq_state = 0, cluster1_freq_state = 0, plug_state = 0;
	int temp = 0;

	if (state > cpu_thermal->cdev.max_state)
		return -EINVAL;
	cpu_thermal->cdev.cur_state = state;

	cluster0_freq_state = pxa1936_cluster0_freq_state[state];
	cluster1_freq_state = pxa1936_cluster1_freq_state[state];
	plug_state = pxa1936_cpu_plug_state[state];

	cpu_sys_get_temp(thermal_dev.therm_cpu, &temp);
	pr_info("Thermal cpu temp %dC, state %lu, cluster0freq qos %lu, cluster1freq qos %lu\n",
		temp / 1000, state, cluster0_freq_state, cluster1_freq_state);
	pr_info("core_num max qos %lu, core_num min qos %lu\n",
		thermal_dev.cpu_num - plug_state,
		thermal_dev.cpu_num - plug_state - 1);

	if (cluster0_freq)
		cluster0_freq->ops->set_cur_state(cluster0_freq, cluster0_freq_state);
	if (cluster1_freq)
		cluster1_freq->ops->set_cur_state(cluster1_freq, cluster1_freq_state);
	if (c_plug)
		c_plug->ops->set_cur_state(c_plug, plug_state);

	return 0;
}

static struct thermal_cooling_device_ops const combile_cooling_ops = {
	.get_max_state = combile_get_max_state,
	.get_cur_state = combile_get_cur_state,
	.set_cur_state = combile_set_cur_state,
};

static void pxa28nm_register_thermal(void)
{
	int i, trip_w_mask = 0;
	struct thermal_cooling_device *cool_dev;
	cool_dev = cpufreq_cool_register("cluster0");
	if (cool_dev)
		thermal_dev.cdev.cool_cpu_cluster0_freq = cool_dev;
	else
		thermal_dev.cdev.cool_cpu_cluster0_freq = NULL;

	cool_dev = cpufreq_cool_register("cluster1");
	if (cool_dev)
		thermal_dev.cdev.cool_cpu_cluster1_freq = cool_dev;
	else
		thermal_dev.cdev.cool_cpu_cluster1_freq = NULL;

	thermal_dev.cdev.cool_cpuhotplug = cpuhotplug_cool_register("helan3");

	thermal_dev.cdev.combile_cool = thermal_cooling_device_register(
			"cpu-combile-cool", &thermal_dev, &combile_cooling_ops);
	thermal_dev.cdev.max_state = TRIP_POINTS_ACTIVE_NUM;
	thermal_dev.cdev.cur_state = 0;

	for (i = 0; i < TRIP_POINTS_NUM; i++)
		trip_w_mask |= (1 << i);
	thermal_dev.therm_cpu = thermal_zone_device_register(
			"thsens_cpu", TRIP_POINTS_NUM, trip_w_mask,
			&thermal_dev, &cpu_thermal_ops, NULL, 0, 0);
	/*
	 * enable bi_direction state machine, then it didn't care
	 * whether up/down trip points are crossed or not
	 */
	thermal_dev.therm_cpu->tzdctrl.state_ctrl = true;
	/* bind combile cooling */
	thermal_zone_bind_cooling_device(thermal_dev.therm_cpu,
			TRIP_POINT_0,  thermal_dev.cdev.combile_cool,
			THERMAL_NO_LIMIT, THERMAL_NO_LIMIT);

	i = sysfs_create_group(&((thermal_dev.therm_cpu->device).kobj),
			&thermal_attr_grp);
	if (i < 0)
		pr_err("Failed to register private thermal interface\n");
}
#endif

int pxa28nm_set_threshold(int range)
{
	u32 tmp;

	if (range < 0 || range > TRIP_POINTS_ACTIVE_NUM) {
		pr_err("soc thermal: invalid threshold %d\n", range);
		return -1;
	}

	if (0 == range) {
		tmp = (millicelsius_encode(thermal_dev.thermal_volt.tsen_trips_temp
		[thermal_dev.thermal_volt.therm_policy][0]) << TSEN_THD0_OFF) &
							TSEN_THD0_MASK;
		reg_clr_set(TSEN_THD01, TSEN_THD0_MASK, tmp);
		tmp = (millicelsius_encode(thermal_dev.thermal_volt.tsen_trips_temp_d
		[thermal_dev.thermal_volt.therm_policy][0]) << TSEN_THD1_OFF) &
							TSEN_THD1_MASK;
		reg_clr_set(TSEN_THD01, TSEN_THD1_MASK, tmp);
		reg_clr_set(TSEN_LCTRL, 0, TSEN_INT0_ENABLE);
		reg_clr_set(TSEN_LCTRL, TSEN_INT1_ENABLE, 0);

	} else if (TRIP_POINTS_ACTIVE_NUM == range) {
		tmp = (millicelsius_encode(thermal_dev.thermal_volt.tsen_trips_temp
		[thermal_dev.thermal_volt.therm_policy][range - 1]) <<
						TSEN_THD0_OFF) & TSEN_THD0_MASK;
		reg_clr_set(TSEN_THD01, TSEN_THD0_MASK, tmp);
		tmp = (millicelsius_encode(thermal_dev.thermal_volt.tsen_trips_temp_d
		[thermal_dev.thermal_volt.therm_policy][range - 1]) <<
						TSEN_THD1_OFF) & TSEN_THD1_MASK;
		reg_clr_set(TSEN_THD01, TSEN_THD1_MASK, tmp);
		reg_clr_set(TSEN_LCTRL, TSEN_INT0_ENABLE, 0);
		reg_clr_set(TSEN_LCTRL, 0, TSEN_INT1_ENABLE);
	} else {
		tmp = (millicelsius_encode(thermal_dev.thermal_volt.tsen_trips_temp
		[thermal_dev.thermal_volt.therm_policy][range]) <<
						TSEN_THD0_OFF) & TSEN_THD0_MASK;
		reg_clr_set(TSEN_THD01, TSEN_THD0_MASK, tmp);
		tmp = (millicelsius_encode(thermal_dev.thermal_volt.tsen_trips_temp_d
		[thermal_dev.thermal_volt.therm_policy][range]) <<
						TSEN_THD1_OFF) & TSEN_THD1_MASK;
		reg_clr_set(TSEN_THD01, TSEN_THD1_MASK, tmp);
		reg_clr_set(TSEN_LCTRL, 0, TSEN_INT0_ENABLE);
		reg_clr_set(TSEN_LCTRL, 0, TSEN_INT1_ENABLE);
	}
	return 0;
}

static void pxa28nm_set_interval(int ms)
{
	/* 500k clock, high 16bit */
	int interval_val = ms * 500 / 256;
	reg_clr_set(TSEN_LCTRL, TSEN_AUTO_INTERVAL_MASK,
	(interval_val << TSEN_AUTO_INTERVAL_OFF) & TSEN_AUTO_INTERVAL_MASK);
}

static irqreturn_t pxa28nm_thread_irq(int irq, void *devid)
{
	if (thermal_dev.therm_cpu) {
		/*
		 * trigger framework cooling, the real cooling behavior
		 * rely on governor, if it's user_space, then only uevent
		 * will be sent by framework, other wise, related governor
		 * will do real cooling
		 */
		thermal_zone_device_update(thermal_dev.therm_cpu);
	}

	if (thermal_dev.therm_gc)
		thermal_zone_device_update(thermal_dev.therm_gc);

	if (thermal_dev.thermal_volt.therm_max)
		thermal_zone_device_update(thermal_dev.thermal_volt.therm_max);

	return IRQ_HANDLED;
}

static irqreturn_t pxa28nm_irq(int irq, void *devid)
{
	u32 tmp, tmp_lc;
	int temp;
	tmp = reg_read(TSEN_LSTATUS);
	tmp_lc = reg_read(TSEN_LCTRL);

	if ((tmp_lc & TSEN_RDY_INT_ENABLE) && (tmp & TSEN_RDY_INT)) {
		cpu_sys_get_temp(thermal_dev.therm_cpu, &temp);
		pr_info("in irq temp = %d\n", temp);
	}
	if ((tmp_lc & TSEN_INT0_ENABLE) && (tmp & TSEN_INT0)) {
		thermal_dev.hit_trip_cnt[thermal_dev.trip_range]++;
		thermal_dev.trip_range++;
		if (thermal_dev.trip_range > TRIP_POINTS_ACTIVE_NUM)
			thermal_dev.trip_range = TRIP_POINTS_ACTIVE_NUM;
		pxa28nm_set_threshold(thermal_dev.trip_range);
	} else if ((tmp_lc & TSEN_INT1_ENABLE) && (tmp & TSEN_INT1)) {
		thermal_dev.trip_range--;
		if (thermal_dev.trip_range < 0)
			thermal_dev.trip_range = 0;
		pxa28nm_set_threshold(thermal_dev.trip_range);
	} else if ((tmp_lc & TSEN_INT2_ENABLE) && (tmp & TSEN_INT2)) {
		/* wait framework shutdown */
		cpu_sys_get_temp(thermal_dev.therm_cpu, &temp);
		pr_info("critical temp = %d\n", temp);
	}
	reg_clr_set(TSEN_LSTATUS, 0, TSEN_INT2 | TSEN_INT1 | TSEN_INT0 | TSEN_RDY_INT);

	return IRQ_WAKE_THREAD;
}

void pxa1936_register_initialize(void)
{
	u32 tmp;
	thermal_dev.cpu_num = num_possible_cpus();

	tmp = (millicelsius_encode(120000) << TSEN_WDT_THD_OFF) &
					TSEN_WDT_THD_MASK;
	reg_clr_set(TSEN_THD23, TSEN_WDT_THD_MASK, tmp);
	reg_clr_set(TSEN_LCTRL, 0, TSEN_WDT_DIRECTION | TSEN_WDT_ENABLE);
	tmp = (millicelsius_encode(thermal_dev.thermal_volt.tsen_trips_temp
		[thermal_dev.thermal_volt.therm_policy][TRIP_POINTS_NUM - 1]) <<
			TSEN_THD2_OFF) & TSEN_THD2_MASK;
	reg_clr_set(TSEN_THD23, TSEN_THD2_MASK, tmp);
	reg_clr_set(TSEN_LCTRL, 0, TSEN_INT2_ENABLE | TSEN_INT2_DIRECTION);

	reg_clr_set(TSEN_LCTRL, 0, TSEN_INT0_ENABLE | TSEN_INT0_DIRECTION);
	reg_clr_set(TSEN_LCTRL, TSEN_INT1_DIRECTION, TSEN_INT1_ENABLE);
	thermal_dev.trip_range = 0;
	pxa28nm_set_threshold(thermal_dev.trip_range);
	/* set auto interval 200ms and start auto mode 2*/
	pxa28nm_set_interval(200);
	reg_clr_set(TSEN_PCTRL, TSEN_ISO_EN | TSEN_RESET, 0);
	tmp = ((2 << TSEN_AUTO_MODE_OFF) & TSEN_AUTO_MODE_MASK);
	reg_clr_set(TSEN_LCTRL, 0, tmp);
	return;

}

void update_trip_temp(void)
{
	int i;
	for (i = 0; i < TRIP_POINTS_NUM; i++) {
		thermal_dev.thermal_volt.tsen_trips_temp[POWER_SAVING_MODE][i]
		= trips_temp_powersave[i];
		thermal_dev.thermal_volt.tsen_trips_temp_d[POWER_SAVING_MODE][i]
		= trips_hyst_powersave[i];
		thermal_dev.thermal_volt.tsen_trips_temp[BENCHMARK_MODE][i]
		= trips_temp_benchmark[i];
		thermal_dev.thermal_volt.tsen_trips_temp_d[BENCHMARK_MODE][i]
		= trips_hyst_benchmark[i];
	}
	return;
}

void thermal_volt_init(void)
{
	thermal_dev.thermal_volt.tsen_throttle_tbl = pxa_tsen_throttle_tbl;
	thermal_dev.thermal_volt.therm_policy = BENCHMARK_MODE;
	thermal_dev.thermal_volt.range_max = TRIP_POINTS_ACTIVE_NUM;
	strcpy(thermal_dev.thermal_volt.cpu_name, "helan3");
	thermal_dev.thermal_volt.set_threshold = pxa28nm_set_threshold;

	thermal_dev.thermal_volt.vl_master =  THROTTLE_CORE1;
	update_trip_temp();

	mutex_init(&thermal_dev.thermal_volt.policy_lock);
	voltage_mrvl_init(&(thermal_dev.thermal_volt));
	tsen_update_policy();
	pxa_register_cooling();

	pxa_register_max_thermal();

	register_debug_interface();
	tsen_policy_dump(NULL, 0);
	return;
}


static int pxa1936_thermal_probe(struct platform_device *pdev)
{
	int ret = 0;
	u32 tmp;

	if (!(of_machine_is_compatible("marvell,pxa1936") ||
			of_machine_is_compatible("marvell,pxa1956")))
		return -ENODEV;

	memset(&thermal_dev, 0, sizeof(thermal_dev));
	thermal_dev.irq = platform_get_irq(pdev, 0);
	if (thermal_dev.irq < 0) {
		dev_err(&pdev->dev, "Failed to get platform irq\n");
		return -EINVAL;
	}

	thermal_dev.mem =
		platform_get_resource(pdev, IORESOURCE_MEM, 0);
	thermal_dev.base =
		devm_ioremap_resource(&pdev->dev, thermal_dev.mem);
	if (IS_ERR(thermal_dev.base))
		return PTR_ERR(thermal_dev.base);

	ret = devm_request_threaded_irq(&pdev->dev, thermal_dev.irq,
			pxa28nm_irq, pxa28nm_thread_irq, IRQF_ONESHOT,
			pdev->name, NULL);
	if (ret) {
		dev_err(&pdev->dev, "Failed to request irq: %d\n",
				thermal_dev.irq);
		return ret;
	}

	thermal_dev.therm_clk = devm_clk_get(&pdev->dev, "ts_clk");
	if (IS_ERR(thermal_dev.therm_clk)) {
		dev_err(&pdev->dev, "Could not get thermal clock\n");
		return PTR_ERR(thermal_dev.therm_clk);
	}
	clk_prepare_enable(thermal_dev.therm_clk);
	/* make sure clock stable */
	usleep_range(20, 30);

	if (reg_read(TSEN_RSTATUS) & TSEN_WDT_FLAG) {
		pr_warn("System reset by thermal watch dog (%d C)\n",
			millicelsius_decode((reg_read(TSEN_RSTATUS) &
				TSEN_DATA_WDT_MASK) >> TSEN_DATA_WDT_OFF)/1000);
		reg_clr_set(TSEN_RSTATUS, 0, TSEN_WDT_FLAG);
	}

	tmp = reg_read(TSEN_LSTATUS);
	if (tmp) {
		void *apb_base = ioremap_nocache(APB_CLK_BASE, SZ_4K);
		if (apb_base) {
			pr_warn("reinit thermal LSTATUS = 0x%x\n", tmp);
			/* delay 10us for each step to ganrantee reset suc */

			/* bit2 ctl reset, bit1&0 ctl enable */
			writel(0x4, (apb_base + 0x6C));
			udelay(10);
			writel(0x0, (apb_base + 0x6C));
			udelay(10);
			writel(0x3, (apb_base + 0x6C));
			udelay(10);

			iounmap(apb_base);
			tmp = reg_read(TSEN_LSTATUS);
			reg_clr_set(TSEN_LSTATUS, 0, tmp);
			tmp = reg_read(TSEN_LSTATUS);
			if (tmp)
				WARN_ON("reinit thermal failed\n");
		}
	} else
		pr_info("thermal status fine\n");

	thermal_volt_init();

	pxa1936_register_initialize();

	pr_info("helan3 thermal probed\n");
	return 0;
}

static int pxa1936_thermal_remove(struct platform_device *pdev)
{
	reg_clr_set(TSEN_PCTRL, 0, TSEN_RESET);
	clk_disable_unprepare(thermal_dev.therm_clk);
	if (!CONFIG_TSEN_MAX) {
		cpufreq_cool_unregister(thermal_dev.cdev.cool_cpu_cluster0_freq);
		cpufreq_cool_unregister(thermal_dev.cdev.cool_cpu_cluster1_freq);
		cpuhotplug_cool_unregister(thermal_dev.cdev.cool_cpuhotplug);
		thermal_cooling_device_unregister(thermal_dev.cdev.combile_cool);
		thermal_zone_device_unregister(thermal_dev.therm_cpu);
		thermal_zone_device_unregister(thermal_dev.therm_gc);
	}

	cpufreq_cool_unregister(thermal_dev.thermal_volt.cool_pxa.cool_cpufreq);
	cpufreq_cool_unregister(thermal_dev.thermal_volt.cool_pxa.cool_cpu1freq);
	cpuhotplug_cool_unregister(thermal_dev.thermal_volt.cool_pxa.cool_cpuhotplug);
	ddrfreq_cool_unregister(thermal_dev.thermal_volt.cool_pxa.cool_ddrfreq);
	gpufreq_cool_unregister(thermal_dev.thermal_volt.cool_pxa.cool_gc2dfreq);
	gpufreq_cool_unregister(thermal_dev.thermal_volt.cool_pxa.cool_gc3dfreq);
	gpufreq_cool_unregister(thermal_dev.thermal_volt.cool_pxa.cool_gcshfreq);
	vpufreq_cool_unregister(thermal_dev.thermal_volt.cool_pxa.cool_vpufreq);
	thermal_cooling_device_unregister(thermal_dev.maxdev.cool_tsen);

	pr_info("Kernel Thermal management unregistered\n");
	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id pxa1936_tmu_match[] = {
	{ .compatible = "marvell,pxa1936-thermal", },
	{},
};
MODULE_DEVICE_TABLE(of, pxa28nm_tmu_match);
#endif

static struct platform_driver pxa1936_thermal_driver = {
	.driver = {
		.name   = "pxa1936-thermal",
		.pm     = PXA_TMU_PM,
#ifdef CONFIG_OF
		.of_match_table = of_match_ptr(pxa1936_tmu_match),
#endif
	},
	.probe = pxa1936_thermal_probe,
	.remove = pxa1936_thermal_remove,
};
module_platform_driver(pxa1936_thermal_driver);

MODULE_AUTHOR("Marvell Semiconductor");
MODULE_DESCRIPTION("HELAN3 SoC thermal driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:pxa1936-thermal");
