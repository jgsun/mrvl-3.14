/*
 * linux/arch/arm/mach-mmp/pxa1978_lowpower.c
 *
 * Author:	Raul Xiong <xjian@marvell.com>
 *		Fangsuo Wu <fswu@marvell.com>
 * Copyright:	(C) 2012 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/cpuidle.h>
#include <linux/cpu_pm.h>
#include <linux/kernel.h>
#include <linux/edge_wakeup_mmp.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/of_address.h>
#include <linux/of.h>
#include <linux/irqchip/arm-gic.h>
#include <asm/mcpm.h>
#include <asm/mcpm_plat.h>
#include <linux/cputype.h>

#include "regs-addr.h"
#include "pxa1978_lowpower.h"

#define MAX_CPU	4
#define MAX_CLUS 2
static void __iomem *apmu_virt_addr;
static void __iomem *mpmu_virt_addr;
static void __iomem *APMU_CORE_IDLE_CFG[MAX_CPU*MAX_CLUS];
static void __iomem *APMU_PCR[MAX_CPU*MAX_CLUS];
static void __iomem *APMU_INT_MASK[MAX_CPU*MAX_CLUS];
static void __iomem *APMU_CORE_RESET[MAX_CPU*MAX_CLUS];

/* Registers for different CPUs are quite scattered */
static const unsigned APMU_CORE_IDLE_CFG_OFFS[] = {
	0x34, 0x38, 0x3c, 0x40, 0x220, 0x224, 0x228, 0x22c
};

static const unsigned APMU_PCR_OFFS[] = {
	0x0, 0x4, 0x8, 0xc, 0x200, 0x204, 0x208, 0x20c
};
#define APMU_PCR8_OFFS	0x10

/* For chip-level stuff do not use the per-CPU PCR's, only one per cluster */
#define C0_VOTING_PCR		0
#define C1_VOTING_PCR		4

static const unsigned APMU_INT_MASK_OFFS[] = {
	0x128, 0x12c, 0x130, 0x134, 0x240, 0x244, 0x248, 0x24c
};

static const unsigned APMU_CORE_RESET_OFFS[] = {
	0x18, 0x1c, 0x20, 0x24, 0x210, 0x214, 0x218, 0x21c
};

#define RINDEX(cpu, clus) ((cpu) + (clus)*MAX_CPU)

enum pxa1978_lowpower_state {
	POWER_MODE_CORE_INTIDLE,	/* used for C1 */
	POWER_MODE_CORE_POWERDOWN,	/* used for C2 */
	POWER_MODE_MP_POWERDOWN,	/* Cluster shutdown */
	POWER_MODE_APPS_IDLE,		/* used for D1P */
	POWER_MODE_SYS_SLEEP,		/* used for non-udr chip sleep, D1 */
	POWER_MODE_UDR_VCTCXO,		/* used for udr with vctcxo, D2 */
	POWER_MODE_UDR,			/* used for udr D2, suspend */
	POWER_MODE_MAX = 15,		/* maximum lowpower states */
};

static struct cpuidle_state pxa1978_modes[] = {
	[POWER_MODE_CORE_INTIDLE] = {
		.exit_latency		= 18,
		.target_residency	= 36,
		.flags			= CPUIDLE_FLAG_TIME_VALID,
		.name			= "C1",
		.desc			= "C1: Core internal clock gated",
		.enter			= cpuidle_simple_enter,
	},
	[POWER_MODE_CORE_POWERDOWN] = {
		.exit_latency		= 20,
		.target_residency	= 40,
		/*
		 * Use CPUIDLE_FLAG_TIMER_STOP flag to let the cpuidle
		 * framework handle the CLOCK_EVENT_NOTIFY_BROADCAST_
		 * ENTER/EXIT when entering idle states.
		 */
		.flags			= CPUIDLE_FLAG_TIME_VALID |
					  CPUIDLE_FLAG_TIMER_STOP,
		.name			= "C2",
		.desc			= "C2: Core power down",
		.disabled		= 1, /* enable for CPUIDLE */
	},
	[POWER_MODE_MP_POWERDOWN] = {
		.exit_latency		= 100,
		.target_residency	= 120,
		.flags			= CPUIDLE_FLAG_TIME_VALID |
					  CPUIDLE_FLAG_TIMER_STOP,
		.name			= "MP2",
		.desc			= "MP2: Core subsystem power down",
		.disabled		= 1, /* enable for CPUIDLE */
	},
#if (0)
	[POWER_MODE_APPS_IDLE] = {
		.exit_latency		= 500,
		.target_residency	= 1000,
		.flags			= CPUIDLE_FLAG_TIME_VALID |
					  CPUIDLE_FLAG_TIMER_STOP,
		.name			= "D1p",
		.desc			= "D1p: AP idle state",
	},
	[POWER_MODE_SYS_SLEEP] = {
		.exit_latency		= 600,
		.target_residency	= 1200,
		.flags			= CPUIDLE_FLAG_TIME_VALID |
					  CPUIDLE_FLAG_TIMER_STOP,
		.name			= "D1",
		.desc			= "D1: Chip idle state",
	},
#endif
};


static void pxa1978_set_dstate(u32 cpu, u32 cluster, u32 power_mode)
{
	(void)cpu;
	(void)power_mode;
}

static void pxa1978_set_cstate(u32 cpu, u32 cluster, u32 power_mode)
{
	int ri = RINDEX(cpu, cluster);
	unsigned pcr_mask;
	unsigned cfg = readl_relaxed(APMU_CORE_IDLE_CFG[ri]);
	unsigned mask = readl_relaxed(APMU_INT_MASK[ri]);
	unsigned pcr = readl_relaxed(APMU_PCR[ri]);

	pcr_mask = cluster ? APMU_PCR_C1_OFF : APMU_PCR_C0_OFF;

	if (power_mode > POWER_MODE_CORE_POWERDOWN)
		power_mode = POWER_MODE_CORE_POWERDOWN;

	if (power_mode == POWER_MODE_CORE_POWERDOWN) {
		cfg |= (CORE_IDLE_CFG_CLKOFF | CORE_IDLE_CFG_PWR_DOWN);
		mask |= INT_MASK_CORE;
		pcr |= pcr_mask;
	} else {
		cfg &= ~(CORE_IDLE_CFG_CLKOFF | CORE_IDLE_CFG_PWR_DOWN);
		mask &= ~INT_MASK_CORE;
		pcr &= ~pcr_mask;
	}

	mask &= ~INT_MASK_APMU;

	writel_relaxed(cfg, APMU_CORE_IDLE_CFG[ri]);
	writel_relaxed(mask, APMU_INT_MASK[ri]);
	writel_relaxed(pcr, APMU_PCR[ri]);
}


static void pxa1978_clear_state(u32 cpu, u32 cluster)
{
	pxa1978_set_cstate(cpu, cluster, 0);
	pxa1978_set_dstate(cpu, cluster, 0);
}

static void pxa1978_lowpower_config(u32 cpu, u32 cluster, u32 power_mode,
				u32 vote_state,
				u32 lowpower_enable)
{
	u32 c_state;

	/* clean up register setting */
	if (!lowpower_enable) {
		pxa1978_clear_state(cpu, cluster);
		return;
	}

	if (power_mode >= POWER_MODE_APPS_IDLE) {
		pxa1978_set_dstate(cpu, cluster, power_mode);
		c_state = POWER_MODE_CORE_POWERDOWN;
	} else
		c_state = power_mode;

	pxa1978_set_cstate(cpu, cluster, c_state);
}

static void pxa1978_save_wakeup(void)
{

}
static void pxa1978_restore_wakeup(void)
{
}

static void pxa1978_set_pmu(u32 cpu, u32 calc_state, u32 vote_state)
{
	u32 mpidr = read_cpuid_mpidr();
	u32 cluster;
	cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);
	cluster = MPIDR_AFFINITY_LEVEL(mpidr, 1);

	pxa1978_lowpower_config(cpu, cluster, calc_state, vote_state, 1);
}

static void pxa1978_clr_pmu(u32 cpu)
{
	u32 mpidr = read_cpuid_mpidr();
	u32 cluster;
	cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);
	cluster = MPIDR_AFFINITY_LEVEL(mpidr, 1);

	pxa1978_lowpower_config(cpu, cluster, 0, 0, 0);
}

static struct platform_power_ops pxa1978_power_ops = {
	.set_pmu	= pxa1978_set_pmu,
	.clr_pmu	= pxa1978_clr_pmu,
	.save_wakeup	= pxa1978_save_wakeup,
	.restore_wakeup	= pxa1978_restore_wakeup,
};

static struct platform_idle pxa1978_idle = {
	.cpudown_state		= POWER_MODE_CORE_POWERDOWN,
	.clusterdown_state	= POWER_MODE_MP_POWERDOWN,
	.wakeup_state		= POWER_MODE_APPS_IDLE,
	.hotplug_state		= POWER_MODE_UDR,
	/*
	 * l2_flush_state indicates to the logic in mcpm_plat.c
	 * to trigger calls to save_wakeup/restore_wakeup,
	 * but is also required for a cluster off indication to smc.
	 */
	.l2_flush_state		= POWER_MODE_MP_POWERDOWN,
	.ops			= &pxa1978_power_ops,
	.states			= pxa1978_modes,
	.state_count		= ARRAY_SIZE(pxa1978_modes),
};

/*
 * It turns out that cluster 1 won't exit reset properly unless
 * some other APMU_PCR does not allow C1 power down/clock off.
 * This function sets up the APMU_PCR's so that only cluster CPU's
 * actively vote to disable the cluster shutdown.
 * Therefore we delay this until after SMP init.
 */
static int __init pxa1978_setup_apmu(void)
{
	int i;

	if (!of_machine_is_compatible("marvell,pxa1978"))
		return -ENODEV;

	for (i = 0; i < 4; i++)
		writel_relaxed(readl_relaxed(APMU_PCR[i]) | APMU_PCR_C1_OFF,
			       APMU_PCR[i]);
	for (; i < 6; i++)
		writel_relaxed(readl_relaxed(APMU_PCR[i]) | APMU_PCR_C0_OFF,
			       APMU_PCR[i]);
	/* Missing cores */
	for (; i < 8; i++)
		writel_relaxed(APMU_PCR_DEFAULT, APMU_PCR[i]);

	writel_relaxed(APMU_PCR_DEFAULT,
		       apmu_virt_addr + APMU_PCR8_OFFS); /* SP */
	return 0;
}
arch_initcall(pxa1978_setup_apmu);

static void __init pxa1978_mappings(void)
{
	int i;

	apmu_virt_addr = regs_addr_get_va(REGS_ADDR_APMU);

	for (i = 0; i < (MAX_CPU*MAX_CLUS); i++) {
		APMU_CORE_IDLE_CFG[i] =
			apmu_virt_addr + APMU_CORE_IDLE_CFG_OFFS[i];
		APMU_PCR[i] =
			apmu_virt_addr + APMU_PCR_OFFS[i];
		APMU_INT_MASK[i] =
			apmu_virt_addr + APMU_INT_MASK_OFFS[i];
		APMU_CORE_RESET[i] =
			apmu_virt_addr + APMU_CORE_RESET_OFFS[i];
	}

	mpmu_virt_addr = regs_addr_get_va(REGS_ADDR_MPMU);
}

void pxa1978_gic_raise_softirq(const struct cpumask *mask, unsigned int irq)
{
	int targ_cpu;

	gic_raise_softirq(mask, irq);
	preempt_disable();
	for_each_cpu(targ_cpu, mask) {
		BUG_ON(targ_cpu >= CONFIG_NR_CPUS);
		/* TBD: physical CPU number might be different */
		writel_relaxed(1, APMU_CORE_RESET[targ_cpu]);
	}
	preempt_enable();
}

static const struct of_device_id mcpm_of_match[] __initconst = {
	{ .compatible = "arm,mcpm",},
	{},
};

/*
 * This is an early as registration is needed to initialize SMP and boot CPU's.
 */
static int __init pxa1978_lowpower_init(void)
{
	struct device_node *np;

	if (!of_machine_is_compatible("marvell,pxa1978"))
		return -ENODEV;

	np = of_find_matching_node(NULL, mcpm_of_match);
	if (!np || !of_device_is_available(np))
		return -ENODEV;
	pr_info("Initialize pxa1978 low power controller based on mcpm.\n");

	pxa1978_mappings();
	mcpm_plat_power_register(&pxa1978_idle);

	set_smp_cross_call(pxa1978_gic_raise_softirq);
	return 0;
}
early_initcall(pxa1978_lowpower_init);
