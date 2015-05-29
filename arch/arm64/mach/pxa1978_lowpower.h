/*
 * linux/arch/arm64/mach/pxa1978_lowpower.h
 *
 * Author:	Anton Eidelman <antone@marvell.com>
 * Copyright:	(C) 2014 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#ifndef __MMP_MACH_PXA1978_LOWPOWER_H__
#define __MMP_MACH_PXA1978_LOWPOWER_H__

/* Allow all, except L2_RETENT that should be 0 in all PCR's to shutdown */
#define APMU_PCR_DEFAULT	0x3f071717

/* Cluster control bits */
#define APMU_PCR_C0_PWR_OFF	(1 << 0)
#define APMU_PCR_C0_CLK_OFF	(1 << 1)
#define APMU_PCR_C0_L2_RETENT	(1 << 3)
#define APMU_PCR_C1_PWR_OFF	(1 << 8)
#define APMU_PCR_C1_CLK_OFF	(1 << 9)
#define APMU_PCR_C1_L2_RETENT	(1 << 11)
#define APMU_PCR_C0_OFF		(APMU_PCR_C0_PWR_OFF | APMU_PCR_C0_CLK_OFF)
#define APMU_PCR_C1_OFF		(APMU_PCR_C1_PWR_OFF | APMU_PCR_C1_CLK_OFF)

/* APMU_CORE_IDLE_CFG register fields */
#define CORE_IDLE_CFG_PWR_DOWN	(1 << 0)
#define CORE_IDLE_CFG_CLKOFF	(1 << 1)
#define CORE_IDLE_CFG_DBGPWRDUP	(1 << 4)

/* APMU_CLSx_INT_MASK_x register fields */
#define INT_MASK_CORE		(1 << 0)
#define INT_MASK_APMU		(1 << 1)

#ifndef __ASSEMBLER__
extern void gic_raise_softirq(const struct cpumask *mask, unsigned int irq);
extern void __iomem *icu_get_base_addr(void);
#endif

#endif
