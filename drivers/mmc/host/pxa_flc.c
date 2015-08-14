/*
 * Copyright (C) 2015 Marvell International Ltd.
 *		Jialing Fu <jlfu@marvell.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/clk/mmp_sdh_tuning.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/memory.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/platform_data/pxa_sdhci.h>
#include <linux/flc.h>

#include "pxa_flc.h"
#include "sdhci.h"
#include "sdhci-pxa.h"
#include "sdhci-pltfm.h"

/* FLC_SDH timeout count, 26MHz base, below is about 10 Sec */
#define FLC_SDH_RESP_TIMEOUT_BASE 26000000
#define FLC_SDH_RESP_TIMEOUT_SEC 10
#define FLC_SDH_RESP_TIMEOUT (FLC_SDH_RESP_TIMEOUT_BASE * FLC_SDH_RESP_TIMEOUT_SEC)

#define FLC_REG_ERR (0xFFFFFFFF)

/*
 * flc_size_to_area_length_reg & flc_size_offset_check:
 *   convert size to Reg MMAP/MMAP_NC "area length region"
 *   Also used to check whether DDR/MMC size/offset is valid or not
 *
 * TODO:
 * Below coding is not a best efficient method,
 * but it is easy to understand and modify if need.
 */
static const u64 flc_a_l_table[] = {
	(u64)8 << 20, /* 0x7 8MB */
	(u64)16 << 20, /* 0x8 16MB */
	(u64)32 << 20, /* 0x9 32MB */
	(u64)64 << 20,
	(u64)128 << 20,
	(u64)256 << 20,
	(u64)512 << 20,
	(u64)1 << 30,
	(u64)2 << 30,
	(u64)4 << 30,
	(u64)8 << 30,
	(u64)16 << 30,
	(u64)32 << 30,
	(u64)64 << 30,
	(u64)128 << 30,
	(u64)256 << 30,
	(u64)512 << 30,
	(u64)1024 << 30,	/* 0x18 1TB */
};

#define FLC_A_L_TABLE_SIZE ARRAY_SIZE(flc_a_l_table)

static u32 flc_size_to_area_length_reg(u64 size)
{
	int index = 0;
	u32 reg_mmap_nc = FLC_REG_ERR;

	while (index < FLC_A_L_TABLE_SIZE) {
		if (size == flc_a_l_table[index]) {
			reg_mmap_nc = (index + FLC_MMAP_START_INDEX)
					<< FLC_MMAP_SIZE_OFFSET;
			return reg_mmap_nc;
		}

		index++;
	}

	pr_err("FLC size_offset 0x%llx is not support\n", size);
	return reg_mmap_nc;
}
#define flc_size_offset_check(size) flc_size_to_area_length_reg(size)

static u32 flc_size_to_nc_ratio_reg(u64 nc_size, u64 c_size)
{
	u32 reg_mmap_nc = FLC_REG_ERR;

	/* avoid float calacuating */
	if (nc_size == c_size) {
		/* real ratio is 1 in fact */
		reg_mmap_nc = (0 << FLC_MMAP_NC_RATIO_OFFSET);
	} else if (nc_size + nc_size == c_size) {
		/* real ratio is 0.5 */
		reg_mmap_nc = (1 << FLC_MMAP_NC_RATIO_OFFSET);
	} else if (nc_size == c_size + c_size) {
		/* real ratio is 2 */
		reg_mmap_nc = (2 << FLC_MMAP_NC_RATIO_OFFSET);
	} else {
		pr_err("nc_size 0x%llx - c_size 0x%llx is not support\n",
			nc_size, c_size);
	}

	return reg_mmap_nc;
}

static u32 flc_addr_to_addr_reg(u64 addr)
{
	u32 reg;

	/* mmap[31:23] = addr[31:23], mmap[15:8] = addr[39:32] */
	reg = (addr & 0xFF800000) | ((addr & 0xFF00000000) >> 24);

	return reg;
}

/*
 * eMMC/DDR range used by FLC
 *  only the settings are available/suitable, the FLC can be enable,
 *  So it is very very important information!
 *
 * Below are the ways to set MMC/DDR range
 * Case A:
 *  Getting from boot cmdline has highest priority
 *  Format: flc_mmc=size@start flc_ddr=size@start (counted by Bytes)
 *  Example:flc_mmc=1G@14G flc_ddr=256M@256M
 *          flc_mmc=0x4000000@14G flc_ddr=0x10000000@0x10000000
 *
 * Case B:
 *  If u-boot doesn't pass the info, Set "CONFIG_FLC_MMC_DEBUG" to
 *	Y: hard coding eMMC/DDR range, force to enable FLC
 *	N: Nobody set eMMC/DDR range, do not enable FLC to avoid
 *	   unexpected issues
 */
#ifdef CONFIG_FLC_MMC_DEBUG
static u64 flc_mmc_start = ((u64)10 << 30); /* 10G */
static u64 flc_mmc_size = ((u64)1 << 30); /* 1G */
static u64 flc_ddr_start = ((u64)256 << 20); /* 256M */
static u64 flc_ddr_size = ((u64)256 << 20); /* 256M */
static u64 flc_cma_size = ((u64)128 << 20); /* 128M */
#else
static u64 flc_mmc_start;
static u64 flc_mmc_size;
static u64 flc_ddr_start;
static u64 flc_ddr_size;
static u64 flc_cma_size = -1;
#endif

#define FLC_NC_START	0x0
#define FLC_NC_SIZE	flc_ddr_start
#define FLC_C_START	flc_ddr_start
#define FLC_C_SIZE	flc_ddr_size
#define FLC_START	0x40000000
#define FLC_SIZE	flc_mmc_size
#define FLC_MMC_START	flc_mmc_start
#define FLC_MMC_SIZE	flc_mmc_size

static int __init early_flc_get_mmc_setting(char *p)
{
	/*
	 * Get the size and offset of MMC range which maps to flc cache
	 * by byte
	 */
	char *endp;
	u64 size = 0;
	u64 start = 0;

	size = memparse(p, &endp);
	if (*endp == '@')
		start = memparse(endp + 1, NULL);

	if (FLC_REG_ERR != flc_size_offset_check(size)) {
		flc_mmc_size = size;
		flc_mmc_start = start;
	}
	return 0;
}
early_param("flc_mmc", early_flc_get_mmc_setting);

static int __init early_flc_get_ddr_setting(char *p)
{
	/*
	 * Get the size and offset of ddr range which maps to flc cache
	 * by byte
	 */
	char *endp;
	u64 size = 0;
	u64 start = 0;

	size = memparse(p, &endp);
	if (*endp == '@')
		start = memparse(endp + 1, NULL);

	if ((FLC_REG_ERR != flc_size_offset_check(size)) &&
		(FLC_REG_ERR != flc_size_offset_check(start))) {
		flc_ddr_size = size;
		flc_ddr_start = start;
	}

	return 0;
}
early_param("flc_ddr", early_flc_get_ddr_setting);

static int __init early_flc_cma(char *p)
{
	pr_debug("%s(%s)\n", __func__, p);
	flc_cma_size = memparse(p, &p);
	flc_cma_size = min(flc_cma_size, flc_ddr_size);

	return 0;
}
early_param("flc_cma", early_flc_cma);

/*
 * Using flc_writb/w/l macro with pr_debug support
 * It can be used for a useful debugging method if need
 */
#define flc_writeb(val, reg) \
{	\
	pr_debug("write reg8_0x%p = 0x%x\n", reg, val);	\
	writeb(val, reg);	\
}

#define flc_writew(val, reg) \
{	\
	pr_debug("write reg16_0x%p = 0x%x\n", reg, val);	\
	writew(val, reg);	\
}

#define flc_writel(val, reg) \
{	\
	pr_debug("write reg32_0x%p = 0x%x\n", reg, val);	\
	writel(val, reg);	\
}

static struct flc_host *pxa_flc;
struct flc_host *get_flc_host(void)
{
	if (!pxa_flc)
		pxa_flc = kzalloc(sizeof(struct flc_host), GFP_KERNEL);

	return pxa_flc;
}

#ifdef CONFIG_FLC_CACHE_LOCK_SIZE_MBTYES
#define FLC_CMA_SIZE_MBYTES CONFIG_FLC_CACHE_LOCK_SIZE_MBTYES
#else
#define FLC_CMA_SIZE_MBYTES 0
#endif

static int flc_memory_hotplug(u64 addr, int size, bool on)
{
	int ret = -1, rsv_size = 0;

	if (flc_cma_size != -1) {
		rsv_size = flc_cma_size;
	} else {
#ifdef CONFIG_FLC_CACHE_LOCK_SIZE_MBTYES
		rsv_size = FLC_CMA_SIZE_MBYTES * SZ_1M;
#endif
	}

	/* FIXME: set default reserve size as 1/2 of flc_ddr_size */
	if (!rsv_size)
		rsv_size = flc_ddr_size >> 1;

	if (on) {
		ret = memory_add_and_online(addr, size, rsv_size);
		if (!ret)
			flc_available = true;
		else
			WARN(1, "FLC memory hotplug failed\n");
	}
	return ret;
}

static irqreturn_t flc_mck_irq(int irq, void *dev_id)
{
	irqreturn_t result = IRQ_HANDLED;

	/* TODO: add more */
	pr_info_ratelimited("Mck IRQ happens\n");

	return result;
}

static void flc_mck_init(struct flc_host *flc)
{
	void __iomem *kaddr_mck = flc->mck_kaddr;
	int ret;
	u32 reg_tmp;
	u32 reg_mmap, reg_mmap_nc;

	reg_tmp = readl(kaddr_mck + FLC_REG_DEBUG_CONTROL);
	reg_tmp &= ~(FLC_DEBUG_CWF_LF_EN | FLC_DEBUG_H_C_INT_LOCLKED_ONLY);
	flc_writel(reg_tmp, kaddr_mck + FLC_REG_DEBUG_CONTROL);

	/* FLC_SDH base address */
	flc_writel(flc->flc_phys, kaddr_mck + FLC_REG_SDH_REG_OFFSET);

	/* FLC_SDH timeout count, 26MHz base, below is about 10 Sec */
	flc_writel(FLC_SDH_RESP_TIMEOUT, kaddr_mck + FLC_REG_SDH_RESP_TIMEOUT);

	/* Enable SDH error interupt */
	flc_writel(readl(kaddr_mck + FLC_MCK_REG_IER) | FLC_MCK_IER_FLC_SDH,
		kaddr_mck + FLC_MCK_REG_IER);

	/* eMMC block index map, transfer byte to sector */
	flc_writel((u32)(flc_mmc_start >> 9), kaddr_mck + FLC_REG_SDH_BLK_OFFSET);

	/*
	 * The relate setting for FLC NC MMAP register
	 *
	 * As FLC_NC_START,FLC_NC_SIZE... have been checked during module_init
	 * Here using flc_size_to_area_length_reg & flc_size_to_nc_ratio_reg is
	 * safe.
	 */
	reg_mmap_nc = FLC_MMAP_NC_MAP_LOW | flc_addr_to_addr_reg(FLC_NC_START);
	reg_mmap_nc |= flc_size_to_area_length_reg(FLC_NC_SIZE);
	reg_mmap_nc |= flc_size_to_nc_ratio_reg(FLC_NC_SIZE, FLC_C_SIZE);
	flc_writel(reg_mmap_nc, kaddr_mck + FLC_REG_MMAP_NC);

	/*
	 * The relate setting for FLC MMAP register
	 * Also it is safe to use flc_size_to_area_length_reg
	 * and flc_size_to_nc_ratio_reg
	 */
	reg_mmap = FLC_MMAP_ENABLE | flc_addr_to_addr_reg(FLC_START);
	reg_mmap |= flc_size_to_area_length_reg(FLC_SIZE);
	flc_writel(reg_mmap, kaddr_mck + FLC_REG_MMAP);

	ret = request_irq(flc->mck_irq, flc_mck_irq, IRQF_SHARED,
				  "flc_mck", flc);
	pr_debug("flc mck irq request ret = %d\n", ret);
	return;
}

static void flc_sdh_reset(struct flc_host *flc)
{
	void __iomem *kaddr_slot_flc = flc->flc_kaddr;
	unsigned long timeout;
	u8 mask = SDHCI_RESET_ALL;

	/* Wait max 100 ms */
	timeout = 100;
	flc_writeb(mask, kaddr_slot_flc + SDHCI_SOFTWARE_RESET);
	while (readb(kaddr_slot_flc + SDHCI_SOFTWARE_RESET) & mask) {
		if (timeout == 0) {
			pr_err("%s: Reset 0x%x never completed.\n",
			__func__, (int)mask);
			return;
		}
		timeout--;
		msleep(1);
	}
}

static irqreturn_t flc_sdh_irq(int irq, void *dev_id)
{
	irqreturn_t result = IRQ_HANDLED;
	struct flc_host *flc = dev_id;
	void __iomem *kaddr_slot_flc = flc->flc_kaddr;
	u32 intmask;

	intmask = readl(kaddr_slot_flc + SDHCI_INT_STATUS);

	pr_debug("*flc got interrupt: 0x%08x\n", intmask);
	flc_writel(intmask, kaddr_slot_flc + SDHCI_INT_STATUS);

	return result;
}

static int pxa_flc_init(struct flc_host *flc)
{
	struct sdhci_host *slot_cpu = flc->parent;
	void __iomem *kaddr_slot_flc = flc->flc_kaddr;
	void __iomem *kaddr_slot_cpu = slot_cpu->ioaddr;
	u16 reg16;
	u32 reg32;
	int ret = 0;

	if (!kaddr_slot_cpu) {
		pr_err("FLC: sdh cpu slot is not ready\n");
		return -EINVAL;
	}

	pr_info("flc init\n");
	pr_debug("flc irq is %d, mck irq is %d\n", flc->flc_irq, flc->mck_irq);

	/* reset flc slot sdh totally, including the bus arbitor */
	flc_sdh_reset(flc);

	/* set cpu slot reg, let FLC and CPU access eMMC bus seperatelly */
	reg32 = readl(kaddr_slot_cpu + SDHCI_FLC_ARBITOR);
	reg32 &= ~(SDHCI_FLC_HIGH_PRIORITY | SDHCI_FLC_SW_RST);
	flc_writel(reg32, kaddr_slot_cpu + SDHCI_FLC_ARBITOR);
	/* allow flc slot to access eMMC, prepare for RX tuning */
	flc_writel(SDHCI_FLC_EN, kaddr_slot_flc + SDHCI_FLC_ARBITOR);

	/* timeout reg: 0xE is max timeout value */
	flc_writeb(0xE, kaddr_slot_flc + SDHCI_TIMEOUT_CONTROL);

	/* clock rate reg: same as cpu slot sdh */
	flc_writew(readw(kaddr_slot_cpu + SDHCI_CLOCK_CONTROL),
		kaddr_slot_flc + SDHCI_CLOCK_CONTROL);
	msleep(20);

	/* Host Control Reg: Bus width, DMA mode, and others */
	reg16 = readw(kaddr_slot_cpu + SDHCI_HOST_CONTROL);
	reg16 &= ~SDHCI_CTRL_LED;
	reg16 = (reg16 & (~SDHCI_CTRL_DMA_MASK)) | SDHCI_CTRL_SDMA;
	flc_writew(reg16, kaddr_slot_flc + SDHCI_HOST_CONTROL);

	/* power control reg: same as cpu slot sdh */
	flc_writeb(readb(kaddr_slot_cpu + SDHCI_POWER_CONTROL),
		kaddr_slot_flc + SDHCI_POWER_CONTROL);

	/* choose the same speed mode as CPU slot */
	flc_writew(readw(kaddr_slot_cpu + SDHCI_HOST_CONTROL2),
		kaddr_slot_flc + SDHCI_HOST_CONTROL2);

	/* SDMA size is 32KB and block size is 512B */
	flc_writel(SDHCI_MAKE_BLKSZ(0x3, 0x200),
		kaddr_slot_flc + SDHCI_BLOCK_SIZE);

	/*
	 * TODO:
	 * 1) fine tune TX Reg if need when real silicon arrive
	 * 2) add RX tuning for HS200 mode
	 */
	flc_writel(readl(kaddr_slot_cpu + SD_TX_CFG_REG),
		kaddr_slot_flc + SD_TX_CFG_REG);

	/* SDHCI_INT_ENABLE: 0x813F0003 */
	flc_writel(SDHCI_INT_CRC_STATUS | SDHCI_INT_ACMD12ERR |
		SDHCI_INT_DATA_CRC | SDHCI_INT_DATA_TIMEOUT |
		SDHCI_INT_INDEX | SDHCI_INT_END_BIT |
		SDHCI_INT_CRC | SDHCI_INT_TIMEOUT |
		SDHCI_INT_DATA_END | SDHCI_INT_RESPONSE,
		kaddr_slot_flc + SDHCI_INT_ENABLE);

	/* SDHCI_SIGNAL_ENABLE: 0x837F0000 */
	flc_writel(SDHCI_INT_CRC_STATUS | SDHCI_INT_ADMA_ERROR |
		SDHCI_INT_ACMD12ERR | SDHCI_INT_DATA_END_BIT |
		SDHCI_INT_DATA_CRC | SDHCI_INT_DATA_TIMEOUT |
		SDHCI_INT_INDEX | SDHCI_INT_END_BIT |
		SDHCI_INT_CRC | SDHCI_INT_TIMEOUT,
		kaddr_slot_flc + SDHCI_SIGNAL_ENABLE);

	/*
	 * Bus arbitor:
	 * allow cpu & FLC slot access eMMC at the same time,
	 * and FLC has higher priority than CPU slot
	 */
	flc_writel(SDHCI_FLC_HW_RESUME_EN | SDHCI_FLC_ABORT_EN |
		SDHCI_FLC_HIGH_PRIORITY, kaddr_slot_cpu + SDHCI_FLC_ARBITOR);

	ret = request_irq(flc->flc_irq, flc_sdh_irq, IRQF_SHARED,
				  "flc_sdh", flc);
	pr_debug("flc irq request ret = %d\n", ret);

	flc_mck_init(flc);

	flc_memory_hotplug(FLC_START, FLC_SIZE, true);

	return ret;
}

static int __init flc_init_module(void)
{
	int ret = 0;
	struct flc_host *flc;

	if ((FLC_REG_ERR == flc_size_offset_check(FLC_NC_SIZE)) ||
		(FLC_REG_ERR == flc_size_offset_check(FLC_C_SIZE)) ||
		(FLC_REG_ERR == flc_size_offset_check(FLC_SIZE)) ||
		(FLC_REG_ERR == flc_size_to_nc_ratio_reg(FLC_NC_SIZE, FLC_C_SIZE))) {
		/*
		 * return here, if having any un-proper DDR/MMC setting
		 * and pxa_flc_init is not registered.
		 *
		 * if pxa_flc_init is not called, FLC is not enabled
		 */
		pr_err("FLC DDR/eMMC setting is not proper, FLC can't be enabled\n");
		pr_err("FLC_NC_SIZE= 0x%llx, FLC_C_SIZE= 0x%llx, FLC_SIZE= 0x%llx\n",
				FLC_NC_SIZE, FLC_C_SIZE, FLC_SIZE);
		return -EINVAL;
	}

	flc = get_flc_host();
	if (flc == NULL) {
		pr_err("fail to alloc flc_host\n");
		return -ENOMEM;
	}

	flc->flc_init = &pxa_flc_init;
	pr_info("FLC: init_module\n");

	return ret;
}
rootfs_initcall(flc_init_module);

static void __exit flc_exit_module(void)
{
	kfree(pxa_flc);
	pr_info("FLC: exit_module\n");

}
module_exit(flc_exit_module);

MODULE_AUTHOR("Jialing Fu");
MODULE_DESCRIPTION("Marvell flc module");
MODULE_LICENSE("GPL");
