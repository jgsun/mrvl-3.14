/*
 * Copyright (C) 2015 Marvell International Ltd.
 *		Jialing Fu <jlfu@marvell.com>
 *		Tim Wang <wangtt@marvell.com>
 *		Kevin Liu <kliu5@marvell.com>
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
#ifndef __SDHCI_PXA_HW_H
#define __SDHCI_PXA_HW_H

/*
 * Marvell PXA SDH Controler private registers
 */
#define SD_CFG_FIFO_PARAM		0x100
#define  SDCFG_GEN_PAD_CLK_ON		(1<<6)
#define  SDCFG_GEN_PAD_CLK_CNT_MASK	0xFF
#define  SDCFG_GEN_PAD_CLK_CNT_SHIFT	24
#define  SDCFG_PIO_RDFC			(1<<0)

#define SD_FIFO_PARAM			0x104
#define  PAD_CLK_GATE_MASK		(0x3<<11)
#define  INT_CLK_GATE_MASK		(0x3<<8)

#define SD_SPI_MODE			0x108

#define SD_CLOCK_BURST_SIZE_SETUP	0x10A

#define SD_CE_ATA_1			0x10C

#define SD_CE_ATA_2			0x10E
#define  SDCE_MISC_INT			(1<<2)
#define  SDCE_MISC_INT_EN		(1<<1)
#define  SD_CE_ATA2_HS200_EN		(1<<10)
#define  SD_CE_ATA2_MMC_MODE		(1<<12)

#define SD_RX_CFG_REG			0x114
#define  RX_SDCLK_DELAY_SHIFT		8
#define  RX_SDCLK_SEL0_MASK		0x3
#define  RX_SDCLK_SEL1_MASK		0x3
#define  RX_SDCLK_SEL0_SHIFT		0
#define  RX_SDCLK_SEL1_SHIFT		2

#define SD_TX_CFG_REG			0x118
#define  TX_DELAY1_SHIFT			16
#define  TX_MUX_SEL			(0x1<<31)
#define  TX_SEL_BUS_CLK			(0x1<<30)

#define RX_TUNING_CFG_REG		0x11C
#define  RX_TUNING_WD_CNT_MASK		0x3F
#define  RX_TUNING_WD_CNT_SHIFT		8
#define  RX_TUNING_TT_CNT_MASK		0xFF
#define  RX_TUNING_TT_CNT_SHIFT		0

#endif /*__SDHCI_PXA_HW_H */
