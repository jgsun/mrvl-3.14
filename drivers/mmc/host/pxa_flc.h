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
#ifndef __PXA_FLC_HW_H
#define __PXA_FLC_HW_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/io.h>

#include <linux/mmc/sdhci.h>

/*
 * FLC-MCK Controller registers
 */
#define FLC_REG_MMAP	0x900
#define  FLC_MMAP_ENABLE	0x1
#define  FLC_MMAP_ADDR_OFFSET	23
#define  FLC_MMAP_ADDR_H_OFFSET	8
#define  FLC_MMAP_SIZE_OFFSET	16

#define FLC_MMAP_START_INDEX 0x7

#define FLC_REG_MMAP_NC	0x908
#define  FLC_MMAP_NC_ADDR_OFFSET	23
#define  FLC_MMAP_NC_ADDR_H_OFFSET	8
#define  FLC_MMAP_NC_SIZE_OFFSET	16
#define  FLC_MMAP_NC_RATIO_OFFSET	4
#define  FLC_MMAP_NC_MAP_DIS	0
#define  FLC_MMAP_NC_MAP_HIGH	1
#define  FLC_MMAP_NC_MAP_LOW	2

#define FLC_REG_DEBUG_CONTROL	0x910
#define  FLC_DEBUG_CWF_LF_EN (1 << 24)
#define  FLC_DEBUG_H_C_INT_LOCLKED_ONLY (1 << 25)

#define FLC_REG_SDH_REG_OFFSET	0x970
#define FLC_REG_SDH_BLK_OFFSET	0x974
#define FLC_REG_SDH_RESP_TIMEOUT	0x97C

#define FLC_MCK_REG_IER	0x144
#define  FLC_MCK_IER_FLC_REGION	0xFC000000
#define  FLC_MCK_IER_FLC_LF_DONE (1 << 31)
#define  FLC_MCK_IER_FLC_MNT_DONE (1 << 30)
#define  FLC_MCK_IER_FLC_HC (1 << 29)
#define  FLC_MCK_IER_FLC_SDH (1 << 28)
#define  FLC_MCK_IER_FLC_LF_ERR (1 << 27)
#define  FLC_MCK_IER_FLC_EVICT_ERR (1 << 26)

#endif /* __PXA_FLC_HW_H */
