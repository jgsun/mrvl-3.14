/*
 *  linux/drivers/clk/mmp/dvfs-pxa1956.c
 *
 *  based on drivers/clk/mmp/dvfs-pxa1936.c
 *  Copyright (C) 2014 Mrvl, Inc. by Liang Chen <chl@marvell.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/clk/mmp_sdh_tuning.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/mfd/88pm80x.h>
#include <linux/mfd/88pm88x.h>
#include <linux/mfd/88pm886.h>
#include <linux/clk/dvfs-dvc.h>
#include <linux/clk/mmpcpdvc.h>
#include <linux/clk/mmpfuse.h>

#include <linux/cputype.h>
#include "clk-plat.h"
#include "clk.h"

/* components that affect the vmin */
enum dvfs_comp {
	CORE = 0,
	CORE1,
	DDR,
	AXI,
	GC3D,
	GC2D,
	GC_SHADER,
	GCACLK,
	VPU,
	ISP,
	SDH0,
	SDH1,
	SDH2,
	VM_RAIL_MAX,
};

#define VL_MAX	8

#define ACTIVE_RAIL_FLAG	(AFFECT_RAIL_ACTIVE)
#define ACTIVE_M2_RAIL_FLAG	(AFFECT_RAIL_ACTIVE | AFFECT_RAIL_M2)
#define ACTIVE_M2_D1P_RAIL_FLAG \
	(AFFECT_RAIL_ACTIVE | AFFECT_RAIL_M2 | AFFECT_RAIL_D1P)

#define APMU_BASE		0xd4282800
#define GEU_BASE		0xd4292800
#define HWDVC_BASE		0xd4050000

/* Fuse information related register definition */
#define APMU_GEU		0x068
/* For chip DRO and profile */
#define NUM_PROFILES	16

#define GEU_FUSE_MANU_PARA_0 0x110
#define GEU_FUSE_MANU_PARA_1 0x114
#define GEU_FUSE_MANU_PARA_2 0x118
#define GEU_AP_CP_MP_ECC 0x11C
#define BLOCK0_RESERVED_1 0x120
#define BLOCK4_MANU_PARA1_0 0x2b4
#define BLOCK4_MANU_PARA1_1 0x2b8
#define CONFIG_SVC_TSMC 1

static unsigned int uiprofile;
static unsigned int helan4_maxfreq;
static struct comm_fuse_info fuseinfo;
static unsigned int fab_rev;
unsigned long (*freqs_cmb_helan4)[VL_MAX];
int *millivolts_helan4;

int ddr_800M_tsmc_svc_helan4[] = {1000, 975, 975, 975, 975, 975, 975, 975, 975,
975, 975, 975, 975, 975, 988, 1000};

struct svtrng {
	unsigned int min;
	unsigned int max;
	unsigned int profile;
};

static struct svtrng svtrngtb[] = {
	{290, 310, 15},
	{311, 322, 14},
	{323, 335, 13},
	{336, 348, 12},
	{349, 360, 11},
	{361, 373, 10},
	{374, 379, 9},
	{380, 386, 8},
	{387, 392, 7},
	{393, 398, 6},
	{399, 405, 5},
	{406, 411, 4},
	{412, 417, 3},
	{418, 424, 2},
	{425, 440, 1},
};

static void convert_max_freq(unsigned int uiCpuFreq)
{
	switch (uiCpuFreq) {
	case 0x0:
	case 0x5:
	case 0x6:
		pr_info("%s Part SKU is 1.5GHz; FuseBank0[179:174] = 0x%X", __func__, uiCpuFreq);
		helan4_maxfreq = CORE_1p5G;
		break;
	case 0x1:
	case 0xA:
		pr_info("%s Part SKU is 1.8GHz; FuseBank0[179:174] = 0x%X", __func__, uiCpuFreq);
		helan4_maxfreq = CORE_1p8G;
		break;
	case 0x2:
	case 0x3:
		pr_info("%s Part SKU is 2GHz; FuseBank0[179:174] = 0x%X", __func__, uiCpuFreq);
		helan4_maxfreq = CORE_2p0G;
		break;
	default:
		pr_info("%s ERROR: Fuse value (0x%X) not supported,default max freq 1.5G",
		__func__, uiCpuFreq);
		helan4_maxfreq = CORE_1p5G;
		break;
	}
	return;
}


unsigned int get_helan4_max_freq(void)
{
	return helan4_maxfreq;
}

static u32 convert_svtdro2profile(unsigned int uisvtdro)
{
	unsigned int uiprofile = 0, idx;

	if (uisvtdro >= 290 && uisvtdro <= 440) {
		for (idx = 0; idx < ARRAY_SIZE(svtrngtb); idx++) {
			if (uisvtdro >= svtrngtb[idx].min &&
				uisvtdro <= svtrngtb[idx].max) {
				uiprofile = svtrngtb[idx].profile;
				break;
			}
		}
	} else {
		uiprofile = 0;
		pr_info("SVTDRO is either not programmed or outside of the SVC spec range: %d",
			uisvtdro);
	}

	pr_info("%s uisvtdro[%d]->profile[%d]\n", __func__, uisvtdro, uiprofile);
	return uiprofile;
}

static unsigned int convertFusesToProfile_helan4(unsigned int uiFuses)
{
	unsigned int uiProfile = 0;
	unsigned int uiTemp = 1, uiTemp2 = 1;
	int i;

	for (i = 1; i < NUM_PROFILES; i++) {
		if (uiTemp == uiFuses)
			uiProfile = i;
		uiTemp |= uiTemp2 << (i);
	}

	pr_info("%s uiFuses[0x%x]->profile[%d]\n", __func__, uiFuses, uiProfile);
	return uiProfile;
}

static unsigned int convert_fab_revision(unsigned int fab_revision)
{
	unsigned int ui_fab = TSMC;
	if (fab_revision == 0)
		ui_fab = TSMC;
	else if (fab_revision == 1)
		ui_fab = SEC;

	return ui_fab;
}

static int __init __init_read_droinfo(void)
{
	struct fuse_info arg;
	unsigned int __maybe_unused uigeustatus = 0;
	unsigned int uiProfileFuses, uiSVCRev, uiFabRev, guiProfile;
	unsigned int uiBlock0_GEU_FUSE_MANU_PARA_0, uiBlock0_GEU_FUSE_MANU_PARA_1;
	unsigned int uiBlock0_GEU_FUSE_MANU_PARA_2, uiBlock0_GEU_AP_CP_MP_ECC;
	unsigned int  uiBlock0_BLOCK0_RESERVED_1, uiBlock4_MANU_PARA1_0, uiBlock4_MANU_PARA1_1;
	unsigned int uiAllocRev, uiRun, uiWafer, uiX, uiY, uiParity;
	unsigned int uiLVTDRO_Avg, uiSVTDRO_Avg, uiSIDD1p05 = 0, uiSIDD1p30 = 0, smc_ret = 0;
	unsigned int uiCpuFreq;
	unsigned int uiskusetting = 0;
	void __iomem *apmu_base, *geu_base;

	apmu_base = ioremap(APMU_BASE, SZ_4K);
	if (apmu_base == NULL) {
		pr_err("error to ioremap APMU base\n");
		return -EINVAL;
	}

	geu_base = ioremap(GEU_BASE, SZ_4K);
	if (geu_base == NULL) {
		pr_err("error to ioremap GEU base\n");
		return -EINVAL;
	}

	uigeustatus = __raw_readl(apmu_base + APMU_GEU);
	if (!(uigeustatus & 0x30)) {
		__raw_writel((uigeustatus | 0x30), apmu_base + APMU_GEU);
		udelay(10);
	}

	smc_ret = smc_get_fuse_info(0xc2003000, (void *)&arg);
	if (smc_ret == 0) {
		/* GEU_FUSE_MANU_PARA_0	0x110	Bank 0 [127: 96] */
		uiBlock0_GEU_FUSE_MANU_PARA_0 = arg.arg0;
		/* GEU_FUSE_MANU_PARA_1	0x114	Bank 0 [159:128] */
		uiBlock0_GEU_FUSE_MANU_PARA_1 = arg.arg1;
		/* GEU_FUSE_MANU_PARA_2	0x118	Bank 0 [191:160] */
		uiBlock0_GEU_FUSE_MANU_PARA_2 = arg.arg2;
		/* GEU_AP_CP_MP_ECC		0x11C	Bank 0 [223:192] */
		uiBlock0_GEU_AP_CP_MP_ECC = arg.arg3;
		/* BLOCK0_RESERVED_1 0x120	Bank 0 [255:224] */
		uiBlock0_BLOCK0_RESERVED_1 = arg.arg4;
		/* Fuse Block 4 191:160 */
		uiBlock4_MANU_PARA1_0 = arg.arg5;
		/* Fuse Block 4 255:192 */
		uiBlock4_MANU_PARA1_1  = arg.arg6;
	} else {
		uiBlock0_GEU_FUSE_MANU_PARA_0 = __raw_readl(geu_base + GEU_FUSE_MANU_PARA_0);
		uiBlock0_GEU_FUSE_MANU_PARA_1 = __raw_readl(geu_base + GEU_FUSE_MANU_PARA_1);
		uiBlock0_GEU_FUSE_MANU_PARA_2 = __raw_readl(geu_base + GEU_FUSE_MANU_PARA_2);
		uiBlock0_GEU_AP_CP_MP_ECC = __raw_readl(geu_base + GEU_AP_CP_MP_ECC);
		uiBlock0_BLOCK0_RESERVED_1 = __raw_readl(geu_base + BLOCK0_RESERVED_1);
		uiBlock4_MANU_PARA1_0 = __raw_readl(geu_base + BLOCK4_MANU_PARA1_0);
		uiBlock4_MANU_PARA1_1  = __raw_readl(geu_base + BLOCK4_MANU_PARA1_1);
	}

	uiAllocRev = uiBlock0_GEU_FUSE_MANU_PARA_0 & 0x7;
	uiRun = ((uiBlock0_GEU_FUSE_MANU_PARA_1 & 0x3) << 24) |
		((uiBlock0_GEU_FUSE_MANU_PARA_0 >> 8) & 0xffffff);
	uiWafer = (uiBlock0_GEU_FUSE_MANU_PARA_1 >>  2) & 0x1f;
	uiX = (uiBlock0_GEU_FUSE_MANU_PARA_1 >>  7) & 0xff;
	uiY = (uiBlock0_GEU_FUSE_MANU_PARA_1 >> 15) & 0xff;
	uiParity = (uiBlock0_GEU_FUSE_MANU_PARA_1 >> 23) & 0x1;
	uiSVCRev = (uiBlock0_BLOCK0_RESERVED_1    >> 13) & 0x3;
	uiSVTDRO_Avg = ((uiBlock0_GEU_FUSE_MANU_PARA_2 & 0x3) << 8) |
		((uiBlock0_GEU_FUSE_MANU_PARA_1 >> 24) & 0xff);
	uiLVTDRO_Avg = (uiBlock0_GEU_FUSE_MANU_PARA_2 >>  4) & 0x3ff;
	uiProfileFuses = (uiBlock0_BLOCK0_RESERVED_1    >> 16) & 0xffff;
	uiSIDD1p05 = uiBlock4_MANU_PARA1_0 & 0x3ff;
	uiSIDD1p30 = ((uiBlock4_MANU_PARA1_1 & 0x3) << 8) |
		((uiBlock4_MANU_PARA1_0 >> 24) & 0xff);
	uiCpuFreq = (uiBlock0_GEU_FUSE_MANU_PARA_2 >>  14) & 0x3f;
	uiFabRev = (uiBlock4_MANU_PARA1_1 >> 4) & 0x3;
	fab_rev = convert_fab_revision(uiFabRev);
	/*bit 201 ~ 202 for UDR voltage*/
	uiskusetting = (uiBlock4_MANU_PARA1_1 >> 9) & 0x3;

	guiProfile = convertFusesToProfile_helan4(uiProfileFuses);

	if (guiProfile == 0)
		guiProfile = convert_svtdro2profile(uiSVTDRO_Avg);

	convert_max_freq(uiCpuFreq);

	fuseinfo.fab = fab_rev;
	fuseinfo.lvtdro = uiLVTDRO_Avg;
	fuseinfo.svtdro = uiSVTDRO_Avg;

	fuseinfo.profile = guiProfile;
	fuseinfo.iddq_1050 = uiSIDD1p05;
	fuseinfo.iddq_1030 = uiSIDD1p30;
	fuseinfo.skusetting = uiskusetting;
	plat_fill_fuseinfo(&fuseinfo);

	pr_info(" \n");
	pr_info("     *************************** \n");
	pr_info("     *  ULT: %08X%08X  * \n", uiBlock0_GEU_FUSE_MANU_PARA_1,
		uiBlock0_GEU_FUSE_MANU_PARA_0);
	pr_info("     *************************** \n");
	pr_info("     ULT decoded below \n");
	pr_info("     alloc_rev = %d\n", uiAllocRev);
	pr_info("           fab = %d\n",      fab_rev);
	pr_info("           run = %d (0x%07X)\n", uiRun, uiRun);
	pr_info("         wafer = %d\n",    uiWafer);
	pr_info("             x = %d\n",        uiX);
	pr_info("             y = %d\n",        uiY);
	pr_info("        parity = %d\n",   uiParity);
	pr_info("        skusetting [201:202] = %d\n", uiskusetting);
	pr_info("     *************************** \n");
	if (0 == fab_rev)
		pr_info("     *  Fab   = TSMC 28LP (%d)\n",    fab_rev);
	else if (1 == fab_rev)
		pr_info("     *  Fab   = SEC 28LP (%d)\n",    fab_rev);
	else
		pr_info("     *  FabRev (%d) not currently supported\n",    fab_rev);
	pr_info("     *  wafer = %d\n", uiWafer);
	pr_info("     *  x     = %d\n",     uiX);
	pr_info("     *  y     = %d\n",     uiY);
	pr_info("     *************************** \n");
	pr_info("     *  Iddq @ 1.05V = %dmA\n",   uiSIDD1p05);
	pr_info("     *  Iddq @ 1.30V = %dmA\n",   uiSIDD1p30);
	pr_info("     *************************** \n");
	pr_info("     *  LVTDRO = %d\n",   uiLVTDRO_Avg);
	pr_info("     *  SVTDRO = %d\n",   uiSVTDRO_Avg);
	pr_info("     *  SVC Revision = %2d\n", uiSVCRev);
	pr_info("     *  SVC Profile  = %2d\n", guiProfile);
	pr_info("     *************************** \n");
	pr_info(" \n");

	uiprofile = guiProfile;
	return 0;

}

#define sdh_dvfs { DUMMY_VL_TO_KHZ(0), DUMMY_VL_TO_KHZ(1), DUMMY_VL_TO_KHZ(2), DUMMY_VL_TO_KHZ(3),\
		  DUMMY_VL_TO_KHZ(4), DUMMY_VL_TO_KHZ(5), DUMMY_VL_TO_KHZ(6), DUMMY_VL_TO_KHZ(7)},\
		{ DUMMY_VL_TO_KHZ(0), DUMMY_VL_TO_KHZ(1), DUMMY_VL_TO_KHZ(2), DUMMY_VL_TO_KHZ(3),\
		  DUMMY_VL_TO_KHZ(4), DUMMY_VL_TO_KHZ(5), DUMMY_VL_TO_KHZ(6), DUMMY_VL_TO_KHZ(7)},\
		{ DUMMY_VL_TO_KHZ(0), DUMMY_VL_TO_KHZ(1), DUMMY_VL_TO_KHZ(2), DUMMY_VL_TO_KHZ(3),\
		  DUMMY_VL_TO_KHZ(4), DUMMY_VL_TO_KHZ(5), DUMMY_VL_TO_KHZ(6), DUMMY_VL_TO_KHZ(7)}

static unsigned long freqs_cmb_1956_tsmc[][VM_RAIL_MAX][VL_MAX] = {
	[0] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{312000, 416000, 416000, 416000, 624000, 832000, 1057000, 1248000}, /* CLUSTER0 */
		{416000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 797000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{0, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{0, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{312000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{208000, 312000, 312000, 416000, 416000, 508000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[1] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{416000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{832000, 832000, 832000, 832000, 832000, 1491000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{312000, 312000, 312000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{705000, 705000, 705000, 705000, 705000, 832000, 832000, 832000}, /* GC3D */
		{312000, 312000, 312000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{705000, 705000, 705000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{416000, 416000, 416000, 416000, 528000, 528000, 528000, 528000}, /* VPU */
		{416000, 416000, 416000, 416000, 450000, 531000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[2] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{416000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{832000, 832000, 832000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{312000, 312000, 312000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{624000, 624000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{312000, 312000, 312000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{705000, 705000, 705000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{416000, 416000, 416000, 416000, 528000, 528000, 528000, 528000}, /* VPU */
		{416000, 416000, 416000, 416000, 450000, 531000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[3] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{416000, 416000, 416000, 624000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{624000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{312000, 312000, 312000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{624000, 624000, 624000, 705000, 705000, 832000, 832000, 832000}, /* GC3D */
		{312000, 312000, 312000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{705000, 705000, 705000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{416000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{312000, 312000, 312000, 416000, 416000, 531000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[4] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{416000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{624000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{312000, 312000, 312000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{624000, 624000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{312000, 312000, 312000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{624000, 624000, 624000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{416000, 416000, 416000, 416000, 528000, 528000, 528000, 528000}, /* VPU */
		{312000, 312000, 312000, 416000, 450000, 531000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[5] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{416000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{624000, 624000, 624000, 624000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{624000, 624000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{208000, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{624000, 624000, 624000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{416000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{312000, 312000, 312000, 416000, 416000, 531000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[6] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{416000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{624000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{624000, 624000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{208000, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{624000, 624000, 624000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{416000, 416000, 416000, 416000, 528000, 528000, 528000, 528000}, /* VPU */
		{312000, 312000, 312000, 416000, 450000, 531000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[7] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{416000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{624000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{208000, 208000, 312000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{416000, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{208000, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{416000, 416000, 624000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{416000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{312000, 312000, 312000, 416000, 416000, 531000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[8] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{416000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{624000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{416000, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{208000, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{416000, 416000, 624000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{416000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{312000, 312000, 312000, 416000, 450000, 531000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[9] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{416000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{416000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{208000, 208000, 312000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{416000, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{208000, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{416000, 416000, 624000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{416000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{312000, 312000, 312000, 416000, 416000, 531000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[10] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{312000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{416000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{416000, 416000, 416000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{208000, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{416000, 624000, 624000, 705000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{416000, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{312000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{312000, 312000, 312000, 416000, 416000, 508000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[11] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{312000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{416000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 667000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{312000, 416000, 416000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{0, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{156000, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{0, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{312000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{208000, 312000, 312000, 416000, 416000, 508000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[12] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{312000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{416000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 797000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{0, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{0, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{312000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{208000, 312000, 312000, 416000, 416000, 508000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[13] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{312000, 416000, 416000, 416000, 624000, 832000, 832000, 1248000}, /* CLUSTER0 */
		{416000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 797000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{0, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{0, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{312000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{208000, 312000, 312000, 416000, 416000, 508000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[14] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{312000, 416000, 416000, 416000, 624000, 832000, 1248000, 1248000}, /* CLUSTER0 */
		{416000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 797000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{0, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{0, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{312000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{208000, 312000, 312000, 416000, 416000, 508000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
	[15] = {
		/* LV0,    LV1,    LV2,    LV3,    LV4,    LV5,    LV6,    LV7 */
		{312000, 416000, 416000, 416000, 624000, 832000, 1248000, 1248000}, /* CLUSTER0 */
		{416000, 624000, 624000, 832000, 832000, 1248000, 1491000, 1491000}, /* CLUSTER1 */
		{624000, 624000, 624000, 624000, 624000, 667000, 797000, 797000}, /* DDR */
		{208000, 208000, 208000, 312000, 312000, 312000, 312000, 312000}, /* AXI */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GC3D */
		{0, 208000, 208000, 312000, 312000, 416000, 416000, 416000}, /* GC2D */
		{0, 416000, 624000, 624000, 705000, 832000, 832000, 832000}, /* GCSHADER */
		{0, 416000, 416000, 416000, 416000, 416000, 416000, 416000}, /* GCACLK */
		{312000, 416000, 416000, 416000, 416000, 528000, 528000, 528000}, /* VPU */
		{208000, 312000, 312000, 416000, 416000, 508000, 531000, 531000}, /* ISP */
		sdh_dvfs,
	},
};

/* 8 VLs PMIC setting */
/* FIXME: adjust according to SVC */
static int vm_millivolts_1956_svc_tsmc[][VL_MAX] = {
	/*LV0,  LV1,  LV2,  LV3,  LV4,  LV5,  LV6,  LV7 */
	{1000, 1050, 1063, 1088, 1100, 1175, 1250, 1300},/* Profile0 */
	{975, 975, 975, 975, 988, 1063, 1063, 1188},/* Profile1 */
	{975, 975, 975, 975, 988, 1063, 1075, 1188},/* Profile2 */
	{975, 975, 975, 988, 988, 1063, 1088, 1200},/* Profile3 */
	{975, 975, 975, 988, 1000, 1075, 1100, 1213},/* Profile4 */
	{975, 975, 975, 988, 1000, 1075, 1113, 1213},/* Profile5 */
	{975, 975, 975, 1000, 1013, 1088, 1113, 1225},/* Profile6 */
	{975, 975, 988, 1000, 1013, 1088, 1125, 1238},/* Profile7 */
	{975, 975, 988, 1013, 1025, 1100, 1138, 1238},/* Profile8 */
	{975, 988, 1000, 1013, 1025, 1100, 1150, 1250},/* Profile9 */
	{975, 1000, 1000, 1025, 1038, 1113, 1163, 1263},/* Profile10 */
	{975, 1000, 1013, 1038, 1050, 1125, 1175, 1275},/* Profile11 */
	{975, 1013, 1025, 1050, 1063, 1138, 1200, 1288},/* Profile12 */
	{975, 1025, 1038, 1063, 1075, 1150, 1213, 1300},/* Profile13 */
	{988, 1038, 1050, 1075, 1088, 1163, 1238, 1238},/* Profile14 */
	{1000, 1050, 1063, 1088, 1100, 1175, 1250, 1250},/* Profile15 */
};

static struct cpmsa_dvc_info cpmsa_dvc_info_1956tsmc[NUM_PROFILES] = {
	[0] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL1},
		.cpdvcinfo[2] = {416, VL1},
		.cpdvcinfo[3] = {624, VL3},
		.cpdvcinfo[4] = {832, VL6},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL2},
		.lteaxidvcinfo[0] = {104, VL1},
		.lteaxidvcinfo[1] = {156, VL1},
		.lteaxidvcinfo[2] = {208, VL1},
		.lteaxidvcinfo[3] = {312, VL1},
		.msadvcvl[0] = {416, VL2},
		.msadvcvl[1] = {624, VL6},
	},
	[1] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL0},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL0},
		.lteaxidvcinfo[0] = {104, VL0},
		.lteaxidvcinfo[1] = {156, VL0},
		.lteaxidvcinfo[2] = {208, VL0},
		.lteaxidvcinfo[3] = {312, VL0},
		.msadvcvl[0] = {416, VL0},
		.msadvcvl[1] = {624, VL5},
	},
	[2] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL0},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL0},
		.lteaxidvcinfo[0] = {104, VL0},
		.lteaxidvcinfo[1] = {156, VL0},
		.lteaxidvcinfo[2] = {208, VL0},
		.lteaxidvcinfo[3] = {312, VL0},
		.msadvcvl[0] = {416, VL0},
		.msadvcvl[1] = {624, VL5},
	},
	[3] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL0},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL0},
		.lteaxidvcinfo[0] = {104, VL0},
		.lteaxidvcinfo[1] = {156, VL0},
		.lteaxidvcinfo[2] = {208, VL0},
		.lteaxidvcinfo[3] = {312, VL0},
		.msadvcvl[0] = {416, VL0},
		.msadvcvl[1] = {624, VL5},
	},
	[4] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL0},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL0},
		.lteaxidvcinfo[0] = {104, VL0},
		.lteaxidvcinfo[1] = {156, VL0},
		.lteaxidvcinfo[2] = {208, VL0},
		.lteaxidvcinfo[3] = {312, VL0},
		.msadvcvl[0] = {416, VL0},
		.msadvcvl[1] = {624, VL5},
	},
	[5] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL0},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL0},
		.lteaxidvcinfo[0] = {104, VL0},
		.lteaxidvcinfo[1] = {156, VL0},
		.lteaxidvcinfo[2] = {208, VL0},
		.lteaxidvcinfo[3] = {312, VL0},
		.msadvcvl[0] = {416, VL0},
		.msadvcvl[1] = {624, VL5},
	},
	[6] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL3},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL0},
		.lteaxidvcinfo[0] = {104, VL0},
		.lteaxidvcinfo[1] = {156, VL0},
		.lteaxidvcinfo[2] = {208, VL0},
		.lteaxidvcinfo[3] = {312, VL0},
		.msadvcvl[0] = {416, VL0},
		.msadvcvl[1] = {624, VL5},
	},
	[7] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL2},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL0},
		.lteaxidvcinfo[0] = {104, VL0},
		.lteaxidvcinfo[1] = {156, VL0},
		.lteaxidvcinfo[2] = {208, VL0},
		.lteaxidvcinfo[3] = {312, VL0},
		.msadvcvl[0] = {416, VL2},
		.msadvcvl[1] = {624, VL5},
	},
	[8] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL2},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL0},
		.lteaxidvcinfo[0] = {104, VL0},
		.lteaxidvcinfo[1] = {156, VL0},
		.lteaxidvcinfo[2] = {208, VL0},
		.lteaxidvcinfo[3] = {312, VL0},
		.msadvcvl[0] = {416, VL2},
		.msadvcvl[1] = {624, VL5},
	},
	[9] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL2},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL1},
		.lteaxidvcinfo[0] = {104, VL0},
		.lteaxidvcinfo[1] = {156, VL0},
		.lteaxidvcinfo[2] = {208, VL0},
		.lteaxidvcinfo[3] = {312, VL0},
		.msadvcvl[0] = {416, VL2},
		.msadvcvl[1] = {624, VL5},
	},
	[10] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL3},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL1},
		.lteaxidvcinfo[0] = {104, VL1},
		.lteaxidvcinfo[1] = {156, VL1},
		.lteaxidvcinfo[2] = {208, VL1},
		.lteaxidvcinfo[3] = {312, VL1},
		.msadvcvl[0] = {416, VL1},
		.msadvcvl[1] = {624, VL6},
	},
	[11] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL0},
		.cpdvcinfo[3] = {624, VL3},
		.cpdvcinfo[4] = {832, VL5},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL2},
		.lteaxidvcinfo[0] = {104, VL1},
		.lteaxidvcinfo[1] = {156, VL1},
		.lteaxidvcinfo[2] = {208, VL1},
		.lteaxidvcinfo[3] = {312, VL1},
		.msadvcvl[0] = {416, VL2},
		.msadvcvl[1] = {624, VL6},
	},
	[12] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL0},
		.cpdvcinfo[2] = {416, VL1},
		.cpdvcinfo[3] = {624, VL3},
		.cpdvcinfo[4] = {832, VL6},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL2},
		.lteaxidvcinfo[0] = {104, VL1},
		.lteaxidvcinfo[1] = {156, VL1},
		.lteaxidvcinfo[2] = {208, VL1},
		.lteaxidvcinfo[3] = {312, VL1},
		.msadvcvl[0] = {416, VL2},
		.msadvcvl[1] = {624, VL6},
	},
	[13] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL1},
		.cpdvcinfo[2] = {416, VL1},
		.cpdvcinfo[3] = {624, VL3},
		.cpdvcinfo[4] = {832, VL6},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL2},
		.lteaxidvcinfo[0] = {104, VL1},
		.lteaxidvcinfo[1] = {156, VL1},
		.lteaxidvcinfo[2] = {208, VL1},
		.lteaxidvcinfo[3] = {312, VL1},
		.msadvcvl[0] = {416, VL2},
		.msadvcvl[1] = {624, VL6},
	},
	[14] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL1},
		.cpdvcinfo[2] = {416, VL1},
		.cpdvcinfo[3] = {624, VL3},
		.cpdvcinfo[4] = {832, VL6},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL2},
		.lteaxidvcinfo[0] = {104, VL1},
		.lteaxidvcinfo[1] = {156, VL1},
		.lteaxidvcinfo[2] = {208, VL1},
		.lteaxidvcinfo[3] = {312, VL1},
		.msadvcvl[0] = {416, VL2},
		.msadvcvl[1] = {624, VL6},
	},
	[15] = {
		.cpdvcinfo[0] = {208, VL0},
		.cpdvcinfo[1] = {312, VL1},
		.cpdvcinfo[2] = {416, VL1},
		.cpdvcinfo[3] = {624, VL3},
		.cpdvcinfo[4] = {832, VL6},
		.cpaxidvcinfo[0] = {104, VL0},
		.cpaxidvcinfo[1] = {156, VL0},
		.cpaxidvcinfo[2] = {208, VL0},
		.cpaxidvcinfo[3] = {312, VL2},
		.lteaxidvcinfo[0] = {104, VL1},
		.lteaxidvcinfo[1] = {156, VL1},
		.lteaxidvcinfo[2] = {208, VL1},
		.lteaxidvcinfo[3] = {312, VL1},
		.msadvcvl[0] = {416, VL2},
		.msadvcvl[1] = {624, VL6},
	},
};


void adjust_ddr_svc_helan4(void)
{
	int i, ddr_voltage  = 0;
	ddr_voltage = ddr_800M_tsmc_svc_helan4[uiprofile];

	if (ddr_mode == DDR_800M)
		for (i = 0; i < VL_MAX; i++)
			if ((freqs_cmb_helan4[DDR][i] != 0) &&
				(millivolts_helan4[i] >= ddr_voltage))
				freqs_cmb_helan4[DDR][i] = 797000;

	return;
}

int handle_svc_table_helan4(void)
{

	millivolts_helan4 = vm_millivolts_1956_svc_tsmc[uiprofile];
	freqs_cmb_helan4 = freqs_cmb_1956_tsmc[uiprofile];

	adjust_ddr_svc_helan4();

	return 0;
}


/*
 * dvfs_rail_component.freqs is inited dynamicly, due to different stepping
 * may have different VL combination
 */
static struct dvfs_rail_component vm_rail_comp_tbl_dvc[VM_RAIL_MAX] = {
	INIT_DVFS("clst0", true, ACTIVE_RAIL_FLAG, NULL),
	INIT_DVFS("clst1", true, ACTIVE_RAIL_FLAG, NULL),
	INIT_DVFS("ddr", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
	INIT_DVFS("axi", true, ACTIVE_M2_RAIL_FLAG, NULL),
	INIT_DVFS("gc3d_clk", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
	INIT_DVFS("gc2d_clk", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
	INIT_DVFS("gcsh_clk", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
	INIT_DVFS("gcbus_clk", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
	INIT_DVFS("vpufunc_clk", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
	INIT_DVFS("isp_pipe_clk", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
	INIT_DVFS("sdh0_dummy", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
	INIT_DVFS("sdh1_dummy", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
	INIT_DVFS("sdh2_dummy", true, ACTIVE_M2_D1P_RAIL_FLAG, NULL),
};

/* pm880: 0x80 is the ASCII code of "p", 0x77 is for "m" */
static int set_pmic_volt(unsigned int lvl, unsigned int mv)
{
	switch (__dvc_guard) {
	case 0x8077860:
		return pm8xx_dvc_setvolt(PM800_ID_BUCK1, lvl, mv * mV2uV);
	case 0x8077880:
	default:
		return pm88x_dvc_set_volt(lvl, mv * mV2uV);
	}
}

static int get_pmic_volt(unsigned int lvl)
{
	int uv = 0, ret = 0;

	switch (__dvc_guard) {
	case 0x8077860:
		ret = pm8xx_dvc_getvolt(PM800_ID_BUCK1, lvl, &uv);
		if (ret < 0)
			return ret;
		break;
	case 0x8077880:
	default:
		uv = pm88x_dvc_get_volt(lvl);
		break;
	}
	return DIV_ROUND_UP(uv, mV2uV);
}

static struct dvc_plat_info dvc_pxa1956_info = {
	.comps = vm_rail_comp_tbl_dvc,
	.num_comps = ARRAY_SIZE(vm_rail_comp_tbl_dvc),
	.num_volts = VL_MAX,
	.cp_pmudvc_lvl = VL0,
	.dp_pmudvc_lvl = VL2,
	.set_vccmain_volt = set_pmic_volt,
	.get_vccmain_volt = get_pmic_volt,
	.pmic_maxvl = 8,
	.pmic_rampup_step = 12500,
	/* On pxa1956, AP side cannot access registers in PMUcp */
	.pmucp_inaccessible = 1,
	/* by default print the debug msg into logbuf */
	.dbglvl = 1,
	.regname = "vccmain",
	/* real measured 8us + 4us, PMIC suggestes 16us for 12.5mV/us */
	.extra_timer_dlyus = 16,
};

int __init setup_pxa1956_dvfs_platinfo(void)
{
	void __iomem *hwdvc_base;
	enum dvfs_comp idx;
	struct dvc_plat_info *plat_info = &dvc_pxa1956_info;

	__init_read_droinfo();

	handle_svc_table_helan4();

	dvc_pxa1956_info.millivolts = millivolts_helan4;

	plat_set_vl_min(0);
	plat_set_vl_max(dvc_pxa1956_info.num_volts);

	fillcpdvcinfo(&cpmsa_dvc_info_1956tsmc[uiprofile]);

	/* register the platform info into dvfs-dvc.c(hwdvc driver) */
	hwdvc_base = ioremap(HWDVC_BASE, SZ_16K);
	if (hwdvc_base == NULL) {
		pr_err("error to ioremap hwdvc base\n");
		return -ENOMEM;
	}
	plat_info->dvc_reg_base = hwdvc_base;
	for (idx = CORE; idx < VM_RAIL_MAX; idx++)
		plat_info->comps[idx].freqs = freqs_cmb_helan4[idx];
	return dvfs_setup_dvcplatinfo(plat_info);
}

