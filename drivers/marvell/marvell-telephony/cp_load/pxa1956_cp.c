/*
 * PXA1956 CP related
 *
 * This software program is licensed subject to the GNU General Public License
 * (GPL).Version 2,June 1991, available at http://www.fsf.org/copyleft/gpl.html

 * (C) Copyright 2007 Marvell International Ltd.
 * All Rights Reserved
 */
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/module.h>
#include "pxa_cp_load.h"
#include "common_regs.h"

/*
 * pxa1956 cp related operations are almost the same as as pxa988
 * exception the branch address set
 */
void cp1956_releasecp(void)
{
	/* the load address must be 64k aligned */
	BUG_ON(arbel_bin_phys_addr & 0xFFFF);
	writel(((unsigned long)arbel_bin_phys_addr >> 16) | 0x10000,
		MPMU_CP_REMAP_REG0);
	__cp988_releasecp();
}

void cp1956_holdcp(void)
{
	cp988_holdcp();
}

bool cp1956_get_status(void)
{
	return cp988_get_status();
}
