/*
 * PXA1908 CP related
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
#include "pxa988_series.h"

/*
 * pxa988 series:
 * for pxa1908, we need to set the remap register CIU_SEAGULL_REMAP
 */
static void releasecp(void)
{
	/* the load address must be 64k aligned */
	BUG_ON(arbel_bin_phys_addr & 0xFFFF);
	cp_set_seagull_remap_reg(arbel_bin_phys_addr | 0x01);
	__cp988_releasecp();
}

static void holdcp(void)
{
	__cp988_holdcp();
}

static bool get_status(void)
{
	return __cp988_get_status();
}

static struct cpload_driver cp_driver = {
	.name = "pxa1908_cp",
	.release_cp = releasecp,
	.hold_cp = holdcp,
	.get_status = get_status,
	.cp_type = 0x31393038,
};


static int __init cpload_init(void)
{
	register_cpload_driver(&cp_driver);
	return 0;
}

static void __exit cpload_exit(void)
{
	unregister_cpload_driver(&cp_driver);
}

module_init(cpload_init);
module_exit(cpload_exit);
