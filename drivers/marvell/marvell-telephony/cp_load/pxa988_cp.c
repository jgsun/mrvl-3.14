/*
 * PXA988 CP related
 *
 * This software program is licensed subject to the GNU General Public License
 * (GPL).Version 2,June 1991, available at http://www.fsf.org/copyleft/gpl.html

 * (C) Copyright 2007 Marvell International Ltd.
 * All Rights Reserved
 */
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/module.h>
#include "pxa_cp_load.h"
#include "common_regs.h"
#include "pxa988_series.h"

/*
 * pxa988 series:
 * for pxa988, we need to set the branch address CIU_SW_BRANCH_ADDR
 */

static void releasecp(void)
{
	writel(arbel_bin_phys_addr, CIU_SW_BRANCH_ADDR);
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
	.name = "pxa988_cp",
	.release_cp = releasecp,
	.hold_cp = holdcp,
	.get_status = get_status,
	.cp_type = 0x30393838,
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
