/*
 * PXA CP load header
 *
 * This software program is licensed subject to the GNU General Public License
 * (GPL).Version 2,June 1991, available at http://www.fsf.org/copyleft/gpl.html

 * (C) Copyright 2007 Marvell International Ltd.
 * All Rights Reserved
 */

#ifndef _PXA_CP_LOAD_H_
#define _PXA_CP_LOAD_H_

#include "util.h"
#include "linux_driver_types.h"
#include <linux/platform_device.h>
#include <linux/device.h>

struct cpload_driver {
	void (*release_cp)(void);
	void (*hold_cp)(void);
	bool (*get_status)(void);
	u32 cp_type;
	const char *name;
	struct device_driver driver;
};

struct cpload_device {
	u32 cp_type;
	u32 lpm_qos;
	const char *name;
	struct cpload_driver *driver;
	struct device dev;
};

#define to_cpload_driver(drv) container_of(drv, struct cpload_driver, driver)
#define to_cpload_device(dev) container_of(dev, struct cpload_device, dev)

extern struct bus_type cpu_subsys;
extern void cp_releasecp(void);
extern void cp_holdcp(void);
extern bool cp_get_status(void);
extern int register_cpload_driver(struct cpload_driver *driver);
extern void unregister_cpload_driver(struct cpload_driver *driver);

extern uint32_t arbel_bin_phys_addr;
extern uint32_t seagull_remap_smc_funcid;

extern void (*watchdog_count_stop_fp)(void);

/**
 * interface exported by kernel for disabling FC during hold/release CP
 */
extern void acquire_fc_mutex(void);
extern void release_fc_mutex(void);

extern int cp_invoke_smc(u64 function_id, u64 arg0, u64 arg1,
	u64 arg2);

static inline int cp_set_seagull_remap_reg(u64 val)
{
	int ret;

	ret = cp_invoke_smc(seagull_remap_smc_funcid, val, 0, 0);

	pr_info("%s: function_id: 0x%llx, arg0: 0x%llx, ret 0x%x\n",
		__func__, (u64)seagull_remap_smc_funcid, val, ret);

	return ret;
}

DECLARE_BLOCKING_NOTIFIER(cp_mem_set);

extern bool cp_is_aponly(void);

#endif /* _PXA_CP_LOAD_H_ */
