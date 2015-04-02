/*

 *(C) Copyright 2015 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * All Rights Reserved
 */

#include <linux/module.h>
#include <linux/device.h>

#include "io_device.h"
#include "csd_misc.h"
#include "shm_share.h"
#include "msocket.h"

static struct io_device raw_io_devices[] = {
	[0] = {
	       .name = "ccidatastub",
	       .app = "csd path control app",
	       .port = PORT_NO_USE_START,
	       .ioctl_hook = ccidatastub_ioctl},
	[1] = {
	       .name = "cctdatadev",
	       .app = "csd path control app",
	       .port = PORT_NO_USE_START+1,
	       .ioctl_hook = cctdatadev_ioctl},
	[2] = {
	       .name = "cidatatty0",
	       .app = "s-ril",
	       .port = CICSDSTUB_PORT,
	       .tx_fixup = tx_fixup_csd,
	       .rx_fixup = rx_fixup_csd,
	       .buffer_offline_enable = 1},
	[3] = {
	       .name = "cidatatty2",
	       .app = "s-ril",
	       .port = CIIMSSTUB_PORT},
};

static int raw_channel_ready_cb(struct notifier_block *nb,
			unsigned long action, void *data)
{
	int i = 0;
	int num_iodevs = ARRAY_SIZE(raw_io_devices);
	for (i = 0; i < num_iodevs; i++) {
		struct io_device *iod = &raw_io_devices[i];
		if (iod->port < PORT_NO_USE_START)
			io_channel_init(iod);
	}

	return 0;
}

static struct notifier_block cp_state_notifier = {
	.notifier_call = raw_channel_ready_cb,
};

static void raw_init_hook(struct io_device *iod)
{
#ifdef CONFIG_SSIPC_SUPPORT
	if (iod->port == CICSDSTUB_PORT)
		set_csd_init_cfg();
#endif

	iod->start_id = CiDataStubRequestStartProcId;
	iod->data_id = CiDataStubReqDataProcId;
	iod->linkdown_id = MsocketLinkdownProcId;
	iod->linkup_id = MsocketLinkupProcId;
}

/* module initialization */
static int __init raw_misc_init(void)
{
	int i = 0;
	int ret = -1;
	int num_iodevs = ARRAY_SIZE(raw_io_devices);
	for (i = 0; i < num_iodevs; i++) {
		struct io_device *iod = &raw_io_devices[i];
		if (!iod->init_hook)
			iod->init_hook = raw_init_hook;
		ret = io_device_register(iod);
		if (ret) {
			pr_err("%s: register %s io device fail\n", __func__,
					iod->name);
			goto err_deinit;
		}
	}
	register_first_cp_synced(&cp_state_notifier);
	return ret;

err_deinit:
	for (--i; i >= 0; i--)
		io_device_deregister(&raw_io_devices[i]);

	return ret;
}

/* module exit */
static void __exit raw_misc_exit(void)
{
	int i;
	int num_iodevs = ARRAY_SIZE(raw_io_devices);

	for (i = 0; i < num_iodevs; i++)
		io_device_deregister(&raw_io_devices[i]);
}

module_init(raw_misc_init);
module_exit(raw_misc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION("Marvell raw misc Driver");
