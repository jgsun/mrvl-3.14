/*
    Marvell SSIPC misc driver for Linux
    Copyright (C) 2010 Marvell International Ltd.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <linux/device.h>
#include <linux/module.h>
#include <linux/skbuff.h>

#include "io_device.h"
#include "shm_share.h"

#define SSIPC_START_PROC_ID	0x06
#define SSIPC_DATA_PROC_ID	0x04

static int ssipc_dsds;
#define PORTS_GOURP_ONE_NUM 11
static struct io_device umts_io_devices[] = {
	[0] = {
	       .name = "umts_boot0",
	       .app = "s-ril",
	       .port = 0},
	[1] = {
	       .name = "umts_ipc0",
	       .app = "s-ril",
	       .port = CISTUB_PORT,
	       .long_packet_enable = 1},
	[2] = {
	       .name = "umts_attest0",
	       .app = "serial_client",
	       .port = RAW_AT_PORT},
	[3] = {
	       .name = "umts_atdun0",
	       .app = "pc modem",
	       .port = RAW_AT_DUN_PORT},
	[4] = {
	       .name = "umts_atprod0",
	       .app = "atd",
	       .port = RAW_AT_PROD_PORT},
	[5] = {
	       .name = "umts_atsimal0",
	       .app = "simal",
	       .port = RAW_AT_SIMAL_PORT},
	[6] = {
	       .name = "umts_atsol0",
	       .app = "at_router",
	       .port = RAW_AT_CLIENT_SOL_PORT},
	[7] = {
	       .name = "umts_atunsol0",
	       .app = "at_router",
	       .port = RAW_AT_CLIENT_UNSOL_PORT},
	[8] = {
	       .name = "umts_at0",
	       .app = "reserved0_1",
	       .port = RAW_AT_RESERVERED_PORT},
	[9] = {
	       .name = "umts_atgps0",
	       .app = "gpsagent",
	       .port = RAW_AT_GPS_PORT},
	/*here may add rfs node
	 * need increase PORTS_GOURP_ONE_NUM after add rfs
	 * */
	[PORTS_GOURP_ONE_NUM - 1] = {
	       .name = "umts_at0_1",
	       .app = "reserved0_2",
	       .port = RAW_AT_RESERVERED2_PORT},
	[PORTS_GOURP_ONE_NUM] = {
	       .name = "umts_ipc1",
	       .app = "s-ril 2",
	       .port = CIDATASTUB_PORT,
	       .long_packet_enable = 1},
	[PORTS_GOURP_ONE_NUM + 1] = {
	       .name = "umts_attest1",
	       .app = "serial_client 2",
	       .port = RAW_AT_PORT2},
	[PORTS_GOURP_ONE_NUM + 2] = {
	       .name = "umts_atdun1",
	       .app = "ppp modem 2",
	       .port = RAW_AT_DUN_PORT2},
	[PORTS_GOURP_ONE_NUM + 3] = {
	       .name = "umts_atprod1",
	       .app = "atd 2",
	       .port = RAW_AT_PROD_PORT2},
	[PORTS_GOURP_ONE_NUM + 4] = {
	       .name = "umts_atsimal1",
	       .app = "simal 2",
	       .port = RAW_AT_SIMAL_PORT2},
	[PORTS_GOURP_ONE_NUM + 5] = {
	       .name = "umts_atsol1",
	       .app = "at_router 2",
	       .port = RAW_AT_CLIENT_SOL_PORT2},
	[PORTS_GOURP_ONE_NUM + 6] = {
	       .name = "umts_atunsol1",
	       .app = "at_router 2",
	       .port = RAW_AT_CLIENT_UNSOL_PORT2},
	[PORTS_GOURP_ONE_NUM + 7] = {
	       .name = "umts_atgps1",
	       .app = "gpsagent 2",
	       .port = RAW_AT_GPS_PORT2},
	[PORTS_GOURP_ONE_NUM + 8] = {
	       .name = "umts_at1",
	       .app = "reserved1_0",
	       .port = RAW_AT_RESERVERED_PORT2},
	[PORTS_GOURP_ONE_NUM + 9] = {
	       .name = "umts_at1_1",
	       .app = "reserved1_1",
	       .port = RAW_AT_RESERVERED2_PORT2},
};

/* polling modem status */
#define IOCTL_MODEM_STATUS		_IO('o', 0x27)
/* trigger modem force reset */
#define IOCTL_MODEM_RESET		_IO('o', 0x21)
/* trigger modem crash, final action rely on EE_CFG in NVM */
#define IOCTL_MODEM_FORCE_CRASH_EXIT		_IO('o', 0x34)

/* trigger ssipc channel start work */
#define IOCTL_MODEM_CHANNEL_START		_IO('o', 0x35)
/* trigger ssipc channel stop work */
#define IOCTL_MODEM_CHANNEL_STOP		_IO('o', 0x36)
/* enable ssipc dsds channels */
#define IOCTL_MODEM_CHANNEL_DSDS		_IO('o', 0x37)

static void set_dsds_feature(int enable)
{
	ssipc_dsds = enable;
}

static int get_dsds_feature(void)
{
	return ssipc_dsds;
}

static void start_ssipc_channel(void)
{
	int i;
	int num_iodevs = ssipc_dsds ?
			ARRAY_SIZE(umts_io_devices) : PORTS_GOURP_ONE_NUM;
	for (i = 0; i < num_iodevs; i++)
		io_channel_init(&umts_io_devices[i]);
}

static void stop_ssipc_channel(void)
{
	int i;
	int num_iodevs = ssipc_dsds ?
			ARRAY_SIZE(umts_io_devices) : PORTS_GOURP_ONE_NUM;
	for (i = 0; i < num_iodevs; i++)
		io_channel_deinit(&umts_io_devices[i]);
}

static long ssipc_ioctl_hook(struct io_device *iod, unsigned int cmd,
		unsigned long arg)
{
	int p_state;

	switch (cmd) {
	case IOCTL_MODEM_STATUS:
		p_state = get_modem_state(iod);
		pr_debug("%s: IOCTL_MODEM_STATUS (state %s)\n",
				iod->name, get_modem_state_str(p_state));
		return p_state;
	case IOCTL_MODEM_FORCE_CRASH_EXIT:
		pr_info("%s: IOCTL_MODEM_FORCE_CRASH_EXIT triggered\n",
				iod->name);
		trigger_modem_crash(0, "ssipc force crash");
		break;
	case IOCTL_MODEM_RESET:
		pr_info("%s: IOCTL_MODEM_RESET triggered\n",
				iod->name);
		trigger_modem_crash(1, "ssipc force reset");
		break;
	case IOCTL_MODEM_CHANNEL_START:
		pr_info("%s: IOCTL_MODEM_START triggered\n",
				iod->name);
		start_ssipc_channel();
		break;
	case IOCTL_MODEM_CHANNEL_STOP:
		pr_info("%s: IOCTL_MODEM_STOP triggered\n",
				iod->name);
		stop_ssipc_channel();
		break;
	case IOCTL_MODEM_CHANNEL_DSDS:
		pr_info("%s: IOCTL_MODEM_DSDS triggered\n",
				iod->name);
		set_dsds_feature(1);
		break;

	default:
		pr_err("%s: ERR! undefined cmd 0x%X\n", iod->name, cmd);
		return -EINVAL;
	}

	return 0;
}

static ssize_t ssipc_dsds_store(struct device *sys_dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int enable;

	if (kstrtoint(buf, 10, &enable) < 0)
		return 0;
	set_dsds_feature(enable);
	pr_info("%s: buf={%s}, enable=%d\n", __func__, buf, enable);
	return len;
}

static ssize_t ssipc_dsds_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int len;
	int enable;

	enable = get_dsds_feature();
	len = sprintf(buf, "%d\n", enable);
	return len;
}

static ssize_t ssipc_ch_enable_store(struct device *sys_dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int enable;

	if (kstrtoint(buf, 10, &enable) < 0)
		return 0;
	if (!enable)
		stop_ssipc_channel();
	else
		start_ssipc_channel();
	pr_info("%s: buf={%s}, enable=%d\n", __func__, buf, enable);
	return len;
}

static ssize_t ssipc_ch_enable_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int len;
	int status;

	status = if_msocket_connect() ? STATE_ONLINE : STATE_OFFLINE;
	len = sprintf(buf, "%d\n", status);
	return len;
}

static DEVICE_ATTR(ssipc_dsds, 0644, ssipc_dsds_show, ssipc_dsds_store);
static DEVICE_ATTR(ssipc_ch_enable, 0644,
		ssipc_ch_enable_show, ssipc_ch_enable_store);
static struct device_attribute *ssipc_attr[] = {
	&dev_attr_ssipc_dsds,
	&dev_attr_ssipc_ch_enable,
	NULL
};

static int ssipc_attr_add(struct device *dev)
{
	int i = 0, n;
	int ret;
	struct device_attribute *attr = NULL;

	n = ARRAY_SIZE(ssipc_attr);
	while (i < n && (attr = ssipc_attr[i++]) != NULL) {
		ret = device_create_file(dev, attr);
		if (ret)
			return -EIO;
	}
	return 0;
}

static int ssipc_attr_rm(struct device *dev)
{
	int i = 0, n;
	struct device_attribute *attr = NULL;

	n = ARRAY_SIZE(ssipc_attr);
	while ((attr = ssipc_attr[i++]) != NULL)
		device_remove_file(dev, attr);
	return 0;
}

static void ssipc_init_hook(struct io_device *iod)
{
	/* register sys node */
	if (!iod->port)
		ssipc_attr_add(iod->dev);

	iod->start_id = SSIPC_START_PROC_ID;
	iod->data_id = SSIPC_DATA_PROC_ID;
	iod->linkdown_id = MsocketLinkdownProcId;
	iod->linkup_id = MsocketLinkupProcId;

	if (!iod->ioctl_hook)
		iod->ioctl_hook = ssipc_ioctl_hook;
}

static void ssipc_deinit_hook(struct io_device *iod)
{
	/* unregister sys node */
	if (!iod->port)
		ssipc_attr_rm(iod->dev);
}

/* module initialization */
static int __init ssipc_misc_init(void)
{
	int i = 0;
	int ret = -1;
	int num_iodevs = ARRAY_SIZE(umts_io_devices);
	for (i = 0; i < num_iodevs; i++) {
		struct io_device *iod = &umts_io_devices[i];
		if (!iod->init_hook)
			iod->init_hook = ssipc_init_hook;
		if (!iod->deinit_hook)
			iod->deinit_hook = ssipc_deinit_hook;
		ret = io_device_register(iod);
		if (ret) {
			pr_err("%s: register %s io device fail\n", __func__,
					iod->name);
			goto err_deinit;
		}
	}
	return ret;

err_deinit:
	for (--i; i >= 0; i--)
		io_device_deregister(&umts_io_devices[i]);

	return ret;
}

/* module exit */
static void __exit ssipc_misc_exit(void)
{
	int i;
	int num_iodevs = ARRAY_SIZE(umts_io_devices);

	for (i = 0; i < num_iodevs; i++)
		io_device_deregister(&umts_io_devices[i]);
}

module_init(ssipc_misc_init);
module_exit(ssipc_misc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION("Marvell SSIPC misc Driver");
