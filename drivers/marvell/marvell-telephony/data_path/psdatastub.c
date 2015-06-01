/*

 *(C) Copyright 2007 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * All Rights Reserved
 */

#include <linux/module.h>
#include <linux/netdevice.h>	/* dev_kfree_skb_any */
#include <linux/ip.h>
#include <linux/debugfs.h>
#include <linux/platform_device.h>
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "psdatastub.h"
#include "data_path_common.h"

#define PSDATASTUB_IOC_MAGIC 'P'
#define PSDATASTUB_GCFDATA _IOW(PSDATASTUB_IOC_MAGIC, 1, int)
#define PSDATASTUB_TOGGLE_DATA_ENABLE_DISABLE _IOW(PSDATASTUB_IOC_MAGIC, 2, int)

struct GCFDATA {
	u32 cid;
	u32 len;		/* length of databuf */
	u8 *databuf;
};

#ifdef CONFIG_COMPAT
struct GCFDATA32 {
	u32 cid;
	u32 len;		/* length of databuf */
	compat_uptr_t databuf;
};
#endif

static int psdatastub_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static long psdatastub_ioctl(struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	struct GCFDATA gcfdata;
	struct sk_buff *gcfbuf;

	if (_IOC_TYPE(cmd) != PSDATASTUB_IOC_MAGIC) {
		pr_debug("%s: cci magic number is wrong!\n", __func__);
		return -ENOTTY;
	}

	pr_debug("%s: cmd=0x%x\n", __func__, cmd);
	switch (cmd) {
	case PSDATASTUB_GCFDATA:	/* For CGSEND and TGSINK */
	{
		struct psd_user psd_user;

		if (copy_from_user(&gcfdata, (struct GCFDATA *) arg,
				sizeof(struct GCFDATA)))
			return -EFAULT;
		gcfbuf = alloc_skb(gcfdata.len, GFP_KERNEL);
		if (!gcfbuf)
			return -ENOMEM;
		if (copy_from_user
		    (skb_put(gcfbuf, gcfdata.len), gcfdata.databuf,
		     gcfdata.len)) {
			kfree_skb(gcfbuf);
			return -EFAULT;
		}
		memset(&psd_user, 0, sizeof(psd_user));
		if (psd_register(&psd_user, gcfdata.cid) == 0) {
			psd_data_tx(gcfdata.cid, 0, gcfbuf);
			psd_unregister(&psd_user, gcfdata.cid);
		} else {
			pr_err("%s: register cid %d failed\n",
				__func__, gcfdata.cid);
			kfree_skb(gcfbuf);
			return -EFAULT;
		}
	}
	break;

	case PSDATASTUB_TOGGLE_DATA_ENABLE_DISABLE:
		if (data_enabled)
			data_enabled = false;
		else
			data_enabled = true;

		pr_info("%s: Toggle Data to %s", __func__, data_enabled ?
			"Enabled" : "Disabled");
		break;

	}
	return 0;
}

#ifdef CONFIG_COMPAT
static int compat_gcfdata_handle(struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	struct GCFDATA32 __user *argp = (void __user *)arg;
	struct GCFDATA __user *buf;
	compat_uptr_t param_addr;
	int ret = 0;

	buf = compat_alloc_user_space(sizeof(*buf));
	if (!access_ok(VERIFY_WRITE, buf, sizeof(*buf))
	    || !access_ok(VERIFY_WRITE, argp, sizeof(*argp)))
		return -EFAULT;

	if (__copy_in_user(buf, argp, offsetof(struct GCFDATA32, databuf))
	    || __get_user(param_addr, &argp->databuf)
	    || __put_user(compat_ptr(param_addr), &buf->databuf))
		return -EFAULT;

	ret = psdatastub_ioctl(filp, cmd, (unsigned long)buf);
	return ret;
}
static long compat_psdatastub_ioctl(struct file *filp,
			      unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	if (_IOC_TYPE(cmd) != PSDATASTUB_IOC_MAGIC) {
		pr_debug("%s: cci magic number is wrong!\n", __func__);
		return -ENOTTY;
	}
	switch (cmd) {
	case PSDATASTUB_GCFDATA:	/* For CGSEND and TGSINK */
		ret = compat_gcfdata_handle(filp, cmd, arg);
		break;
	default:
		ret = psdatastub_ioctl(filp, cmd, arg);
		break;
	}
	return ret;
}
#endif

static const struct file_operations psdatastub_fops = {
	.open = psdatastub_open,
	.unlocked_ioctl = psdatastub_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_psdatastub_ioctl,
#endif
	.owner = THIS_MODULE
};

static struct miscdevice psdatastub_miscdev = {
	MISC_DYNAMIC_MINOR,
	"psdatastub",
	&psdatastub_fops,
};

static int __init psdatastub_init(void)
{
	int ret;

	ret = misc_register(&psdatastub_miscdev);
	if (ret)
		pr_err("register misc device error\n");

	return ret;
}

static void __exit psdatastub_exit(void)
{
	misc_deregister(&psdatastub_miscdev);
}

module_init(psdatastub_init);
module_exit(psdatastub_exit);
