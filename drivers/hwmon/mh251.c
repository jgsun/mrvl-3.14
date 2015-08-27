/******************************************************************************
*(C) Copyright 2015 Marvell International Ltd.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License version 2 as published
	by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
******************************************************************************/

#include <linux/module.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>
#include <linux/gpio_event.h>
#include <linux/gpio.h>
#include <linux/edge_wakeup_mmp.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/wakelock.h>

#define HS_DEBUG		0
#if HS_DEBUG
#define HS_INFO(format, arg...) \
	pr_info("hall_sensor: [%s] " format , __func__ , ##arg)
#else
#define HS_INFO(format, arg...) do { } while (0)
#endif
#define HS_NOTICE(format, arg...)	\
	pr_notice("hall_sensor: [%s] " format , __func__ , ##arg)
#define HS_ERR(format, arg...)	\
	pr_err("hall_sensor: [%s] " format , __func__ , ##arg)

#define MH251_NAME	"mst_mh251"
#define HALL_SENSOR_WAKE_UP 1
#define HS_WAKEUP_TIMEOUT 1000

/*MST-MH251 IO Control*/
#define MST_IOCTL_MAGIC         0x78
#define MST_IOCTL_GET_HFLAG     _IOR(MST_IOCTL_MAGIC, 1, int)
#define MST_IOCTL_SET_HFLAG     _IOW(MST_IOCTL_MAGIC, 2, int)
#define MST_IOCTL_GET_DATA      _IOW(MST_IOCTL_MAGIC, 3, unsigned char)

static uint32_t hsensor_delay_time_in_jiffies = HZ/4;
struct platform_device *this_pdev = NULL;
struct delayed_work hall_sensor_work;
struct mh251_data
{
	struct device *dev;
	struct input_dev *input_dev_hs;
	struct delayed_work hs_work;
	struct workqueue_struct *hs_wq;
	struct platform_device *pdev;
	struct wake_lock hs_wake_lock;
	spinlock_t lock;
	int gpio;
	u16 irq;
	u32 hs_state;
};

static void hsensor_event_wakeup(int gpio, void *data){
	struct mh251_data *hs_data = (struct mh251_data *)data;
	pm_wakeup_event(&hs_data->pdev->dev, HS_WAKEUP_TIMEOUT);
}

static irqreturn_t hs_interrupt_handler(int irq, void *dev_id)
{
	struct mh251_data *data = (struct mh251_data*) dev_id;
	unsigned long flags = 0;

	spin_lock_irqsave(&data->lock, flags);
	wake_lock_timeout(&data->hs_wake_lock, HS_WAKEUP_TIMEOUT);
	queue_delayed_work(data->hs_wq, &data->hs_work, hsensor_delay_time_in_jiffies);
	spin_unlock_irqrestore(&data->lock, flags);
	return IRQ_HANDLED;
}

void mh251_enable(int enable)
{
	struct mh251_data *data = platform_get_drvdata(this_pdev);
	unsigned long flags = 0	;
	int ret =0;
	int value = 0;

	spin_lock_irqsave(&data->lock, flags);
	if (enable) {
		if (data->hs_state == 0) {
			data->hs_state = 1;
			ret = request_mfp_edge_wakeup(data->gpio, hsensor_event_wakeup,
					data, &data->pdev->dev);
			if (ret)
				HS_ERR("failed to request edge wakeup.\n");
			enable_irq(data->irq);
		}
	} else {
		if (data->hs_state == 1) {
			data->hs_state = 0;
			disable_irq(data->irq);
			remove_mfp_edge_wakeup(data->gpio);
		}
	}
	/*input report init*/
	value = gpio_get_value(data->gpio) ? 1 : 0;
	input_report_abs(data->input_dev_hs, ABS_DISTANCE, value);
	input_sync(data->input_dev_hs);
	spin_unlock_irqrestore(&data->lock, flags);
}
static ssize_t mh251_store_enable(struct device *dev,
									   struct device_attribute *attr,
									   const char *buf, size_t size)
{
	unsigned long val;
	char *after;

	val = simple_strtoul(buf, &after, 10);

	printk(KERN_INFO "enable hall sensor -> %ld\n", val);
	if(val)
		mh251_enable(1);
	else
		mh251_enable(0);
	return size;
}

static ssize_t mh251_show_enable(struct device *dev,
									  struct device_attribute *attr, char *buf)
{
	struct mh251_data *data = platform_get_drvdata(this_pdev);
	return sprintf(buf, "%u\n", data->hs_state);
}

static ssize_t mh251_show_hs_status(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct mh251_data *data = platform_get_drvdata(this_pdev);
	char *s = buf;

	s += sprintf(buf, "%u\n",
		gpio_get_value(data->gpio) ? 1 : 0);
	return s - buf;
}

static DEVICE_ATTR(hall, S_IRUGO | S_IWUGO, mh251_show_enable,mh251_store_enable);
static DEVICE_ATTR(hs_status, S_IRUGO, mh251_show_hs_status, NULL);
static struct attribute *hs_attrs[] = {
	&dev_attr_hall.attr,
	&dev_attr_hs_status.attr,
	NULL
};
static struct attribute_group hs_attr_group = {
	.attrs = hs_attrs,
};

static int mh251_open(struct inode *inode, struct file *file)
{
	return 0;
}
static int mh251_release(struct inode *inode, struct file *file)
{
	return 0;
}
static long mh251_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct mh251_data *data = platform_get_drvdata(this_pdev);
	int flag;

	HS_INFO("cmd = %d, %d\n", _IOC_NR(cmd), cmd);
	switch (cmd) {
		case MST_IOCTL_SET_HFLAG:
			if (copy_from_user(&flag, argp, sizeof(flag)))
				return -EFAULT;
			HS_INFO("LTR_IOCTL_SET_HFLAG = %d\n", flag);
			if (1 == flag) {
				mh251_enable(1);
			} else if (0 == flag) {
				mh251_enable(0);
			} else {
				return -EINVAL;
			}
			break;
		case MST_IOCTL_GET_HFLAG:
			flag = gpio_get_value(data->gpio) ? 1 : 0;
			HS_INFO("MST_IOCTL_GET_HFLAG = %d\n", flag);
			if (copy_to_user(argp, &flag, sizeof(flag)))
				return -EFAULT;
			break;
		default:
			HS_ERR("unknown command: 0x%08X  (%d)\n", cmd, cmd);
			break;
	}
	return 0;
}

static const struct file_operations mh251_fops = {
	.owner = THIS_MODULE,
	.open = mh251_open,
	.release = mh251_release,
	.unlocked_ioctl = mh251_ioctl,
	.compat_ioctl = mh251_ioctl,
};
static struct miscdevice mh251_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = MH251_NAME,
	.fops = &mh251_fops,
};

static void hs_report_function(struct work_struct *work)
{
	struct mh251_data *data = container_of(work, struct mh251_data, hs_work.work);
	int value = 0;

	if (!data->input_dev_hs) {
		HS_ERR("Hall sensor input device doesn't exist\n");
		return;
	}
	value = gpio_get_value(data->gpio) ? 1 : 0;
	input_report_abs(data->input_dev_hs, ABS_DISTANCE, value);
	input_sync(data->input_dev_hs);
	HS_NOTICE("report value = %d\n", value);
}
static int hs_input_device_create(struct platform_device *pdev, struct mh251_data *data)
{
	int err = 0;

	data->input_dev_hs = input_allocate_device();
	if (!data->input_dev_hs) {
		HS_ERR("hs_indev allocation fails\n");
		err = -ENOMEM;
		goto exit;
	}
	data->input_dev_hs->dev.parent = &pdev->dev;
	data->input_dev_hs->name = "hall";
	set_bit(EV_ABS, data->input_dev_hs->evbit);
	input_set_abs_params(data->input_dev_hs, ABS_DISTANCE, 0, 1, 0, 0);

	input_set_drvdata(data->input_dev_hs, data);
	err = input_register_device(data->input_dev_hs);
	if (err) {
		HS_ERR("hs_indev registration fails\n");
		goto exit_input_free;
	}
	return 0;
exit_input_free:
	input_free_device(data->input_dev_hs);
	data->input_dev_hs = NULL;
exit:
	return err;
}

static int hsensor_probe(struct platform_device *pdev)
{
	int ret = 0, irq = 0, hs_gpio = -1;
	unsigned long irqflags;
	struct mh251_data *data = NULL;
	struct class *hs_class;
	struct device *hs_cmd_dev;

	if (!pdev)
		return -EINVAL;

	data = devm_kzalloc(&pdev->dev, sizeof(struct mh251_data), GFP_KERNEL);
	if(!data)	{
		HS_ERR("devm_kzalloc error \n");
		ret = -ENOMEM;
		goto fail_sys;
	}
	spin_lock_init(&data->lock);
	data->hs_state = 0;
	data->gpio = -1;
	data->pdev = pdev;
	data->dev = &pdev->dev;

	platform_set_drvdata(pdev, data);

	of_property_read_u32(pdev->dev.of_node, "edge-wakeup-gpio", &hs_gpio);
	if (hs_gpio >= 0) {
		data->gpio = hs_gpio;
	} else {
		HS_ERR("edge-wakeup-gpio error!!!\n");
		goto fail_sys;
	}
	ret = sysfs_create_group(&pdev->dev.kobj, &hs_attr_group);
	if (ret) {
		HS_ERR("Unable to create sysfs, error: %d\n", ret);
		goto fail_sys;
	}

	hs_class = class_create(THIS_MODULE,"mst-hs");
	if(IS_ERR(hs_class))
		HS_ERR("Failed to create class(mst-hs)!\n");
	hs_cmd_dev = device_create(hs_class, NULL, 0, NULL, "device");
	if(IS_ERR(hs_cmd_dev))
		HS_ERR("Failed to create device(hs_cmd_dev)!\n");
	if(device_create_file(hs_cmd_dev, &dev_attr_hall) < 0)
	{
	    HS_ERR("Failed to create device file(%s)!\n", dev_attr_hall.attr.name);
	}
	if(device_create_file(hs_cmd_dev, &dev_attr_hs_status) < 0)
	{
	    HS_ERR("Failed to create device file(%s)!\n", dev_attr_hall.attr.name);
	}

	ret = hs_input_device_create(pdev,data);
	if (ret) {
		HS_ERR(
		"Unable to register input device, error: %d\n",
			ret);
		goto fail_create;
	}
	data->hs_wq = create_singlethread_workqueue("hs_wq");
	if(!data->hs_wq){
		HS_ERR("Unable to create workqueue\n");
		goto fail_create;
	}
	if (!gpio_is_valid(data->gpio)) {
		HS_ERR("Invalid GPIO %d\n", data->gpio);
		goto fail_create;
	}
	ret = gpio_request(data->gpio, "hsensor");
	if (ret < 0) {
		HS_ERR("Failed to request GPIO %d\n",
				data->gpio);
		goto fail_create;
	}
	ret = gpio_direction_input(data->gpio);
	if (ret < 0) {
		HS_ERR(
		"Failed to configure direction for GPIO %d\n",
			data->gpio);
		goto fail_free;
	}
	irq = gpio_to_irq(data->gpio);
	data->irq = irq;
	if (irq < 0) {
		HS_ERR("Unable to get irq number for GPIO %d\n",
				data->gpio);
		goto fail_free;
	}

	ret = misc_register(&mh251_device);
	if (ret) {
		HS_ERR("misc_register failed!\n");
		goto fail_free;
	}
	irqflags = IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING |IRQF_NO_SUSPEND;
	ret = request_irq(irq, hs_interrupt_handler,
					irqflags, "hall_sensor",
					data);
	if (ret < 0) {
		HS_ERR("Unable to claim irq %d\n", irq);
		goto free_irq;
	}
	disable_irq(irq);
	this_pdev = pdev;
	wake_lock_init(&data->hs_wake_lock, WAKE_LOCK_SUSPEND, "hs_wake_lock");
	INIT_DELAYED_WORK(&data->hs_work, hs_report_function);
	HS_INFO("Hall sensor probe success \n");
	return ret;
free_irq:
	free_irq(irq, data);
fail_free:
	gpio_free(data->gpio);
fail_create:
	sysfs_remove_group(&pdev->dev.kobj, &hs_attr_group);
fail_sys:
	if (data)
		devm_kfree(&pdev->dev, data);
	return ret;
}

static int hsensor_remove(struct platform_device *pdev)
{
	struct mh251_data *data = platform_get_drvdata(pdev);

	wake_lock_destroy(&data->hs_wake_lock);
	sysfs_remove_group(&pdev->dev.kobj, &hs_attr_group);
	free_irq(data->irq, NULL);
	cancel_delayed_work_sync(&data->hs_work);
	if (gpio_is_valid(data->gpio))
		gpio_free(data->gpio);
	input_unregister_device(data->input_dev_hs);
	input_free_device(data->input_dev_hs);
	misc_deregister(&mh251_device);
	devm_kfree(&pdev->dev, data);
	data = NULL;
	return 0;
}

static const struct of_device_id hsensor_of_match[] = {
	{ .compatible = "marvell,hsensor",},
	{},
};
MODULE_DEVICE_TABLE(of, hsensor_of_match);

static struct platform_driver hsensor_driver = {
	.probe = hsensor_probe,
	.remove = hsensor_remove,
	.driver = {
		.name = "mst_mh251",
		.owner = THIS_MODULE,
		.of_match_table = hsensor_of_match,
	},
};
module_platform_driver(hsensor_driver);
MODULE_DESCRIPTION("Hall Sensor Driver");
MODULE_LICENSE("GPL");

