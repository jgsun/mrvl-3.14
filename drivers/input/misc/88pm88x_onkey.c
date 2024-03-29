/*
 * Marvell 88PM886 ONKEY driver
 *
 * Copyright (C) 2014 Marvell International Ltd.
 * Yi Zhang <yizhang@marvell.com>
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License. See the file "COPYING" in the main directory of this
 * archive for more details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/input.h>
#include <linux/mfd/88pm88x.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/of.h>

#define PM88X_ONKEY_STS1		(0x1 << 0)

#define PM88X_GPIO0_HW_RST1_N		(0x6 << 1)
#define PM88X_GPIO0_HW_RST2_N		(0x7 << 1)

#define PM88X_GPIO1_HW_RST1_N		(0x6 << 5)
#define PM88X_GPIO1_HW_RST2_N		(0x7 << 5)

#define PM88X_GPIO2_HW_RST1		(0x6 << 1)
#define PM88X_GPIO2_HW_RST2		(0x7 << 1)

#define PM88X_HWRST_DB_MSK		(0x1 << 7)
#define PM88X_HWRST_DB_SHIFT		(7)

#define PM88X_LONKEY_PRESS_TIME_MSK	(0xf0)
#define PM88X_LONKEY_PRESS_TIME_SHIFT	(4)
#define PM88X_LONKEY_RESTOUTN_PULSE_MSK (0x3)
#define PM88X_LONKEY_RESTOUTN_PULSE_1S	(0x1 << 0)

#define PM88X_LONG_ONKEY_EN_MSK		(0x3)

#define PM88X_FAULT_WU_EN		(1 << 2)

enum {
	PM88X_LONG_ONKEY_DETECT_RTC,
	PM88X_LONG_ONKEY_DETECT1,
	PM88X_LONG_ONKEY_DETECT2,
};

enum {
	PM88X_HWRST_DB_2S,
	PM88X_HWRST_DB_7S,
};

enum {
	PM88X_HW_RESET_DETECT1 = 1,
	PM88X_HW_RESET_DETECT2,
};

enum {
	PM88X_HW_RESET_DETECT1_N = 1,
	PM88X_HW_RESET_DETECT2_N,
};

struct pm88x_onkey_info {
	struct input_dev *idev;
	struct pm88x_chip *pm88x;
	struct regmap *map;
	struct delayed_work long_onkey_rst_work;
	int irq;
	int gpio_number;
	int long_onkey_type;
	int disable_long_key_rst;
	int long_key_rst_delay_time;
	int long_key_press_time;
	int hwrst_db_period;	/* hardware reset debounce period */
	int hwrst_type;
};

static struct pm88x_onkey_info *g_info;

static char *long_onkey_type[3] = {
	"LONG ONKEY RTC",
	"DETECTION1 (power off)",
	"DETECTION2 (reset)"
};

static char *hw_rst_type[2] = {
	"DETECTION1 (reset)",
	"DETECTION2 (power off)"
};

static int pm88x_config_gpio(struct pm88x_onkey_info *info)
{
	int gpio_mode;
	if (!info || !info->map) {
		pr_err("%s: No chip information!\n", __func__);
		return -ENODEV;
	}

	/* choose HW_RST1_N for GPIO, only toggle RESETOUTN */
	switch (info->gpio_number) {
	case 0:
		gpio_mode = (info->hwrst_type == PM88X_HW_RESET_DETECT1_N ?
			     PM88X_GPIO0_HW_RST1_N : PM88X_GPIO0_HW_RST2_N);
		regmap_update_bits(info->map, PM88X_GPIO_CTRL1,
				   PM88X_GPIO0_MODE_MSK, gpio_mode);
		break;
	case 1:
		gpio_mode = (info->hwrst_type == PM88X_HW_RESET_DETECT1_N ?
			     PM88X_GPIO1_HW_RST1_N : PM88X_GPIO1_HW_RST2_N);
		regmap_update_bits(info->map, PM88X_GPIO_CTRL1,
				   PM88X_GPIO1_MODE_MSK, gpio_mode);
		break;
	case 2:
		gpio_mode = (info->hwrst_type == PM88X_HW_RESET_DETECT1 ?
			     PM88X_GPIO2_HW_RST1 : PM88X_GPIO2_HW_RST2);
		regmap_update_bits(info->map, PM88X_GPIO_CTRL2,
				   PM88X_GPIO2_MODE_MSK, gpio_mode);
		break;
	default:
		dev_err(info->idev->dev.parent, "use the wrong GPIO, exit 0\n");
		return 0;
	}
	/* 0xe2: set debounce period of ONKEY, when used with GPIO */
	regmap_update_bits(info->map, PM88X_AON_CTRL2,
			   PM88X_HWRST_DB_MSK , info->hwrst_db_period << PM88X_HWRST_DB_SHIFT);
	return 0;
}

static int pm88x_config_long_onkey(struct pm88x_onkey_info *info)
{
	/* 0xe3: set debounce period of ONKEY as 10s and set duration of RESETOUTN pulse as 1s */
	regmap_update_bits(info->map, PM88X_AON_CTRL3,
			   (PM88X_LONKEY_PRESS_TIME_MSK | PM88X_LONKEY_RESTOUTN_PULSE_MSK),
			   ((info->long_key_press_time << PM88X_LONKEY_PRESS_TIME_SHIFT) |
			   PM88X_LONKEY_RESTOUTN_PULSE_1S));

	/* 0xe4: enable LONG_ONKEY_DETECT, onkey reset system */
	regmap_update_bits(info->map, PM88X_AON_CTRL4,
			   PM88X_LONG_ONKEY_EN_MSK, info->long_onkey_type);

	return 0;
}

static int pm88x_onkey_rst_and_get_sts(struct pm88x_onkey_info *info, unsigned int *val)
{
	int ret;

	/* reset the LONKEY reset time */
	regmap_update_bits(info->map, PM88X_MISC_CONFIG1,
			   PM88X_LONKEY_RST, PM88X_LONKEY_RST);

	ret = regmap_read(info->map, PM88X_STATUS1, val);
	if (ret < 0) {
		dev_err(info->idev->dev.parent,
			"failed to read status: %d\n", ret);
		return ret;
	}

	*val &= PM88X_ONKEY_STS1;

	return ret;
}

static void pm88x_onkey_rst_work(struct work_struct *work)
{
	struct pm88x_onkey_info *info =
		container_of(work, struct pm88x_onkey_info,
			     long_onkey_rst_work.work);
	unsigned int val;

	pm88x_onkey_rst_and_get_sts(info, &val);
	if (val)
		schedule_delayed_work(&info->long_onkey_rst_work, info->long_key_rst_delay_time);
}

static irqreturn_t pm88x_onkey_handler(int irq, void *data)
{
	struct pm88x_onkey_info *info = data;
	int ret = 0;
	unsigned int val;

	ret = pm88x_onkey_rst_and_get_sts(info, &val);
	if (ret < 0)
		return IRQ_NONE;

	if (info->disable_long_key_rst) {
		if (val)
			schedule_delayed_work(&info->long_onkey_rst_work,
					      info->long_key_rst_delay_time);
		else
			cancel_delayed_work(&info->long_onkey_rst_work);
	}
	input_report_key(info->idev, KEY_POWER, val);
	input_sync(info->idev);

	return IRQ_HANDLED;
}

static SIMPLE_DEV_PM_OPS(pm88x_onkey_pm_ops, NULL, NULL);

static int pm88x_onkey_dt_init(struct device_node *np,
			       struct pm88x_onkey_info *info)
{
	int ret;

	if (!info) {
		pr_err("%s: No chip information!\n", __func__);
		return -ENODEV;
	}

	ret = of_property_read_u32(np, "pm88x-onkey-gpio-number",
				   &info->gpio_number);
	if (ret < 0) {
		/* give the gpio number as a default value */
		info->gpio_number = -1;
		dev_warn(info->idev->dev.parent, "No GPIO for long onkey.\n");
	}

	ret = of_property_read_u32(np, "pm88x-onkey-long-onkey-type",
				   &info->long_onkey_type);
	if (ret < 0) {
		/* LONG_ONKEY_DETECT2 is enabled by default */
		info->long_onkey_type = PM88X_LONG_ONKEY_DETECT2;
		dev_warn(info->idev->dev.parent, "Not select LONG ONKEY function.\n");
	}

	ret = of_property_read_u32(np, "pm88x-onkey-disable-long-key-rst",
				   &info->disable_long_key_rst);
	if (ret < 0) {
		/* LONKEY reset function is enabled by default */
		info->disable_long_key_rst = 0;
		dev_warn(info->idev->dev.parent, "LONKEY disable function is not set.\n");
	}

	ret = of_property_read_u32(np, "pm88x-onkey-long-key-press-time",
				   &info->long_key_press_time);
	if (ret < 0) {
		/* LONKEY press time is 10s by default */
		info->long_key_press_time = 10;
		dev_warn(info->idev->dev.parent, "LONKEY press time is not set.\n");
	}

	ret = of_property_read_u32(np, "pm88x-onkey-hwrst-db-period",
				   &info->hwrst_db_period);
	if (ret < 0) {
		/* hw reset db period is 7s by default */
		info->hwrst_db_period = PM88X_HWRST_DB_7S;
		dev_warn(info->idev->dev.parent, "HW reset db period is not set.\n");
	}

	ret = of_property_read_u32(np, "pm88x-onkey-hwrst-type", &info->hwrst_type);
	if (ret < 0) {
		/* HWRST_DETECT1 is default */
		info->hwrst_type = PM88X_HW_RESET_DETECT1;
		dev_warn(info->idev->dev.parent, "HW reset type is not set.\n");
	}

	return 0;
}

int pm88x_onkey_display_status(char *buf)
{
	int len;

	len = sprintf(buf, "\nONKEY status:\n");
	len += sprintf(buf + len, "GPIO number: %d\n", g_info->gpio_number);
	len += sprintf(buf + len, "long onkey detection type: %s\n",
		       long_onkey_type[g_info->long_onkey_type]);
	len += sprintf(buf + len, "hardware reset detection type: %s\n",
		       hw_rst_type[g_info->hwrst_type - 1]);
	len += sprintf(buf + len, "long onkey press time: %ds\n", g_info->long_key_press_time);
	len += sprintf(buf + len, "onkey hardware reset debounce period: %ds\n",
		       g_info->hwrst_db_period ? 7 : 2);
	len += sprintf(buf + len, "long onkey reset status: %s\n",
		       g_info->disable_long_key_rst ? "disable" : "enable");

	return len;
}

int pm88x_onkey_config_status(char arg, int val)
{
	switch (arg) {
	case 'l':
		if (val < 0 || val > 2)
			goto out;
		g_info->long_onkey_type = val;
		pr_info("long onkey detection type is set to: %s\n", long_onkey_type[val]);
		break;
	case 'h':
		if (val < 1 || val > 2)
			goto out;
		g_info->hwrst_type = val;
		pr_info("hardware reset detection type is set to: %s\n", hw_rst_type[val - 1]);
		break;
	case 't':
		if (val < 1 || val > 15)
			goto out;
		g_info->long_key_press_time = val;
		pr_info("long onkey press time is set to: %ds\n", val);
		break;
	case 'd':
		if (val < 0 || val > 1)
			goto out;
		g_info->hwrst_db_period = val;
		pr_info("hardware reset debounce period is set to: %ds\n", val ? 7 : 2);
		break;
	default:
		goto out;
	}

	pm88x_config_gpio(g_info);
	pm88x_config_long_onkey(g_info);

	return 0;

out:
	pr_err("Invalid parameter, please check.\n");
	return -EINVAL;
}

static int pm88x_onkey_probe(struct platform_device *pdev)
{

	struct pm88x_chip *chip = dev_get_drvdata(pdev->dev.parent);
	struct device_node *node = pdev->dev.of_node;
	struct pm88x_onkey_info *info;
	int err;

	info = devm_kzalloc(&pdev->dev, sizeof(struct pm88x_onkey_info),
			    GFP_KERNEL);
	if (!info || !chip)
		return -ENOMEM;
	info->pm88x = chip;

	info->irq = platform_get_irq(pdev, 0);
	if (info->irq < 0) {
		dev_err(&pdev->dev, "No IRQ resource!\n");
		err = -EINVAL;
		goto out;
	}

	info->map = info->pm88x->base_regmap;
	if (!info->map) {
		dev_err(&pdev->dev, "No regmap handler!\n");
		err = -EINVAL;
		goto out;
	}

	info->idev = input_allocate_device();
	if (!info->idev) {
		dev_err(&pdev->dev, "Failed to allocate input dev\n");
		err = -ENOMEM;
		goto out;
	}

	info->idev->name = "88pm88x_on";
	info->idev->phys = "88pm88x_on/input0";
	info->idev->id.bustype = BUS_I2C;
	info->idev->dev.parent = &pdev->dev;
	info->idev->evbit[0] = BIT_MASK(EV_KEY);
	__set_bit(KEY_POWER, info->idev->keybit);

	err = pm88x_onkey_dt_init(node, info);
	if (err < 0) {
		err = -ENODEV;
		goto out_register;
	}

	g_info = info;

	err = devm_request_threaded_irq(&pdev->dev, info->irq, NULL,
					pm88x_onkey_handler,
					IRQF_ONESHOT | IRQF_NO_SUSPEND,
					"onkey", info);
	if (err < 0) {
		dev_err(&pdev->dev, "Failed to request IRQ: #%d: %d\n",
			info->irq, err);
		goto out_register;
	}

	err = input_register_device(info->idev);
	if (err) {
		dev_err(&pdev->dev, "Can't register input device: %d\n", err);
		goto out_register;
	}

	platform_set_drvdata(pdev, info);

	device_init_wakeup(&pdev->dev, 1);

	err = pm88x_config_gpio(info);
	if (err < 0) {
		dev_err(&pdev->dev, "Can't configure gpio: %d\n", err);
		goto out_register;
	}

	err = pm88x_config_long_onkey(info);

	if (info->disable_long_key_rst) {
		INIT_DELAYED_WORK(&info->long_onkey_rst_work, pm88x_onkey_rst_work);

		if (info->long_key_press_time > 1)
			info->long_key_rst_delay_time = msecs_to_jiffies
					((info->long_key_press_time - 1) * 1000);
		else
			info->long_key_rst_delay_time = msecs_to_jiffies(500);
	}

	/* 0xe7: enable fault wakeup */
	regmap_update_bits(info->map, PM88X_AON_CTRL7,
			   PM88X_FAULT_WU_EN, PM88X_FAULT_WU_EN);

	return 0;

out_register:
	input_free_device(info->idev);
out:
	return err;
}

static int pm88x_onkey_remove(struct platform_device *pdev)
{
	struct pm88x_onkey_info *info = platform_get_drvdata(pdev);

	if (info->disable_long_key_rst)
		cancel_delayed_work(&info->long_onkey_rst_work);

	device_init_wakeup(&pdev->dev, 0);
	devm_free_irq(&pdev->dev, info->irq, info);

	input_unregister_device(info->idev);

	devm_kfree(&pdev->dev, info);

	return 0;
}

static const struct of_device_id pm88x_onkey_dt_match[] = {
	{ .compatible = "marvell,88pm88x-onkey", },
	{ },
};
MODULE_DEVICE_TABLE(of, pm88x_onkey_dt_match);

static struct platform_driver pm88x_onkey_driver = {
	.driver = {
		.name = "88pm88x-onkey",
		.owner = THIS_MODULE,
		.pm = &pm88x_onkey_pm_ops,
		.of_match_table = of_match_ptr(pm88x_onkey_dt_match),
	},
	.probe = pm88x_onkey_probe,
	.remove = pm88x_onkey_remove,
};
module_platform_driver(pm88x_onkey_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Marvell 88PM88x ONKEY driver");
MODULE_AUTHOR("Yi Zhang <yizhang@marvell.com>");
MODULE_ALIAS("platform:88pm88x-onkey");
