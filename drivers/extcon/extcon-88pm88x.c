/*
 * Marvell 88pm88x extcon driver
 *
 * this driver is used to detect VBUS or ID pin
 *
 * Author: Yi Zhang <yizhang@marvell.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/mfd/88pm88x.h>
#include <linux/mfd/88pm886.h>
#include <linux/mfd/88pm886-reg.h>
#include <linux/mfd/88pm88x-reg.h>
#include <linux/delay.h>
#include <linux/extcon.h>
#include <linux/of_device.h>

#define PM88X_VBUS_LOW_TH		(0x1a)
#define PM88X_VBUS_UPP_TH		(0x2a)

#define PM88X_USB_OTG_EN		(1 << 7)

#define PM88X_CHG_CONFIG4		(0x2B)
#define PM88X_VBUS_SW_EN		(1 << 0)

#define PM88X_OTG_LOG1			(0x47)
#define PM88X_OTG_UVVBAT		(1 << 0)
#define PM88X_OTG_SHORT_DET		(1 << 1)

#define PM88X_BOOST_CFG1		(0x6B)
#define PM88X_OTG_BST_VSET_MASK		(0x7)
#define PM88X_OTG_BST_VSET(x)		((x - 3750) / 250)

#define PM88X_CHG_STATUS2		(0x43)
#define PM88X_USB_LIM_OK		(1 << 3)
#define PM88X_VBUS_SW_OV		(1 << 0)

#define USB_OTG_MIN			(4800) /* mV */

/* choose 0x100(87.5mV) as threshold */
#define OTG_IDPIN_TH			(0x100)

/* 1.367 mV/LSB */
/*
 * this should be 1.709mV/LSB. setting to 1.367mV/LSB
 * as a W/A since there's currently a BUG per JIRA PM886-9
 * will be refined once fix is available
 */
#define PM886A0_VBUS_VOLT2REG(regval)	((regval << 9) / 700)
#define PM886A0_VBUS_REG2VOLT(volt)	((volt * 700) >> 9)

/* 1.709 mV/LSB */
#define PM88X_VBUS_VOLT2REG(regval)	((regval << 9) / 875)
#define PM88X_VBUS_REG2VOLT(volt)	((volt * 875) >> 9)

#define VBUS_TH_VOLT2REG(volt)		((((volt * 1000) / 1709) & 0xff0) >> 4)
#define VBUS_TH_VOLT2REG_886A0(volt)	((((volt * 1000) / 1367) & 0xff0) >> 4)

/* struct to save gpadc register address */
struct pm88x_gpadc_reg {
	unsigned int meas;
	unsigned int upp_th;
	unsigned int low_th;
};

struct pm88x_vbus_info {
	struct pm88x_chip	*chip;
	struct device		*dev;

	struct extcon_dev	edev;
	struct pm88x_gpadc_reg	gpadc;

	int			vbus_irq;
	int			id_irq;
	int			vbus_gpio;
	int			id_gpadc;
	bool			detect_usb_id;
	int			vbus_high_th;
	struct delayed_work	pxa_notify;
};

static const char *pm88x_extcon_cable[] = {
	[0] = "VBUS",
	[1] = "USB-ID",
	NULL,
};

static const int mutually_exclusive[] = {0x3, 0x0};

static void pm88x_vbus_check_errors(struct pm88x_vbus_info *info)
{
	int val = 0;

	regmap_read(info->chip->battery_regmap, PM88X_OTG_LOG1, &val);

	if (val & PM88X_OTG_UVVBAT)
		dev_err(info->chip->dev, "OTG error: OTG_UVVBAT\n");
	if (val & PM88X_OTG_SHORT_DET)
		dev_err(info->chip->dev, "OTG error: OTG_SHORT_DET\n");

	if (val)
		regmap_write(info->chip->battery_regmap, PM88X_OTG_LOG1, val);
}

enum vbus_volt_range {
	OFFLINE_RANGE = 0, /* vbus_volt_threshold[0, 1]*/
	ONLINE_RANGE, /* vbus_volt_threshold[2, 3]*/
	ABNORMAL_RANGE, /* vbus_volt_threshold[4, 5]*/
	MAX_RANGE,
};

struct volt_threshold {
	unsigned int lo; /* mV */
	unsigned int hi;
	int range_id;
};

/*
 * change according to chip: 5250mV and 5160mV
 * for 88pm886, different chips may have different OVPs,
 * so threshold 5250mv should not be constant,
 * we may use vbus-high-th to modify its value later.
 */
static struct volt_threshold vbus_volt[] = {
	[0] = {.lo = 0, .hi = 4000, .range_id = OFFLINE_RANGE},
	[1] = {.lo = 3500, .hi = 5250, .range_id = ONLINE_RANGE},
	[2] = {.lo = 5160, .hi = 6000, .range_id = ABNORMAL_RANGE},
};

static void config_vbus_threshold(struct pm88x_chip *chip, int range_id)
{
	unsigned int lo_volt, hi_volt, lo_reg, hi_reg;

	lo_volt = vbus_volt[range_id].lo;
	hi_volt = vbus_volt[range_id].hi;

	switch (chip->type) {
	case PM886:
		if (chip->chip_id == PM886_A0) {
			hi_reg = VBUS_TH_VOLT2REG_886A0(hi_volt);
			lo_reg = VBUS_TH_VOLT2REG_886A0(lo_volt);
		} else {
			hi_reg = VBUS_TH_VOLT2REG(hi_volt);
			lo_reg = VBUS_TH_VOLT2REG(lo_volt);
		}
		break;
	default:
		hi_reg = VBUS_TH_VOLT2REG(hi_volt);
		lo_reg = VBUS_TH_VOLT2REG(lo_volt);
		break;
	}

	regmap_write(chip->gpadc_regmap, PM88X_VBUS_LOW_TH, lo_reg);
	regmap_write(chip->gpadc_regmap, PM88X_VBUS_UPP_TH, hi_reg);
}

static int get_vbus_volt(struct pm88x_chip *chip)
{
	int ret, val, voltage;
	unsigned char buf[2];

	ret = regmap_bulk_read(chip->gpadc_regmap, PM88X_VBUS_MEAS1, buf, 2);
	if (ret)
		return ret;

	val = ((buf[0] & 0xff) << 4) | (buf[1] & 0x0f);

	switch (chip->type) {
	case PM886:
		if (chip->chip_id == PM886_A0)
			voltage = PM886A0_VBUS_REG2VOLT(val);
		else
			voltage = PM88X_VBUS_REG2VOLT(val);
		break;
	default:
		voltage = PM88X_VBUS_REG2VOLT(val);
		break;
	}

	return voltage;
}

/*
 * this function is only triggered by interrupt:
 * - when vbus interrupt happens, it must have cross the threashold
 * so no need to care about overlap
 */
static int get_current_range(struct pm88x_chip *chip)
{
	int current_vbus_volt, i, size;

	current_vbus_volt = get_vbus_volt(chip);
	dev_info(chip->dev, "now, vbus voltage = %dmV\n", current_vbus_volt);

	size = ARRAY_SIZE(vbus_volt);
	for (i = 0; i < size; i++) {
		if (current_vbus_volt >= vbus_volt[i].lo &&
		    current_vbus_volt <= vbus_volt[i].hi)
			return vbus_volt[i].range_id;
	}

	return -EINVAL;
}

static int pm88x_otg_boost_is_enabled(struct pm88x_chip *chip)
{
	unsigned int data;

	if (!chip)
		return 0;

	regmap_read(chip->battery_regmap, PM88X_CHG_CONFIG1, &data);

	return !!(data & PM88X_USB_OTG_EN);
}

static void pm88x_set_vbus_cable_state(struct pm88x_vbus_info *pm88x_vbus)
{
	int current_range;
	int ret = 0;

	if (pm88x_otg_boost_is_enabled(pm88x_vbus->chip))
		return;

	current_range = get_current_range(pm88x_vbus->chip);
	switch (current_range) {
	case ONLINE_RANGE:
		ret = extcon_set_cable_state(&pm88x_vbus->edev, "VBUS", true);
		dev_info(pm88x_vbus->dev, "%s: 88pm88x vbus high\n", __func__);
		break;
	case OFFLINE_RANGE:
	default:
		ret = extcon_set_cable_state(&pm88x_vbus->edev, "VBUS", false);
		dev_info(pm88x_vbus->dev, "%s: 88pm88x vbus low\n", __func__);
		break;
	}

	if (ret != 0)
		dev_err(pm88x_vbus->dev,
			"%s: fail to set cable state, ret=%d\n", __func__, ret);
}

static int pm88x_vbus_sw_ctrl(struct pm88x_chip *chip, bool enable)
{
	int ret = 0;
	unsigned int val = enable ? PM88X_VBUS_SW_EN : 0;

	switch (chip->type) {
	case PM886:
		if (chip->chip_id == PM886_A0)
			break;
	default:
		ret = regmap_update_bits(chip->battery_regmap,
					 PM88X_CHG_CONFIG4, PM88X_VBUS_SW_EN, val);
		break;
	}

	return ret;
}

static int pm88x_gpadc_config(struct pm88x_vbus_info *pm88x_vbus)
{
	unsigned int meas, upp_th, low_th, en;

	switch (pm88x_vbus->id_gpadc) {
	case PM88X_GPADC0:
		meas = PM88X_GPADC0_MEAS1;
		low_th = PM88X_GPADC0_LOW_TH;
		upp_th = PM88X_GPADC0_UPP_TH;
		en = PM88X_GPADC0_MEAS_EN;
		break;
	case PM88X_GPADC1:
		meas = PM88X_GPADC1_MEAS1;
		low_th = PM88X_GPADC1_LOW_TH;
		upp_th = PM88X_GPADC1_UPP_TH;
		en = PM88X_GPADC1_MEAS_EN;
		break;
	case PM88X_GPADC2:
		meas = PM88X_GPADC2_MEAS1;
		low_th = PM88X_GPADC2_LOW_TH;
		upp_th = PM88X_GPADC2_UPP_TH;
		en = PM88X_GPADC2_MEAS_EN;
		break;
	case PM88X_GPADC3:
		meas = PM88X_GPADC3_MEAS1;
		low_th = PM88X_GPADC3_LOW_TH;
		upp_th = PM88X_GPADC3_UPP_TH;
		en = PM88X_GPADC3_MEAS_EN;
		break;
	default:
		pr_err("%s: wrong gpadc number: %d\n", __func__, pm88x_vbus->id_gpadc);
		return -EINVAL;
	}

	pm88x_vbus->gpadc.meas = meas;
	pm88x_vbus->gpadc.upp_th = upp_th;
	pm88x_vbus->gpadc.low_th = low_th;

	/* GPADC module is not initialized yet, we enable GPADC measurement directly */
	regmap_update_bits(pm88x_vbus->chip->gpadc_regmap, PM88X_GPADC_CONFIG2, en, en);
	/* wait until the voltage is stable */
	usleep_range(10000, 20000);

	return 0;
}

static int pm88x_get_gpadc_data(struct pm88x_vbus_info *pm88x_vbus, int *data)
{
	unsigned char buf[2];
	int ret;

	ret = regmap_bulk_read(pm88x_vbus->chip->gpadc_regmap, pm88x_vbus->gpadc.meas, buf, 2);
	if (ret < 0)
		return ret;

	*data = ((buf[0] & 0xff) << 4) | (buf[1] & 0xf);

	return ret;
}

static void pm88x_set_id_cable_state(struct pm88x_vbus_info *pm88x_vbus)
{
	int ret, data;

	if ((pm88x_vbus->id_gpadc < PM88X_GPADC0) || (pm88x_vbus->id_gpadc > PM88X_GPADC3)) {
		dev_err(pm88x_vbus->dev, "%s: GPADC number is error.\n", __func__);
		return;
	}

	ret = pm88x_get_gpadc_data(pm88x_vbus, &data);
	if (ret < 0)
		return;

	if (data > OTG_IDPIN_TH) {
		regmap_write(pm88x_vbus->chip->gpadc_regmap, pm88x_vbus->gpadc.low_th,
			     OTG_IDPIN_TH >> 4);
		regmap_write(pm88x_vbus->chip->gpadc_regmap, pm88x_vbus->gpadc.upp_th, 0xff);
		ret = extcon_set_cable_state(&pm88x_vbus->edev, "USB-ID", false);
		dev_info(pm88x_vbus->dev, "%s: USB-HOST cable is not attached\n", __func__);
	} else {
		regmap_write(pm88x_vbus->chip->gpadc_regmap, pm88x_vbus->gpadc.low_th, 0);
		regmap_write(pm88x_vbus->chip->gpadc_regmap, pm88x_vbus->gpadc.upp_th,
			     OTG_IDPIN_TH >> 4);
		ret = extcon_set_cable_state(&pm88x_vbus->edev, "USB-ID", true);
		dev_info(pm88x_vbus->dev, "%s: USB-HOST cable is attached\n", __func__);
	}

	if (ret != 0)
		dev_err(pm88x_vbus->dev,
			"%s: fail to set cable state, ret=%d\n", __func__, ret);
}

static void dump_vbus_ov_status(struct pm88x_vbus_info *info)
{
	int ret;
	unsigned int val;
	bool usb_lim_ok, vbus_sw_ov, vbus_sw_en;

	ret = regmap_read(info->chip->battery_regmap, PM88X_CHG_STATUS2, &val);
	if (ret) {
		dev_err(info->chip->dev, "fail to read charger status: %d\n", ret);
		return;
	}

	usb_lim_ok = !!(val & PM88X_USB_LIM_OK);
	vbus_sw_ov = !!(val & PM88X_VBUS_SW_OV);

	ret = regmap_read(info->chip->battery_regmap, PM88X_CHG_CONFIG4, &val);
	if (ret) {
		dev_err(info->chip->dev, "fail to read charger config 4: %d\n", ret);
		return;
	}

	vbus_sw_en = !!(val & PM88X_VBUS_SW_EN);

	/*
	 * usb_lim_ok = 1, 4V < VBUS < 6V
	 * vbus_sw_ov = 1, VBUS > 5.25V or VBUS_SW_EN = 0, VBUS switch is opened.
	 */
	dev_info(info->chip->dev, "usb_lim_ok:%d vbus_sw_ov:%d vbus_sw_en:%d\n",
		 usb_lim_ok, vbus_sw_ov, vbus_sw_en);
}

static irqreturn_t pm88x_vbus_irq_handler(int irq, void *_pm88x_vbus)
{
	int current_range;
	struct pm88x_vbus_info *pm88x_vbus = _pm88x_vbus;

	dev_info(pm88x_vbus->chip->dev, "88pm88x vbus interrupt is served..\n");

	/* otg boost enabled case */
	if (pm88x_otg_boost_is_enabled(pm88x_vbus->chip)) {
		dev_info(pm88x_vbus->chip->dev, "otg boost is enabled.\n");
		return IRQ_HANDLED;
	}

	current_range = get_current_range(pm88x_vbus->chip);
	if (current_range < 0) {
		dev_err(pm88x_vbus->chip->dev, "what happened to vbus?\n");
		/* stop configuring ranges */
		goto out;
	}

	/* set new range */
	config_vbus_threshold(pm88x_vbus->chip, current_range);

	/* close the USB_SW for online, open the USB_SW for offline to save power */
	if (current_range == ONLINE_RANGE)
		pm88x_vbus_sw_ctrl(pm88x_vbus->chip, true);
	else
		pm88x_vbus_sw_ctrl(pm88x_vbus->chip, false);

out:
	dump_vbus_ov_status(pm88x_vbus);
	/* allowing 7.5msec for the SW to close */
	schedule_delayed_work(&pm88x_vbus->pxa_notify, usecs_to_jiffies(7500));

	return IRQ_HANDLED;
}

static irqreturn_t pm88x_id_irq_handler(int irq, void *_pm88x_vbus)
{
	struct pm88x_vbus_info *pm88x_vbus = _pm88x_vbus;

	dev_info(pm88x_vbus->chip->dev, "88pm88x idpin interrupt is served..\n");

	pm88x_set_id_cable_state(pm88x_vbus);

	return IRQ_HANDLED;
}

static void pm88x_vbus_work_callback(struct work_struct *work)
{
	struct pm88x_vbus_info *pm88x_vbus =
		container_of(work, struct pm88x_vbus_info, pxa_notify.work);

	pm88x_set_vbus_cable_state(pm88x_vbus);
	return;
}

static void pm88x_vbus_config(struct pm88x_vbus_info *info)
{
	if (!info)
		return;

	/* set booster voltage to 5.0V */
	regmap_update_bits(info->chip->battery_regmap, PM88X_BOOST_CFG1,
			   PM88X_OTG_BST_VSET_MASK, PM88X_OTG_BST_VSET(5000));

	/* clear OTG errors */
	pm88x_vbus_check_errors(info);
}

static void pm88x_vbus_fixup(struct pm88x_vbus_info *info)
{
	if (!info || !info->chip) {
		pr_err("%s: empty device information.\n", __func__);
		return;
	}

	switch (info->chip->type) {
	case PM886:
		if (info->chip->chip_id == PM886_A0) {
			pr_info("%s: fix up for the vbus driver.\n", __func__);
			/* 1. unlock test page */
			hold_test_page(info->chip);
			/* 2. test page 0x90.[4:0] = 0, reset trimming to mid point 0 */
			regmap_update_bits(info->chip->test_regmap, 0x90, 0x1f << 0, 0);
			/* 3. lock the test page */
			release_test_page(info->chip);
		}
		break;
	default:
		break;
	}
}

static int pm88x_vbus_probe(struct platform_device *pdev)
{
	struct pm88x_chip *chip = dev_get_drvdata(pdev->dev.parent);
	struct device_node *node = pdev->dev.of_node;
	struct pm88x_vbus_info *pm88x_vbus;
	int current_range, ret;
	const char *id_gpadc_name;

	pm88x_vbus = devm_kzalloc(&pdev->dev, sizeof(*pm88x_vbus), GFP_KERNEL);
	if (!pm88x_vbus)
		return -ENOMEM;

	/* parse device tree */
	pm88x_vbus->detect_usb_id =
		of_property_read_bool(node, "marvell,enable-usb-id-detection");

	if (pm88x_vbus->detect_usb_id) {
		of_property_read_string(node, "marvell,usb-id-gpadc", &id_gpadc_name);
		dev_info(&pdev->dev,
			 "%s is used to detect id pin.\n", id_gpadc_name);
	}

	pm88x_vbus->chip = chip;
	pm88x_vbus->dev = &pdev->dev;
	pm88x_vbus->vbus_irq = platform_get_irq_byname(pdev, "88pm88x-vbus-det");
	if (pm88x_vbus->detect_usb_id) {
		pm88x_vbus->id_irq = platform_get_irq_byname(pdev, id_gpadc_name);
		pm88x_vbus->id_gpadc =
			pm88x_vbus->id_irq - regmap_irq_chip_get_base(chip->irq_data);
		pm88x_vbus->id_gpadc -= PM88X_IRQ_GPADC0;
		pm88x_gpadc_config(pm88x_vbus);
	}

	ret = of_property_read_u32(node, "vbus-high-th", &pm88x_vbus->vbus_high_th);
	if (!ret) {
		vbus_volt[ONLINE_RANGE].hi = pm88x_vbus->vbus_high_th;
		vbus_volt[ABNORMAL_RANGE].lo = pm88x_vbus->vbus_high_th - 90;
		dev_info(&pdev->dev, "reset vbus-high-th %d.\n", vbus_volt[ONLINE_RANGE].hi);
	}

	platform_set_drvdata(pdev, pm88x_vbus);

	current_range = get_current_range(chip);
	if (current_range < 0) {
		dev_err(chip->dev, "what happened to vbus?\n");
		return -EINVAL;
	}
	/* set new range */
	config_vbus_threshold(chip, current_range);
	/* do it before enable interrupt */
	pm88x_vbus_fixup(pm88x_vbus);

	/* initialize the extcon device */
	pm88x_vbus->edev.supported_cable = pm88x_extcon_cable;
	pm88x_vbus->edev.dev.parent = pm88x_vbus->dev;
	pm88x_vbus->edev.mutually_exclusive = mutually_exclusive;
	pm88x_vbus->edev.name = "88pm88x-extcon";

	ret = extcon_dev_register(&pm88x_vbus->edev);
	if (ret) {
		dev_err(&pdev->dev, "failed to register extcon device\n");
		return ret;
	}

	/* initial the vbus state */
	pm88x_set_vbus_cable_state(pm88x_vbus);
	/* initial the id state */
	if (pm88x_vbus->detect_usb_id)
		pm88x_set_id_cable_state(pm88x_vbus);

	INIT_DELAYED_WORK(&pm88x_vbus->pxa_notify, pm88x_vbus_work_callback);

	ret = devm_request_threaded_irq(pm88x_vbus->dev,
					pm88x_vbus->vbus_irq, NULL,
					pm88x_vbus_irq_handler,
					IRQF_ONESHOT | IRQF_NO_SUSPEND,
					"pm88x_usb_vbus", pm88x_vbus);
	if (ret < 0) {
		dev_err(&pdev->dev, "can't get IRQ %d, err %d\n",
			pm88x_vbus->vbus_irq, ret);
		goto fail_extcon;
	}

	if (pm88x_vbus->detect_usb_id) {
		pm88x_vbus_config(pm88x_vbus);
		ret = devm_request_threaded_irq(pm88x_vbus->dev,
						pm88x_vbus->id_irq,
						NULL, pm88x_id_irq_handler,
						IRQF_ONESHOT | IRQF_NO_SUSPEND,
						"pm88x_usb_id", pm88x_vbus);
		if (ret < 0) {
			dev_err(&pdev->dev, "can't get IRQ %d, err %d\n",
				pm88x_vbus->id_irq, ret);
			goto fail_extcon;
		}
	}

	device_init_wakeup(&pdev->dev, 1);

	return 0;

fail_extcon:
	extcon_dev_unregister(&pm88x_vbus->edev);
	return ret;
}

static int pm88x_vbus_remove(struct platform_device *pdev)
{
	struct pm88x_vbus_info *pm88x_vbus = platform_get_drvdata(pdev);

	extcon_dev_unregister(&pm88x_vbus->edev);

	return 0;
}

static int pm88x_vbus_suspend(struct device *dev)
{
	return 0;
}

static int pm88x_vbus_resume(struct device *dev)
{
	return 0;
};

static const struct dev_pm_ops pm88x_vbus_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(pm88x_vbus_suspend,
				pm88x_vbus_resume)
};

static struct of_device_id of_pm88x_match_tbl[] = {
	{ .compatible = "marvell,88pm88x-vbus", },
	{ /* end */ }
};
MODULE_DEVICE_TABLE(of, of_pm88x_match_tbl);

static struct platform_driver pm88x_vbus_driver = {
	.probe = pm88x_vbus_probe,
	.remove = pm88x_vbus_remove,
	.driver = {
		.name = "88pm88x-vbus",
		.of_match_table = of_match_ptr(of_pm88x_match_tbl),
		.owner = THIS_MODULE,
		.pm = &pm88x_vbus_pm_ops,
	},
};

module_platform_driver(pm88x_vbus_driver);

MODULE_ALIAS("platform:88pm88x-vbus");
MODULE_AUTHOR("Yi Zhang <yizhang@marvell.com>");
MODULE_DESCRIPTION("88pm88x extcon driver");
MODULE_LICENSE("GPL");
