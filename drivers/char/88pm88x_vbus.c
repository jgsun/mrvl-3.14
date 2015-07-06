/*
 * 88pm88x VBus driver for Marvell USB
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
#include <linux/of_device.h>
#include <linux/platform_data/mv_usb.h>

#define PM88X_VBUS_LOW_TH (0x1a)
#define PM88X_VBUS_UPP_TH (0x2a)

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
#define PM886A0_VBUS_VOLT2REG(volt)	((volt << 9) / 700)
#define PM886A0_VBUS_REG2VOLT(regval)		((regval * 700) >> 9)

/* 1.709 mV/LSB */
#define PM88X_VBUS_VOLT2REG(volt)		((volt << 9) / 875)
#define PM88X_VBUS_REG2VOLT(regval)		((regval * 875) >> 9)

#define VBUS_TH_VOLT2REG(volt)		((((volt * 1000) / 1709) & 0xff0) >> 4)
#define VBUS_TH_VOLT2REG_886A0(volt)	((((volt * 1000) / 1367) & 0xff0) >> 4)

struct pm88x_vbus_info {
	struct pm88x_chip	*chip;
	int			vbus_irq;
	int			id_irq;
	int			vbus_gpio;
	int			id_gpadc;
	struct delayed_work	pxa_notify;
};

static struct pm88x_vbus_info *vbus_info;

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
	ONLINE_RANGE,  /* vbus_volt_threshold[2, 3]*/
	ABNORMAL_RANGE, /* vbus_volt_threshold[4, 5]*/
	MAX_RANGE,
};

struct volt_threshold {
	unsigned int lo; /* mV */
	unsigned int hi;
	int range_id;
};

/* change according to chip: 5250mV and 5160mV */
static const struct volt_threshold vbus_volt[] = {
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

	ret = regmap_bulk_read(chip->gpadc_regmap,
				PM88X_VBUS_MEAS1, buf, 2);
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

static int pm88x_otg_boost_on(struct pm88x_chip *chip)
{
	unsigned int data;

	if (!chip)
		return 0;

	regmap_read(chip->battery_regmap, PM88X_CHG_CONFIG1, &data);

	return data & PM88X_USB_OTG_EN;
}

static int pm88x_get_vbus(unsigned int *level)
{
	int volt, current_range;

	/* otg boost enabled case */
	if (pm88x_otg_boost_on(vbus_info->chip)) {
		volt = get_vbus_volt(vbus_info->chip);
		if (volt >= USB_OTG_MIN)
			*level = VBUS_HIGH;
		else
			*level = VBUS_LOW;

		return 0;
	}

	current_range = get_current_range(vbus_info->chip);
	switch (current_range) {
	case ONLINE_RANGE:
		*level = VBUS_HIGH;
		break;
	default:
	case OFFLINE_RANGE:
		*level = VBUS_LOW;
		pm88x_vbus_check_errors(vbus_info);
		break;
	}

	return 0;
}

static int pm88x_vbus_sw_control(bool enable)
{
	int ret = 0;
	unsigned int val = enable ? PM88X_VBUS_SW_EN : 0;

	switch (vbus_info->chip->type) {
	case PM886:
		if (vbus_info->chip->chip_id == PM886_A0)
			break;
	default:
		ret = regmap_update_bits(vbus_info->chip->battery_regmap,
			PM88X_CHG_CONFIG4, PM88X_VBUS_SW_EN, val);
		break;
	}

	return ret;
}

static int pm88x_set_vbus(unsigned int vbus)
{
	int ret;
	unsigned int data = 0;

	if (vbus == VBUS_HIGH) {
		ret = regmap_update_bits(vbus_info->chip->battery_regmap, PM88X_CHG_CONFIG1,
					PM88X_USB_OTG_EN, PM88X_USB_OTG_EN);
		if (ret)
			return ret;

		ret = pm88x_vbus_sw_control(true);
	} else {
		ret = regmap_update_bits(vbus_info->chip->battery_regmap, PM88X_CHG_CONFIG1,
					PM88X_USB_OTG_EN, 0);
		if (ret)
			return ret;

		ret = pm88x_vbus_sw_control(false);
	}

	if (ret)
		return ret;

	usleep_range(10000, 20000);

	ret = pm88x_get_vbus(&data);
	if (ret)
		return ret;

	if (data != vbus) {
		dev_err(vbus_info->chip->dev, "vbus set failed %x\n", vbus);
		pm88x_vbus_check_errors(vbus_info);
	} else
		dev_info(vbus_info->chip->dev, "vbus set done %x\n", vbus);

	return 0;
}

static int pm88x_read_id_val(unsigned int *level)
{
	unsigned int meas, upp_th, low_th;
	unsigned char buf[2];
	int ret, data;

	switch (vbus_info->id_gpadc) {
	case PM88X_GPADC0:
		meas = PM88X_GPADC0_MEAS1;
		low_th = PM88X_GPADC0_LOW_TH;
		upp_th = PM88X_GPADC0_UPP_TH;
		break;
	case PM88X_GPADC1:
		meas = PM88X_GPADC1_MEAS1;
		low_th = PM88X_GPADC1_LOW_TH;
		upp_th = PM88X_GPADC1_UPP_TH;
		break;
	case PM88X_GPADC2:
		meas = PM88X_GPADC2_MEAS1;
		low_th = PM88X_GPADC2_LOW_TH;
		upp_th = PM88X_GPADC2_UPP_TH;
		break;
	case PM88X_GPADC3:
		meas = PM88X_GPADC3_MEAS1;
		low_th = PM88X_GPADC3_LOW_TH;
		upp_th = PM88X_GPADC3_UPP_TH;
		break;
	default:
		return -ENODEV;
	}

	ret = regmap_bulk_read(vbus_info->chip->gpadc_regmap, meas, buf, 2);
	if (ret)
		return ret;

	data = ((buf[0] & 0xFF) << 4) | (buf[1] & 0xF);

	if (data > OTG_IDPIN_TH) {
		regmap_write(vbus_info->chip->gpadc_regmap, low_th, OTG_IDPIN_TH >> 4);
		regmap_write(vbus_info->chip->gpadc_regmap, upp_th, 0xff);
		*level = VBUS_HIGH;
	} else {
		regmap_write(vbus_info->chip->gpadc_regmap, low_th, 0);
		regmap_write(vbus_info->chip->gpadc_regmap, upp_th, OTG_IDPIN_TH >> 4);
		*level = VBUS_LOW;
	}

	return 0;
};

static int pm88x_init_id(void)
{
	return 0;
}

static void pm88x_pxa_notify(struct work_struct *work)
{
	struct pm88x_vbus_info *info =
		container_of(work, struct pm88x_vbus_info, pxa_notify.work);
	/*
	 * 88pm88x has no ability to distinguish
	 * AC/USB charger, so notify usb framework to do it
	 */
	pxa_usb_notify(PXA_USB_DEV_OTG, EVENT_VBUS, 0);
	dev_dbg(info->chip->dev, "88pm88x vbus pxa usb is notified..\n");
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

static irqreturn_t pm88x_vbus_handler(int irq, void *data)
{
	int current_range;
	struct pm88x_vbus_info *info = data;

	dev_info(info->chip->dev, "88pm88x vbus interrupt is served..\n");

	/* if vbus raise caused by OTG boost, ignore it */
	if (pm88x_otg_boost_on(info->chip)) {
		dev_info(info->chip->dev, "OTG boost case, exit\n");
		return IRQ_HANDLED;
	}

	current_range = get_current_range(vbus_info->chip);
	if (current_range < 0) {
		dev_err(info->chip->dev, "what happened to vbus?\n");
		/* stop configuring ranges */
		goto out;
	}

	/* set new range */
	config_vbus_threshold(vbus_info->chip, current_range);

	/* close the USB_SW for online, open the USB_SW for offline to save power */
	if (current_range == ONLINE_RANGE)
		pm88x_vbus_sw_control(true);
	else
		pm88x_vbus_sw_control(false);

out:
	dump_vbus_ov_status(info);
	/* allowing 7.5msec for the SW to close */
	schedule_delayed_work(&info->pxa_notify, usecs_to_jiffies(7500));
	return IRQ_HANDLED;
}

static irqreturn_t pm88x_id_handler(int irq, void *data)
{
	struct pm88x_vbus_info *info = data;

	 /* notify to wake up the usb subsystem if ID pin is pulled down */
	pxa_usb_notify(PXA_USB_DEV_OTG, EVENT_ID, 0);
	dev_dbg(info->chip->dev, "88pm88x id interrupt is served..\n");
	return IRQ_HANDLED;
}

static void pm88x_vbus_config(struct pm88x_vbus_info *info)
{
	unsigned int en, low_th, upp_th;

	if (!info)
		return;

	/* set booster voltage to 5.0V */
	regmap_update_bits(info->chip->battery_regmap, PM88X_BOOST_CFG1,
			PM88X_OTG_BST_VSET_MASK, PM88X_OTG_BST_VSET(5000));

	/* clear OTG errors */
	pm88x_vbus_check_errors(info);

	/* set id gpadc low/upp threshold and enable it */
	switch (info->id_gpadc) {
	case PM88X_GPADC0:
		low_th = PM88X_GPADC0_LOW_TH;
		upp_th = PM88X_GPADC0_UPP_TH;
		en = PM88X_GPADC0_MEAS_EN;
		break;
	case PM88X_GPADC1:
		low_th = PM88X_GPADC1_LOW_TH;
		upp_th = PM88X_GPADC1_UPP_TH;
		en = PM88X_GPADC1_MEAS_EN;
		break;
	case PM88X_GPADC2:
		low_th = PM88X_GPADC2_LOW_TH;
		upp_th = PM88X_GPADC2_UPP_TH;
		en = PM88X_GPADC2_MEAS_EN;
		break;
	case PM88X_GPADC3:
		low_th = PM88X_GPADC3_LOW_TH;
		upp_th = PM88X_GPADC3_UPP_TH;
		en = PM88X_GPADC3_MEAS_EN;
		break;
	default:
		return;
	}

	/* set the threshold for GPADC to prepare for interrupt */
	regmap_write(info->chip->gpadc_regmap, low_th, OTG_IDPIN_TH >> 4);
	regmap_write(info->chip->gpadc_regmap, upp_th, 0xff);

	regmap_update_bits(info->chip->gpadc_regmap, PM88X_GPADC_CONFIG2, en, en);
}

static int pm88x_vbus_dt_init(struct device_node *np, struct pm88x_vbus_info *usb)
{
	return of_property_read_u32(np, "gpadc-number", &usb->id_gpadc);
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
			/* 1. base page 0x1f.0 = 1 --> unlock test page */
			regmap_write(info->chip->base_regmap, 0x1f, 0x1);
			/* 2. test page 0x90.[4:0] = 0, reset trimming to mid point 0 */
			regmap_update_bits(info->chip->test_regmap, 0x90, 0x1f << 0, 0);
			/* 3. base page 0x1f.0 = 0 --> lock the test page */
			regmap_write(info->chip->base_regmap, 0x1f, 0x0);
		}
		break;
	default:
		break;
	}
}

static int pm88x_vbus_probe(struct platform_device *pdev)
{
	struct pm88x_chip *chip = dev_get_drvdata(pdev->dev.parent);
	struct pm88x_vbus_info *usb;
	struct device_node *node = pdev->dev.of_node;
	int ret, current_range;

	/* vbus_info global variable used by get/set_vbus */
	vbus_info = usb = devm_kzalloc(&pdev->dev,
			   sizeof(struct pm88x_vbus_info), GFP_KERNEL);
	if (!usb)
		return -ENOMEM;

	ret = pm88x_vbus_dt_init(node, usb);
	if (ret < 0)
		usb->id_gpadc = PM88X_NO_GPADC;

	usb->chip = chip;

	current_range = get_current_range(chip);
	if (current_range < 0) {
		dev_err(chip->dev, "what happened to vbus?\n");
		return -EINVAL;
	}

	/* set new range */
	config_vbus_threshold(chip, current_range);
	/* do it before enable interrupt */
	pm88x_vbus_fixup(usb);

	usb->vbus_irq = platform_get_irq(pdev, 0);
	if (usb->vbus_irq < 0) {
		dev_err(&pdev->dev, "failed to get vbus irq\n");
		ret = -ENXIO;
		goto out;
	}

	INIT_DELAYED_WORK(&usb->pxa_notify, pm88x_pxa_notify);

	ret = devm_request_threaded_irq(&pdev->dev, usb->vbus_irq, NULL,
					pm88x_vbus_handler,
					IRQF_ONESHOT | IRQF_NO_SUSPEND,
					"vbus detect", usb);
	if (ret) {
		dev_info(&pdev->dev,
			"cannot request irq for VBUS, return\n");
		goto out;
	}

	if (usb->id_gpadc != PM88X_NO_GPADC) {
		pm88x_vbus_config(usb);

		usb->id_irq = platform_get_irq(pdev, usb->id_gpadc + 1);
		if (usb->id_irq < 0) {
			dev_err(&pdev->dev, "failed to get idpin irq\n");
			ret = -ENXIO;
			goto out;
		}

		ret = devm_request_threaded_irq(&pdev->dev, usb->id_irq, NULL,
						pm88x_id_handler,
						IRQF_ONESHOT | IRQF_NO_SUSPEND,
						"id detect", usb);
		if (ret) {
			dev_info(&pdev->dev,
				"cannot request irq for idpin, return\n");
			goto out;
		}
	}

	platform_set_drvdata(pdev, usb);
	device_init_wakeup(&pdev->dev, 1);

	pxa_usb_set_extern_call(PXA_USB_DEV_OTG, vbus, set_vbus,
				pm88x_set_vbus);
	pxa_usb_set_extern_call(PXA_USB_DEV_OTG, vbus, get_vbus,
				pm88x_get_vbus);
	if (usb->id_gpadc != PM88X_NO_GPADC) {
		pxa_usb_set_extern_call(PXA_USB_DEV_OTG, idpin, get_idpin,
					pm88x_read_id_val);
		pxa_usb_set_extern_call(PXA_USB_DEV_OTG, idpin, init,
					pm88x_init_id);
	}

	return 0;

out:
	return ret;
}

static int pm88x_vbus_remove(struct platform_device *pdev)
{
	platform_set_drvdata(pdev, NULL);

	return 0;
}

static const struct of_device_id pm88x_vbus_dt_match[] = {
	{ .compatible = "marvell,88pm88x-vbus", },
	{ },
};
MODULE_DEVICE_TABLE(of, pm88x_vbus_dt_match);

static struct platform_driver pm88x_vbus_driver = {
	.driver		= {
		.name	= "88pm88x-vbus",
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(pm88x_vbus_dt_match),
	},
	.probe		= pm88x_vbus_probe,
	.remove		= pm88x_vbus_remove,
};

static int pm88x_vbus_init(void)
{
	return platform_driver_register(&pm88x_vbus_driver);
}
module_init(pm88x_vbus_init);

static void pm88x_vbus_exit(void)
{
	platform_driver_unregister(&pm88x_vbus_driver);
}
module_exit(pm88x_vbus_exit);

MODULE_DESCRIPTION("VBUS driver for Marvell Semiconductor 88PM88X");
MODULE_AUTHOR("Shay Pathov <shayp@marvell.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:88pm88x-vbus");
