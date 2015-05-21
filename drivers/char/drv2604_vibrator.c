/*
 *    Vibrator driver for TI DRV2604 vibrator driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/mfd/88pm80x.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/regulator/machine.h>

#include "../staging/android/timed_output.h"

#define DRV2604_NAME "drv2604-vibrator"

/* prints wrapper for better debug */
#define VIB_ERR_MSG(fmt, ...) \
	pr_err(DRV2604_NAME ": %s(%d): " fmt, __func__, __LINE__ , ##__VA_ARGS__)
#define VIB_INFO_MSG(fmt, ...) \
	pr_info(DRV2604_NAME ": %s(%d): " fmt, __func__, __LINE__ , ##__VA_ARGS__)
#define VIB_DBG_MSG(fmt, ...) \
	pr_debug(DRV2604_NAME ": %s(%d): " fmt, __func__, __LINE__ , ##__VA_ARGS__)

/* DRV2604 registers */
#define DRV2604_STATUS				0x00
#define DRV2604_MODE				0x01
#define DRV2604_RTP				0x02
#define DRV2604_WAVEFORMSEQ1			0x04
#define DRV2604_WAVEFORMSEQ2			0x05
#define DRV2604_GO				0x0C
#define DRV2604_ODT				0x0D
#define DRV2604_SPT				0x0E
#define DRV2604_SNT				0x0F
#define DRV2604_BRT				0x10
#define DRV2604_RATED_VOLTAGE			0x16
#define DRV2604_OVERDRIVE_CLAMP_VOLTAGE	0x17
#define DRV2604_FBCTRL				0x1A
#define DRV2604_RAM_ADDR_UP_BYTE		0xFD
#define DRV2604_RAM_ADDR_LOW_BYTE		0xFE
#define DRV2604_RAM_DATA			0xFF

/*
 * Registers Bits definitions
 */

/* STATUS */
#define STATUS_DIAG_RESULT	BIT(3)

/* MODE */
#define MODE_TYPE_INT_TRIG		0x0
#define MODE_TYPE_EXT_LEVEL_TRIG	0x2
#define MODE_TYPE_AUTOCAL		0x7
#define MODE_SET(x)			((x) & 0x7)
#define MODE_STANDBY			BIT(6)
#define MODE_INIT_MASK			0x0

/* GO */
#define GO_CMD		(0x1)
#define STOP_CMD	(0x0)

/* RATED_VOLTAGE */
#define LRA_RV_3p0	0x7D
#define ERM_RV_3p0	0x8D
#define ERM_RV_2p6	0x79

/* OVERDRIVE_CLAMP_VOLTAGE */
#define LRA_ODV_3p6	0xA4
#define ERM_ODV_3p6	0xBA

/* FBCTRL */
#define FBCTRL_BEMF_GAIN(x)		((x) & 0x3)
#define FBCTRL_LOOP_RESPONSE(x)	(((x) & 0x3) << 2)
#define FBCTRL_BRAKE_FACTOR(x)		(((x) & 0x7) << 4)
#define FBCTRL_N_ERM_LRA(x)		(((x) & 0x1) << 7)
#define DEFAULT_BEMF_GAIN		0x0
#define DEFAULT_LOOP_RESPONSE		0x1
#define DEFAULT_BRAKE_FACTOR		0x2
#define SET_ERM			0x0
#define SET_LRA			0x1

/* WAVEFORMSEQ */
#define WAVEFORMSEQ_TERMINATE	0

/* definitions */
#define VIBRA_OFF_VALUE		0
#define VIBRA_ON_VALUE			1
#define LDO_VOLTAGE_3p3V		3300000
#define DRV2604_DRIVE_TIME_USEC_DEFAULT		4800
#define DRV2604_CURRENT_DISSIPATION_TIME_USEC_DEFAULT	75
#define DRV2604_BLANKING_TIME_USEC_DEFAULT		75


const unsigned char ram_table_header[] = {
0x00,		/* RAM Library Revision Byte (to track library revisions) */
0x01, 0x00, 0xE2,	/* Waveform #1 Continuous Buzz */
0x01, 0x04, 0xE2	/* Waveform #2 Continuous Buzz */
};

const unsigned char ram_table_data[] = {
0x3F, 0xFF,		/* Test Continuous Buzz */
0x3F, 0xFF		/* Test Continuous Buzz */
};

struct drv2604_vibrator_info {
	int (*trigger)(struct drv2604_vibrator_info *info, int on);
	struct regmap *regmap;
	struct timed_output_dev vibrator_timed_dev;
	struct timer_list vibrate_timer;
	struct work_struct vibrator_off_work;
	struct mutex vib_mutex;
	struct regulator *vib_regulator;
	int trig_gpio;
	unsigned char (*calc_rated_voltage)(struct drv2604_vibrator_info *info);
	unsigned char (*calc_od_clamp_voltage)(
				struct drv2604_vibrator_info *info);
	unsigned int average_vol_mv;
	unsigned int average_od_vol_mv;
	unsigned int actuator_type;
	unsigned int brake_factor;
	unsigned int loop_response;
	unsigned int bemf_gain;
	unsigned int drive_time_usec;
	unsigned int current_dis_time_usec;
	unsigned int blanking_time_usec;
	int enable;
	int probe_called;
	unsigned long start_cal_time;
};
static struct drv2604_vibrator_info drv2604_info;

static int drv2604_i2c_trigger(struct drv2604_vibrator_info *info, int on)
{
	int ret;

	if (on == VIBRA_OFF_VALUE) {
		/* turn off actuator */
		ret = regmap_write(info->regmap, DRV2604_GO, STOP_CMD);
		if (ret) {
			VIB_ERR_MSG("regmap write failed\n");
			mutex_unlock(&info->vib_mutex);
			return -1;
		}
	} else if (on == VIBRA_ON_VALUE) {
		/* turn on actuator */
		ret = regmap_write(info->regmap, DRV2604_GO, GO_CMD);
		if (ret) {
			VIB_ERR_MSG("regmap write failed\n");
			mutex_unlock(&info->vib_mutex);
			return -1;
		}
	} else {
		VIB_ERR_MSG("Illegal vibrator trigger command\n");
		return -1;
	}

	return 0;
}

static int drv2604_gpio_trigger(struct drv2604_vibrator_info *info, int on)
{
	if (on == VIBRA_OFF_VALUE) {
		gpio_direction_output(info->trig_gpio, 0);
	} else if (on == VIBRA_ON_VALUE) {
		gpio_direction_output(info->trig_gpio, 1);
	} else {
		VIB_ERR_MSG("Illegal vibrator trigger command\n");
		return -1;
	}

	return 0;
}

static int drv2604_control_vibrator(struct drv2604_vibrator_info *info,
				unsigned char value)
{
	mutex_lock(&info->vib_mutex);
	if (info->enable == value) {
		mutex_unlock(&info->vib_mutex);
		return 0;
	}

	if (info->trigger(info, value))
		return -1;

	mutex_unlock(&info->vib_mutex);
	info->enable = value;

	return 0;
}

static void vibrator_off_worker(struct work_struct *work)
{
	struct drv2604_vibrator_info *info;

	info = container_of(work, struct drv2604_vibrator_info,
				vibrator_off_work);
	drv2604_control_vibrator(info, VIBRA_OFF_VALUE);
}

static void on_vibrate_timer_expired(unsigned long x)
{
	struct drv2604_vibrator_info *info;
	info = (struct drv2604_vibrator_info *)x;
	schedule_work(&info->vibrator_off_work);
}

static void vibrator_enable_set_timeout(struct timed_output_dev *sdev,
					int timeout)
{
	struct drv2604_vibrator_info *info;

	info = container_of(sdev, struct drv2604_vibrator_info,
				vibrator_timed_dev);
	VIB_DBG_MSG("Vibrator: Set duration: %dms\n", timeout);

	if (timeout <= 0) {
		drv2604_control_vibrator(info, VIBRA_OFF_VALUE);
		del_timer(&info->vibrate_timer);
	} else {

		drv2604_control_vibrator(info, VIBRA_ON_VALUE);
		mod_timer(&info->vibrate_timer,
			  jiffies + msecs_to_jiffies(timeout));
	}

	return;
}

static int vibrator_get_remaining_time(struct timed_output_dev *sdev)
{
	struct drv2604_vibrator_info *info;
	int rettime;

	info = container_of(sdev, struct drv2604_vibrator_info,
		vibrator_timed_dev);
	rettime = jiffies_to_msecs(jiffies - info->vibrate_timer.expires);
	VIB_DBG_MSG("Vibrator: Current duration: %dms\n", rettime);
	return rettime;
}

static int drv2604_write_waveform_to_ram(struct regmap *regmap)
{
	int ret;

	/* Load header into RAM */
	ret = regmap_write(regmap, DRV2604_RAM_ADDR_UP_BYTE, 0x0);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}
	ret = regmap_write(regmap, DRV2604_RAM_ADDR_LOW_BYTE, 0x0);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}
	ret = regmap_bulk_write(regmap, DRV2604_RAM_DATA,
			(void *)ram_table_header, ARRAY_SIZE(ram_table_header));
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* Load data into RAM */
	ret = regmap_write(regmap, DRV2604_RAM_ADDR_UP_BYTE, 0x01);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}
	ret = regmap_write(regmap, DRV2604_RAM_ADDR_LOW_BYTE, 0x0);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}
	ret = regmap_bulk_write(regmap, DRV2604_RAM_DATA,
			(void *)ram_table_data, ARRAY_SIZE(ram_table_data));
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}
end:
	return ret;
}

static int drv2604_vibratior_init(struct drv2604_vibrator_info *info)
{
	int ret;

	/* exit stand-by mode */
	ret = regmap_write(info->regmap, DRV2604_MODE, MODE_INIT_MASK);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* Set RTP register to zero, prevent playback */
	ret = regmap_write(info->regmap, DRV2604_RTP, 0x0);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* Set Library Overdrive time to zero */
	ret = regmap_write(info->regmap, DRV2604_ODT, 0x0);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* Set Library Sustain positive time */
	ret = regmap_write(info->regmap, DRV2604_SPT, 0x0);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* Set Library Sustain negative time */
	ret = regmap_write(info->regmap, DRV2604_SNT, 0x0);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* Set Library Brake Time */
	ret = regmap_write(info->regmap, DRV2604_BRT, 0x0);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}
end:
	return ret;
}

static unsigned char drv2604_calc_erm_rated_voltage(
					struct drv2604_vibrator_info *info)
{
	/*
	 * the formula to obtain the rated voltage from averge voltage is:
	 * RatedVoltage = (Vaverage[mV] * 255) / 5440[mV]
	 */
	return (info->average_vol_mv * 255) / 5440;
}

static unsigned char drv2604_calc_lra_rated_voltage(
					struct drv2604_vibrator_info *info)
{
	/*
	 * the formula to obtain the rated voltage from averge (RMS) voltage is:
	 * RatedVoltage = (Vabs[mV] * 255) / 5280[mV]
	 */
	return (info->average_vol_mv * 255) / 5280;
}

static unsigned char drv2604_calc_erm_od_clamp_voltage(
					struct drv2604_vibrator_info *info)
{
	unsigned int vpeak;
	/*
	 * the formula to obtain the overdrive clamp voltage from averge
	 * clamp vaoltge (Vav) is:
	 * OverdriveClampVoltage = Vpeak[mV] * 255 / 5440[mV]
	 * where
	 * Vpeak[mV] =
	 * (Vav[mV] * (DriveTime[usec] + IDissTime[usec] + BlankingTime[usec]))
	 *	/
	 * (DriveTime[usec] - 300[usec])
	 */
	vpeak = (info->average_od_vol_mv *
			(info->drive_time_usec +
				info->current_dis_time_usec +
				info->blanking_time_usec))
			/ (info->drive_time_usec - 300);

	return (vpeak * 255) / 5440;
}

static unsigned char drv2604_calc_lra_od_clamp_voltage(
					struct drv2604_vibrator_info *info)
{
	/*
	 * the formula to obtain the overdrive clamp voltage from averge
	 * clamp vaoltge (Vav) is:
	 * OverdriveClampVoltage = Vod[mV] * 255 / 5600[mV]
	 */
	return (info->average_od_vol_mv * 255) / 5600;
}

static int drv2604_auto_calibration_trigger(struct drv2604_vibrator_info *info)
{
	int ret;

	/*
	 * Set DRV260x Control Registers
	 * =============================
	 */

	/* set rated-voltage register */
	ret = regmap_write(info->regmap,
				DRV2604_RATED_VOLTAGE,
				info->calc_rated_voltage(info));
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* set overdrive-clamp-voltage register */
	ret = regmap_write(info->regmap,
				DRV2604_OVERDRIVE_CLAMP_VOLTAGE,
				info->calc_od_clamp_voltage(info));
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* set feedback control register */
	ret = regmap_write(info->regmap, DRV2604_FBCTRL,
				FBCTRL_N_ERM_LRA(info->actuator_type) |
				FBCTRL_BRAKE_FACTOR(info->brake_factor) |
				FBCTRL_LOOP_RESPONSE(info->loop_response) |
				FBCTRL_BEMF_GAIN(info->bemf_gain));
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/*
	 * Run Auto-Calibration
	 * ====================
	 */

	/* exit stand-by mode and set to auto calibration mode */
	ret = regmap_write(info->regmap, DRV2604_MODE,
					MODE_SET(MODE_TYPE_AUTOCAL));
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* set the GO bit */
	ret = regmap_write(info->regmap, DRV2604_GO, GO_CMD);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		goto end;
	}

	/* store start of calibration time */
	info->start_cal_time = jiffies;
end:
	return ret;
}

static int drv2604_auto_calibration_test_result(
				struct drv2604_vibrator_info *info)
{
	int ret;
	unsigned int cal_time_msec, val;

	/* check if calibration process ended */
	ret = regmap_read(info->regmap, DRV2604_GO, &val);
	/* if read error occures- try in next iteration */
	if (ret) {
		VIB_ERR_MSG("regmap read failed\n");
		return ret;
	}

	if (val) {
		cal_time_msec =
			jiffies_to_msecs(jiffies - info->start_cal_time);
		if (cal_time_msec > 1000) {
			VIB_ERR_MSG("auto clibration timeout\n");
			return -ETIME;
		}
		return -EPROBE_DEFER;
	}

	/* check calibration results */
	ret = regmap_read(info->regmap, DRV2604_STATUS, &val);
	if (ret) {
		VIB_ERR_MSG("regmap read failed\n");
		return ret;
	}
	if (val & STATUS_DIAG_RESULT)
		VIB_INFO_MSG("calibration failed, work uncalibrated\n");

	return 0;
}

static int drv2604_enable_recorded_sequence(struct regmap *regmap)
{
	int ret;

	/* populate RAM with waveforms */
	ret = drv2604_write_waveform_to_ram(regmap);
	if (ret) {
		VIB_ERR_MSG("failed to write waveform to RAM\n");
		return ret;
	}

	/* set the desired sequence to be played */
	ret = regmap_write(regmap, DRV2604_WAVEFORMSEQ1, 0x1);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		return ret;
	}

	/* Insert termination character in sequence register 2 */
	ret = regmap_write(regmap, DRV2604_WAVEFORMSEQ2,
							WAVEFORMSEQ_TERMINATE);
	if (ret) {
		VIB_ERR_MSG("regmap write failed\n");
		return ret;
	}

	return 0;
}

static int drv2604_set_internal_trigger(struct drv2604_vibrator_info *info)
{
	int ret;

	/* slect internal trigger */
	if (info->trig_gpio < 0) {
		ret = regmap_write(info->regmap, DRV2604_MODE,
					MODE_SET(MODE_TYPE_INT_TRIG));
		if (ret) {
			VIB_ERR_MSG("regmap write failed\n");
			return ret;
		}
	} else {
		ret = regmap_write(info->regmap, DRV2604_MODE,
					MODE_SET(MODE_TYPE_EXT_LEVEL_TRIG));
		if (ret) {
			VIB_ERR_MSG("regmap write failed\n");
			return ret;
		}
	}

	return 0;
}

static int drv2604_trigger_method(struct drv2604_vibrator_info *info)
{
	int ret;
	if (info->trig_gpio < 0) {
		/* default trigger method is I2C */
		info->trigger = drv2604_i2c_trigger;
		return 0;
	}

	ret = gpio_request(info->trig_gpio, "vibrator trigger");
	if (ret) {
		VIB_ERR_MSG("gpio %d request failed\n", info->trig_gpio);
		return ret;
	}

	info->trigger = drv2604_gpio_trigger;
	return 0;
}

#ifdef CONFIG_OF
static void of_vibrator_probe_erm(struct device_node *np,
				struct drv2604_vibrator_info *info)
{
	if (of_property_read_u32(np, "drive-time-usec",
					&info->drive_time_usec)) {
		VIB_INFO_MSG("failed to get drive-time-usec property, use default\n");
		info->drive_time_usec = DRV2604_DRIVE_TIME_USEC_DEFAULT;
	}

	if (of_property_read_u32(np, "current-dissipation-time-usec",
					&info->current_dis_time_usec)) {
		VIB_INFO_MSG("failed to get current-dissipation-time-usec, use default\n");
		info->current_dis_time_usec =
				DRV2604_CURRENT_DISSIPATION_TIME_USEC_DEFAULT;
	}

	if (of_property_read_u32(np, "blanking-time-usec",
					&info->blanking_time_usec)) {
		VIB_INFO_MSG("failed to get blanking-time-usec, use default\n");
		info->blanking_time_usec = DRV2604_BLANKING_TIME_USEC_DEFAULT;
	}
}

static int of_vibrator_probe(struct device_node *np,
				struct drv2604_vibrator_info *info)
{
	int ret;

	info->trig_gpio =
		of_get_named_gpio(np, "trig_gpio", 0);
	if (info->trig_gpio < 0)
		VIB_INFO_MSG("No GPIO trigger defined, work with I2C writes\n");

	if (of_property_read_u32(np, "actuator-type",
					&info->actuator_type)) {
		VIB_INFO_MSG("failed to get actuator-type, use default\n");
		info->actuator_type = SET_ERM;
	}

	ret = of_property_read_u32(np, "average-voltage-mv",
					&info->average_vol_mv);
	if (ret) {
		VIB_ERR_MSG("failed to get average-voltage-mv property\n");
		return ret;
	}

	ret = of_property_read_u32(np, "average-overdrive-voltage-mv",
					&info->average_od_vol_mv);
	if (ret) {
		VIB_ERR_MSG("failed to get average-overdrive-voltage-mv property\n");
		return ret;
	}

	if (of_property_read_u32(np, "bemf-gain",
					&info->bemf_gain)) {
		VIB_INFO_MSG("failed to get bemf-gain, use default\n");
		info->bemf_gain = DEFAULT_BEMF_GAIN;
	}

	if (of_property_read_u32(np, "loop-response",
					&info->loop_response)) {
		VIB_INFO_MSG("failed to get loop-response, use default\n");
		info->loop_response = DEFAULT_LOOP_RESPONSE;
	}

	if (of_property_read_u32(np, "brake-factor",
					&info->brake_factor)) {
		VIB_INFO_MSG("failed to get brake-factor, use default\n");
		info->brake_factor = DEFAULT_BRAKE_FACTOR;
	}

	if (info->actuator_type == SET_ERM) {
		of_vibrator_probe_erm(np, info);
		info->calc_rated_voltage = drv2604_calc_erm_rated_voltage;
		info->calc_od_clamp_voltage = drv2604_calc_erm_od_clamp_voltage;
	} else {
		info->calc_rated_voltage = drv2604_calc_lra_rated_voltage;
		info->calc_od_clamp_voltage = drv2604_calc_lra_od_clamp_voltage;
	}


	return 0;
}
#else
static int of_vibrator_probe(struct device_node *np,
				struct drv2604_vibrator_info *info)
{
	return 0;
}
#endif

static const struct regmap_config drv2604_regmap = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = 0xFF,
};

static int vibrator_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	int ret = 0;
	struct drv2604_vibrator_info *info;

	info = &drv2604_info;

	/* allocate register map */
	info->regmap = devm_regmap_init_i2c(client, &drv2604_regmap);
	if (IS_ERR(info->regmap)) {
		ret = PTR_ERR(info->regmap);
		VIB_ERR_MSG("Failed to allocate register map: %d\n", ret);
		goto err;
	}

	if (info->probe_called) {
		/* check auto calibration results */
		ret = drv2604_auto_calibration_test_result(info);
		if (ret)
			goto err_unregister;

		/* work with recorded RAM sequence */
		ret = drv2604_enable_recorded_sequence(info->regmap);
		if (ret)
			goto err_unregister;

		/* set internal trigger */
		ret = drv2604_set_internal_trigger(info);
		if (ret == -EPROBE_DEFER)
			return ret;
		else if (ret)
			goto err_unregister;

		VIB_ERR_MSG("Probe ended successfully\n");
		return 0;
	}
	info->probe_called = 1;

	/* We should be able to read and write byte data */
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		VIB_ERR_MSG("I2C_FUNC_I2C not supported\n");
		ret = -ENOTSUPP;
		goto err;
	}

	/* get of parameters */
	ret = of_vibrator_probe(client->dev.of_node, info);
	if (ret)
		goto err;

	/* handle vibrator trigger method */
	ret = drv2604_trigger_method(info);
	if (ret)
		goto err;

	/* Setup timed_output obj */
	info->vibrator_timed_dev.name = "vibrator";
	info->vibrator_timed_dev.enable = vibrator_enable_set_timeout;
	info->vibrator_timed_dev.get_time = vibrator_get_remaining_time;

	/* Vibrator dev register in /sys/class/timed_output/ */
	ret = timed_output_dev_register(&info->vibrator_timed_dev);
	if (ret < 0) {
		VIB_ERR_MSG("Vibrator: timed_output dev registration failure\n");
		goto free_gpio;
	}

	INIT_WORK(&info->vibrator_off_work, vibrator_off_worker);
	mutex_init(&info->vib_mutex);
	info->enable = 0;

	init_timer(&info->vibrate_timer);
	info->vibrate_timer.function = on_vibrate_timer_expired;
	info->vibrate_timer.data = (unsigned long)info;

	i2c_set_clientdata(client, info);

	info->vib_regulator = regulator_get(&client->dev, "vibrator");
	if (IS_ERR(info->vib_regulator)) {
		VIB_ERR_MSG("get vibrator ldo fail!\n");
		ret = -1;
		goto err_unregister;
	}

	regulator_set_voltage(info->vib_regulator, LDO_VOLTAGE_3p3V,
							LDO_VOLTAGE_3p3V);

	ret = regulator_enable(info->vib_regulator);
	if (ret)
		VIB_ERR_MSG("enable vibrator ldo fail!\n");

	regulator_put(info->vib_regulator);

	/* perform initialization sequence for the DRV2604 */
	ret = drv2604_vibratior_init(info);
	if (ret)
		goto err_unregister;

	/*
	 * since vibrator calibration take around few 100msecs we would like
	 * to let HW perform the calibration in background to prevent long
	 * boot time.
	 * in order to accomplish this after triggering auto-calibration the
	 * driver requests deferred probe and check calibration results in
	 * subsequent probe call.
	 */
	ret = drv2604_auto_calibration_trigger(info);
	if (ret)
		goto err_unregister;

	return -EPROBE_DEFER;
err_unregister:
	timed_output_dev_unregister(&info->vibrator_timed_dev);
free_gpio:
	if (info->trig_gpio >= 0)
		gpio_free(info->trig_gpio);
err:
	return ret;
}

static int vibrator_remove(struct i2c_client *client)
{
	struct drv2604_vibrator_info *info = i2c_get_clientdata(client);

	timed_output_dev_unregister(&info->vibrator_timed_dev);
	if (info->trig_gpio >= 0)
		gpio_free(info->trig_gpio);
	return 0;
}

static const struct i2c_device_id drv2604_id[] = {
	{DRV2604_NAME, 0},
	{}
};

static struct of_device_id drv2604_dt_ids[] = {
	{.compatible = "ti,drv2604-vibrator",},
	{}
};

/* This is the I2C driver that will be inserted */
static struct i2c_driver vibrator_driver = {
	.driver = {
		   .name = DRV2604_NAME,
		   .of_match_table = of_match_ptr(drv2604_dt_ids),
		   },
	.id_table = drv2604_id,
	.probe = vibrator_probe,
	.remove = vibrator_remove,
};

static int __init vibrator_init(void)
{
	int ret;

	ret = i2c_add_driver(&vibrator_driver);
	if (ret)
		VIB_ERR_MSG("i2c_add_driver failed, error %d\n", ret);

	return ret;
}

static void __exit vibrator_exit(void)
{
	i2c_del_driver(&vibrator_driver);
}

module_init(vibrator_init);
module_exit(vibrator_exit);

MODULE_DESCRIPTION("Android Vibrator driver");
MODULE_LICENSE("GPL");
