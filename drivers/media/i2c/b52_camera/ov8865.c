/* Marvell ISP OV8865 Driver
 *
 * Copyright (C) 2009-2014 Marvell International Ltd.
 *
 * Based on mt9v011 -Micron 1/4-Inch VGA Digital Image OV8865
 *
 * Copyright (c) 2009 Mauro Carvalho Chehab (mchehab@redhat.com)
 * This code is placed under the terms of the GNU General Public License v2
 */

#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/videodev2.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/gpio.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/fixed.h>

#include <asm/div64.h>
#include <media/v4l2-device.h>
#include <media/v4l2-subdev.h>
#include <media/v4l2-ctrls.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <uapi/media/b52_api.h>

#include "ov8865.h"

static void OV8865_write_i2c(struct b52_sensor *sensor, u16 reg, u8 val)
{
	b52_sensor_call(sensor, i2c_write, reg, val, 1);
}
static int OV8865_read_i2c(struct b52_sensor *sensor, u16 reg)
{
	int temp1;
	b52_sensor_call(sensor, i2c_read, reg, &temp1, 1);
	return temp1;
}

static int OV8865_get_mipiclock(struct v4l2_subdev *sd, u32 *rate, u32 mclk)
{
	int temp1, temp2;
	int Pll1_predivp, Pll1_prediv2x, Pll1_mult, Pll1_divm;
	int Pll1_predivp_map[] = {1, 2};
	int Pll1_prediv2x_map[] = {2, 3, 4, 5, 6, 8, 12, 16};

	struct b52_sensor *sensor = to_b52_sensor(sd);
	b52_sensor_call(sensor, i2c_read, 0x030a, &temp1, 1);
	temp2 = (temp1) & 0x01;
	Pll1_predivp = Pll1_predivp_map[temp2];
	b52_sensor_call(sensor, i2c_read, 0x0300, &temp1, 1);
	temp2 = temp1 & 0x07;
	Pll1_prediv2x = Pll1_prediv2x_map[temp2];
	b52_sensor_call(sensor, i2c_read, 0x0301, &temp1, 1);
	temp2 = temp1 & 0x03;
	b52_sensor_call(sensor, i2c_read, 0x0302, &temp1, 1);
	Pll1_mult = (temp2<<8) + temp1;
	b52_sensor_call(sensor, i2c_read, 0x0303, &temp1, 1);
	temp2 = temp1 & 0x0f;
	Pll1_divm = temp2 + 1;
	*rate = mclk / Pll1_predivp * 2 / Pll1_prediv2x * Pll1_mult / Pll1_divm;


	pr_err("OV8865_get_mipiclock %d", *rate);

	return 0;
}

static int OV8865_get_dphy_desc(struct v4l2_subdev *sd,
			struct csi_dphy_desc *dphy_desc, u32 mclk)
{
	OV8865_get_mipiclock(sd, &dphy_desc->clk_freq, mclk);
	dphy_desc->hs_prepare = 71;
	dphy_desc->hs_zero = 100;

	return 0;
}

static int OV8865_get_pixelclock(struct v4l2_subdev *sd, u32 *rate, u32 mclk)
{
	int temp1, temp2;
	int Pll2_prediv0, Pll2_prediv2x, Pll2_multiplier, Pll2_divs;
	int Sys_divider2x, Sys_prediv, Sclk_pdiv;
	int Pll2_prediv0_map[] = {1, 2};
	int Pll2_prediv2x_map[] = {2, 3, 4, 5, 6, 8, 12, 16};
	int Sys_divider2x_map[] = {2, 3, 4, 5, 6, 7, 8, 10};
	int Sys_prediv_map[] = {1, 2, 4, 1};
int Sclk_pdiv_map[] = {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	struct b52_sensor *sensor = to_b52_sensor(sd);

	b52_sensor_call(sensor, i2c_read, 0x0312, &temp1, 1);
	temp2 = (temp1>>4) & 0x01;
	Pll2_prediv0 = Pll2_prediv0_map[temp2];
	b52_sensor_call(sensor, i2c_read, 0x030b, &temp1, 1);
	temp2 = temp1 & 0x07;
	Pll2_prediv2x = Pll2_prediv2x_map[temp2];
	b52_sensor_call(sensor, i2c_read, 0x030c, &temp1, 1);
	b52_sensor_call(sensor, i2c_read, 0x030d, &temp2, 1);

	Pll2_multiplier = (temp1<<8) + temp2;
	if (!Pll2_multiplier)
		Pll2_multiplier = 1;

	b52_sensor_call(sensor, i2c_read, 0x030f, &temp1, 1);
	temp2 = temp1 & 0x0f;
	Pll2_divs = temp2 + 1;
	b52_sensor_call(sensor, i2c_read, 0x030e, &temp1, 1);
	temp2 = temp1 & 0x07;
	Sys_divider2x = Sys_divider2x_map[temp2];
	b52_sensor_call(sensor, i2c_read, 0x3106, &temp1, 1);
	temp2 = (temp1>>4) & 0x0f;
	Sclk_pdiv = Sclk_pdiv_map[temp2];
	temp2 = (temp1>>2) & 0x03;
	Sys_prediv = Sys_prediv_map[temp2];

	*rate = mclk * 2 / Pll2_prediv0 / Pll2_prediv2x * Pll2_multiplier /
		Pll2_divs * 2 / Sys_divider2x /	Sys_prediv / Sclk_pdiv;
	/*
	* ov8865 process 2 pixels in each pixelclock, double the
	* pixelclock and hts value to fix the exposure time error issue
	*/
	*rate = *rate * 2;

	pr_err("OV8865_get_pixelclock %d", *rate);

	return 0;
}

static int OV8865_read_OTP(struct b52_sensor *sensor,
			struct b52_sensor_otp *otp, u32 *flag, u8 *lenc)
{
	int otp_flag, otp_base, i;
	/*read OTP into buffer*/
	OV8865_write_i2c(sensor, 0x3d84, 0xC0);
	OV8865_write_i2c(sensor, 0x3d88, 0x70); /*OTP start address*/
	OV8865_write_i2c(sensor, 0x3d89, 0x10);
	OV8865_write_i2c(sensor, 0x3d8A, 0x70); /*OTP end address*/
	OV8865_write_i2c(sensor, 0x3d8B, 0xf4);
	OV8865_write_i2c(sensor, 0x3d81, 0x01); /*load otp into buffer*/
	usleep_range(10000, 10010); /*10ms*/

	/*OTP into*/
	otp_flag = OV8865_read_i2c(sensor, 0x7010);
	otp_base = 0;
	if ((otp_flag & 0xc0) == 0x40)
		otp_base = 0x7011;/*base address of info group 1*/
	else if ((otp_flag & 0x30) == 0x10)
		otp_base = 0x7016;/*base address of info group 2*/
	else if ((otp_flag & 0x0c) == 0x04)
		otp_base = 0x701b;/*base address of info group 3*/

	if (otp_base != 0) {
		*flag = 0x80; /*valid info in OTP*/ /*0xC0->0x80*/
		(*otp).module_id = OV8865_read_i2c(sensor, otp_base);
		(*otp).lens_id = OV8865_read_i2c(sensor, otp_base + 1);

	} else {
		*flag = 0x00; /*not info in OTP*/
		(*otp).module_id = 0;
		(*otp).lens_id = 0;
	}

	pr_err("OTP_INF OV8865:Module=0x%x, Lens=0x%x\n",
			(*otp).module_id, (*otp).lens_id);

#if 0
	/*OTP VCM Calibration*/
	otp_flag = OV8865_read_i2c(sensor, 0x7030);
	otp_base = 0;
	if ((otp_flag & 0xc0) == 0x40)
		otp_base = 0x7031; /*base address of VCM Calibration group 1*/
	else if ((otp_flag & 0x30) == 0x10)
		otp_base = 0x7034; /*base address of VCM Calibration group 2*/
	else if ((otp_flag & 0x0c) == 0x04)
		otp_base = 0x7037; /* base address of VCM Calibration group 3*/

	if (otp_base != 0) {
		*flag |= 0x20;
		temp = OV8865_read_i2c(sensor, otp_base + 2);
		(*otp).vcm_start = (OV8865_read_i2c(sensor, otp_base) << 2)
					 | ((temp>>6) & 0x03);
		(*otp).vcm_end = (OV8865_read_i2c(sensor, otp_base + 1) << 2)
					 | ((temp>>4) & 0x03);
		(*otp).vcm_dir = (temp >> 2) & 0x03;
	} else {
		(*otp).vcm_start = 0;
		(*otp).vcm_end = 0;
		(*otp).vcm_dir = 0;
	}
#endif
	/*OTP Lenc Calibration*/
	otp_flag = OV8865_read_i2c(sensor, 0x703a);/*0x7028*/
	otp_base = 0;
	if ((otp_flag & 0xc0) == 0x40)
		otp_base = 0x703b; /*base address of Lenc Calibration group 1*/
	else if ((otp_flag & 0x30) == 0x10)
		otp_base = 0x7079; /*base address of Lenc Calibration group 2*/
	else if ((otp_flag & 0x0c) == 0x04)
		otp_base = 0x70b7; /*base address of Lenc Calibration group 3*/


	if (otp_base != 0) {
		*flag |= 0x10;
		for (i = 0; i < 62; i++) {
			lenc[i] = OV8865_read_i2c(sensor, otp_base + i);
		}
	} else {
		for (i = 0; i < 62; i++)
			lenc[i] = 0;

	}
	/* Clear OTP data */
	for (i = 0x7010; i <= 0x70f4; i++)
		OV8865_write_i2c(sensor, i, 0x0);

	return *flag;
}

static int check_otp_info(struct b52_sensor *sensor)
{
	int flag, addr = 0x0;

	flag = OV8865_read_i2c(sensor, 0x7020);
	addr = 0;
	if ((flag & 0xc0) == 0x40)
		addr = 0x7021;/*base address of WB Calibration group 1*/
	else if ((flag & 0x30) == 0x10)
		addr = 0x7026;/*base address of WB Calibration group 2*/
	else if ((flag & 0x0c) == 0x04)
		addr = 0x702b;/*base address of WB Calibration group 3*/

	return addr;
}

static int read_otp_wb(struct b52_sensor *sensor, int addr,
				struct b52_sensor_otp *otp)
{
	int temp;

	temp = OV8865_read_i2c(sensor, addr + 4);
	otp->rg_ratio = (OV8865_read_i2c(sensor, addr)<<2)
					+ ((temp>>6) & 0x03);
	otp->bg_ratio = (OV8865_read_i2c(sensor, addr + 1)<<2)
					+ ((temp>>4) & 0x03);
	otp->user_data[0] = 0;
	otp->user_data[1] = 0;

	return 0;
}

static int OV8865_update_wb(struct b52_sensor *sensor,
			struct b52_sensor_otp *otp)
{
	int otp_addr;
	int r_gain, g_gain, b_gain, base_gain;
	int rg_typical_ratio, bg_typical_ratio;

	/*apply OTP WB Calibration*/

	otp_addr = check_otp_info(sensor);
	read_otp_wb(sensor, otp_addr, otp);

	if (otp->golden_rg_ratio && otp->golden_bg_ratio) {
		rg_typical_ratio = otp->golden_rg_ratio;
		bg_typical_ratio = otp->golden_bg_ratio;
	} else {
		rg_typical_ratio = DEFAULT_RG_TYPICAL_RATIO;
		bg_typical_ratio = DEFAULT_BG_TYPICAL_RATIO;
	}

		r_gain = (rg_typical_ratio * 1000) / otp->rg_ratio;
		b_gain = (bg_typical_ratio * 1000) / otp->bg_ratio;
		g_gain = 1000;

		/*find gain<1000*/
		if (r_gain < 1000 || b_gain < 1000) {
			if (r_gain < b_gain)
				base_gain = r_gain;
			else
				base_gain = b_gain;
		} else
			base_gain = g_gain;
		/*set min gain to 0x400*/
		r_gain = 0x400 * r_gain / base_gain;
		g_gain = 0x400 * g_gain / base_gain;
		b_gain = 0x400 * b_gain / base_gain;
		/*update sensor WB gain*/
		if (r_gain > 0x400) {
			OV8865_write_i2c(sensor, 0x5018, r_gain >> 6);
			OV8865_write_i2c(sensor, 0x5019, r_gain & 0x003f);
		}
		if (g_gain > 0x400) {
			OV8865_write_i2c(sensor, 0x501A, g_gain >> 6);
			OV8865_write_i2c(sensor, 0x501B, g_gain & 0x003f);
		}
		if (b_gain > 0x400) {
			OV8865_write_i2c(sensor, 0x501C, b_gain >> 6);
			OV8865_write_i2c(sensor, 0x501D, b_gain & 0x003f);
		}
	return 0;
}
static int OV8865_update_lenc(struct b52_sensor *sensor,
			struct b52_sensor_otp *otp, u32 *flag, u8 *lenc)
{
	int temp, i;
	if (*flag & 0x10) {
		temp = OV8865_read_i2c(sensor, 0x5000);
		temp = 0x80 | temp;
		OV8865_write_i2c(sensor, 0x5000, temp);
		for (i = 0; i < 62; i++)
			OV8865_write_i2c(sensor, 0x5800 + i, lenc[i]);
	}
	return *flag;
}

static void OV8865_otp_access_start(struct b52_sensor *sensor)
{
	/* need stream on sensor before read OTP data*/
	OV8865_write_i2c(sensor, 0x0100, 0x01);
	OV8865_write_i2c(sensor, 0x5002, 0x00);
	usleep_range(5000, 5010);
}

static void OV8865_otp_access_end(struct b52_sensor *sensor)
{
	OV8865_write_i2c(sensor, 0x5002, 0x08);
	OV8865_write_i2c(sensor, 0x0100, 0x00);
}

static int OV8865_read_data(struct v4l2_subdev *sd,
				struct b52_sensor_otp *otp)
{
	int i, len, otp_flag, otp_base, tmp_len = 0;
	int ret = 0;
	char *paddr = NULL;
	char *bank_grp = NULL;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!otp->user_otp) {
		pr_err("%s:user otp haven't init\n", __func__);
		return 0;
	}

	OV8865_otp_access_start(sensor);
	/*return current module name, not real module id get from OTP */
	len = otp->user_otp->module_data_len;
	if (len > 0) {
		bank_grp = devm_kzalloc(sd->dev, len, GFP_KERNEL);
		if (sensor->drvdata->module && sensor->drvdata->num_module > 0
			&& sensor->cur_mod_id >= 0
			&& sensor->cur_mod_id < sensor->drvdata->num_module
			&& sensor->drvdata->module[sensor->cur_mod_id].name) {
			for (i = 0; i < len; i++)
				bank_grp[i] =
				sensor->drvdata->module[sensor->cur_mod_id].name[i];
		} else {
			for (i = 0; i < len; i++)
				bank_grp[i] = 0;
		}

		paddr = otp->user_otp->module_data;
		if (copy_to_user(paddr, &bank_grp[0], len)) {
			ret = -EIO;
			goto err;
		}
		devm_kfree(sd->dev, bank_grp);
	}

	/* read vcm otp */
	len = otp->user_otp->vcm_otp_len;
	if (len > 0) {
		bank_grp = devm_kzalloc(sd->dev, len, GFP_KERNEL);
		/*load vcm OTP only */
		OV8865_write_i2c(sensor, 0x3d84, 0xC0);
		OV8865_write_i2c(sensor, 0x3d88, 0x70);/*VCM OTP start address*/
		OV8865_write_i2c(sensor, 0x3d89, 0x30);
		OV8865_write_i2c(sensor, 0x3d8A, 0x70);/*VCM OTP end address*/
		OV8865_write_i2c(sensor, 0x3d8B, 0x39);
		OV8865_write_i2c(sensor, 0x3d81, 0x01);/*load otp data*/
		usleep_range(5000, 5010);/*delay 10ms*/

		otp_base = 0;
		otp_flag = OV8865_read_i2c(sensor, 0x7030);

		if ((otp_flag & 0xc0) == 0x40)
			otp_base = 0x7031; /*group 1*/
		else if ((otp_flag & 0x30) == 0x10)
			otp_base = 0x7034; /*group 2*/
		else if ((otp_flag & 0x0c) == 0x04)
			otp_base = 0x7037; /*group 3*/

		if (otp_base != 0) {
			for (i = 0; i < len; i++)
				bank_grp[i] = OV8865_read_i2c(sensor, otp_base + i);
			pr_info("%s:got vcm OTP data: 0x%x,0x%x,0x%x\n",
				__func__, bank_grp[0], bank_grp[1], bank_grp[2]);
		} else {
			for (i = 0; i < len; i++)
				bank_grp[i] = 0;
		}
		/* Clear OTP data */
		for (i = 0x7030; i <= 0x7039; i++)
			OV8865_write_i2c(sensor, i, 0x0);
		paddr = (char *)otp->user_otp->otp_data + tmp_len;
		if (copy_to_user(paddr, &bank_grp[0], len)) {
			ret = -EIO;
			goto err;
		}
		tmp_len += len;
		devm_kfree(sd->dev, bank_grp);
	}

	/* read wb otp, return 0 */
	len = otp->user_otp->wb_otp_len;
	if (len > 0) {
		bank_grp = devm_kzalloc(sd->dev, len, GFP_KERNEL);
		for (i = 0; i < len; i++)
			bank_grp[i] = 0;
		paddr = (char *)otp->user_otp->otp_data + tmp_len;
		if (copy_to_user(paddr, &bank_grp[0], len)) {
			ret = -EIO;
			goto err;
		}
		tmp_len += len;
		devm_kfree(sd->dev, bank_grp);
	}

	/*read lsc otp, return 0 */
	len = otp->user_otp->lsc_otp_len;
	if (len > 0) {
		bank_grp = devm_kzalloc(sd->dev, len, GFP_KERNEL);
		for (i = 0; i < len; i++)
			bank_grp[i] = 0;
		paddr = (char *)(otp->user_otp->otp_data + tmp_len);
		if (copy_to_user(paddr, &bank_grp[0], len)) {
			ret = -EIO;
			goto err;
		}
		devm_kfree(sd->dev, bank_grp);
	}
err:
	devm_kfree(sd->dev, bank_grp);
	OV8865_otp_access_end(sensor);
	return ret;
}

static int OV8865_update_otp(struct v4l2_subdev *sd,
				struct b52_sensor_otp *otp)
{
	int ret = 0;
	int flag = 0;
	u8 lenc[240];
	struct b52_sensor *sensor = to_b52_sensor(sd);
	pr_err("OV8865_update_otp %d", otp->otp_type);


	if (otp->otp_type ==  SENSOR_TO_SENSOR) {
		/*access otp data start*/
		OV8865_otp_access_start(sensor);

		/*read otp data firstly*/
		ret = OV8865_read_OTP(sensor, otp, &flag, lenc);

		if (ret < 0)
			goto fail;
		/*apply some otp data, include awb and lenc*/
		if (otp->otp_ctrl & V4L2_CID_SENSOR_OTP_CONTROL_WB) {
			ret = OV8865_update_wb(sensor, otp);
			if (ret < 0)
				goto fail;
		}
		if (otp->otp_ctrl & V4L2_CID_SENSOR_OTP_CONTROL_LENC) {
			ret = OV8865_update_lenc(sensor, otp, &flag, lenc);
			if (ret < 0)
				goto fail;
		}

		/*access otp data end*/
		OV8865_otp_access_end(sensor);
		return 0;
	} else if (otp->otp_type ==  SENSOR_TO_ISP) {
		OV8865_read_data(sd, otp);
		return 0;
	} else
		return -1;
fail:
	pr_err("otp update fail\n");
	return ret;
}

