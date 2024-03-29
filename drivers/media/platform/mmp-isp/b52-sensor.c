/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 2 of the License,
 * or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/regulator/driver.h>
#include <media/v4l2-device.h>
#include <media/v4l2-subdev.h>
#include <media/b52-sensor.h>
#include <linux/leds.h>
#include <linux/math64.h>
#include <uapi/media/b52_api.h>
#include <linux/clk.h>
#include <media/mv_sc2_twsi_conf.h>
#include <media/b52socisp/host_isd.h>
#include "plat_cam.h"

static int otp_ctrl = -1;
static enum b52_sensor_mode s_mode;
module_param(otp_ctrl, int, 0644);

static const struct v4l2_ctrl_ops b52_ctrl_ops;

/* supported controls */
static struct v4l2_queryctrl sensor_qctrl[] = {
	{
		.id = V4L2_CID_ENUM_SENSOR,
		.type = V4L2_CTRL_TYPE_INTEGER,
		.name = "enum sensor",
		.minimum = 0,
		.maximum = 1,
		.step = 1,
		.default_value = 0x0001,
		.flags = 0,
	}, {
	}
};

static int __b52_sensor_cmd_write(const struct b52_sensor_i2c_attr
		*i2c_attr, const struct b52_sensor_regs *regs, u8 pos)
{
	struct b52_cmd_i2c_data data;

	if (!i2c_attr || !regs) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	if (regs->num == 0)
		return 0;

	data.attr = i2c_attr;
	data.tab  = regs->tab;
	data.num  = regs->num;
	data.pos  = pos;

	return b52_cmd_write_i2c(&data);
}
static int b52_sensor_cmd_write(struct v4l2_subdev *sd, u16 addr,
		u32 val, u8 num)
{
	int shift = 0;
	struct regval_tab tab[3];
	struct b52_sensor_regs regs;
	const struct b52_sensor_i2c_attr *attr;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!sensor || num == 0) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	attr = &sensor->drvdata->i2c_attr[sensor->cur_i2c_idx];
	if (num > 3 || (num == 3 && attr->val_len == I2C_16BIT)) {
		pr_err("%s, write num %d too long\n", __func__, num);
		return -EINVAL;
	}

	if (attr->val_len == I2C_8BIT)
		shift = 8;
	else if (attr->val_len == I2C_16BIT)
		shift = 16;

	switch (num) {
	case 1:
		tab[0].reg = addr;
		tab[0].val = val;
		break;
	case 2:
		tab[0].reg = addr;
		tab[0].val = (val >> shift) & ((1 << shift) - 1);

		tab[1].reg = addr + 1;
		tab[1].val = val & ((1 << shift) - 1);
		break;
	case 3:
		tab[0].reg = addr;
		tab[0].val = (val >> shift * 2) & ((1 << shift) - 1);

		tab[1].reg = addr + 1;
		tab[1].val = (val >> shift * 1) & ((1 << shift) - 1);

		tab[2].reg = addr + 2;
		tab[2].val = (val >> shift * 0) & ((1 << shift) - 1);
		break;
	default:
		pr_err("%s, write num no correct\n", __func__);
		return -EINVAL;
	}

	regs.tab = tab;
	regs.num = num;

	return __b52_sensor_cmd_write(attr, &regs, sensor->pos);
}

static int b52_sensor_cmd_read(struct v4l2_subdev *sd, u16 addr,
		u32 *val, u8 num)
{
	int ret;
	int shift = 0;
	int i;
	struct regval_tab tab[3];
	const struct b52_sensor_i2c_attr *attr;
	struct b52_cmd_i2c_data data;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!sensor || !val || (num == 0)) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	attr = &sensor->drvdata->i2c_attr[sensor->cur_i2c_idx];
	if (num > 3 || (num == 3 && attr->val_len == I2C_16BIT)) {
		pr_err("%s, read num %d too long\n", __func__, num);
		return -EINVAL;
	}

	for (i = 0; i < num; i++)
		tab[i].reg = addr + i;
	data.attr = attr;
	data.tab = tab;
	data.num = num;
	data.pos = sensor->pos;

	ret = b52_cmd_read_i2c(&data);
	if (ret)
		return ret;

	if (data.attr->val_len == I2C_8BIT)
		shift = 8;
	else if (data.attr->val_len == I2C_16BIT)
		shift = 16;

	switch (num) {
	case 1:
		*val = tab[0].val;
		break;
	case 2:
		*val = (tab[0].val << shift) | tab[1].val;
		break;
	case 3:
		*val =	(tab[0].val << shift * 2) |
			(tab[1].val << shift * 1) |
			(tab[2].val << shift * 0);
		break;
	default:
		pr_err("%s, read num no correct\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int b52_sensor_g_cur_fmt(struct v4l2_subdev *sd,
	struct b52_cmd_i2c_data *data)
{
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!data) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	mutex_lock(&sensor->lock);

	data->attr = &sensor->drvdata->i2c_attr[sensor->cur_i2c_idx];
	data->tab  = sensor->mf_regs.tab;
	data->num  = sensor->mf_regs.num;
	data->pos  = sensor->pos;

	mutex_unlock(&sensor->lock);

	return 0;
}


struct b52_sensor *b52_get_sensor(struct media_entity *entity)
{
	struct v4l2_subdev *sd, *hsd;
	struct media_device *mdev = entity->parent;
	struct media_entity_graph graph;
	struct media_entity *sensor_entity = NULL;

	mutex_lock(&mdev->graph_mutex);
	media_entity_graph_walk_start(&graph, entity);
	while ((entity = media_entity_graph_walk_next(&graph)))
		if (entity->type == MEDIA_ENT_T_V4L2_SUBDEV_HOST) {
			sensor_entity = entity;
			break;
		}
	mutex_unlock(&mdev->graph_mutex);

	if (!sensor_entity) {
		pr_err("sensor entity not found\n");
		return NULL;
	}

	hsd = container_of(sensor_entity, struct v4l2_subdev, entity);
	sd = host_subdev_get_guest(hsd, MEDIA_ENT_T_V4L2_SUBDEV_SENSOR);
	return to_b52_sensor(sd);
}
EXPORT_SYMBOL(b52_get_sensor);

/* only used for detect sensor, not download the FW */
static int __b52_sensor_isp_read(const struct b52_sensor_i2c_attr *attr,
		u16 reg, u16 *val, u8 pos)
{
	if (!attr || !val) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}
	return b52_isp_read_i2c(attr, reg, val, pos);
}

static int __b52_sensor_isp_write(const struct b52_sensor_i2c_attr *attr,
		u16 reg, u16 val, u8 pos)
{
	if (!attr) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}
	return b52_isp_write_i2c(attr, reg, val, pos);
}

/* only can be called after detect the sensor */
static int b52_sensor_isp_read(struct v4l2_subdev *sd, u16 addr,
		u16 *val)
{
	u8 pos;
	const struct b52_sensor_i2c_attr *attr;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!sensor) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}
	attr = &sensor->drvdata->i2c_attr[sensor->cur_i2c_idx];
	pos = sensor->pos;

	return __b52_sensor_isp_read(attr, addr, val, pos);
}
/* only can be called after detect the sensor */
static int b52_sensor_isp_write(struct v4l2_subdev *sd, u16 addr,
		u16 val)
{
	u8 pos;
	const struct b52_sensor_i2c_attr *attr;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!sensor) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}
	attr = &sensor->drvdata->i2c_attr[sensor->cur_i2c_idx];
	pos = sensor->pos;
	return __b52_sensor_isp_write(attr, addr, val, pos);
}

static int b52_sensor_init(struct v4l2_subdev *sd)
{
	int ret = 0;
	int num = 0;
	int written_num = 0;
	struct b52_sensor_regs regs;
	const struct b52_sensor_i2c_attr *attr;
	struct b52_sensor_module *module;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!sensor) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	if (sensor->sensor_init)
		return 0;

	attr = &sensor->drvdata->i2c_attr[sensor->cur_i2c_idx];
	regs.tab = sensor->drvdata->global_setting.tab;

	while (written_num < sensor->drvdata->global_setting.num) {
		if (likely(regs.tab[num].reg != SENSOR_MDELAY ||
				regs.tab[num].val != SENSOR_MDELAY)) {
			num++;
			if (likely(written_num + num <
					sensor->drvdata->global_setting.num))
				continue;
		}

		regs.num = num;
		ret = __b52_sensor_cmd_write(attr, &regs, sensor->pos);
		if (ret)
			return ret;

		if (unlikely(regs.tab[num].reg == SENSOR_MDELAY &&
				regs.tab[num].val == SENSOR_MDELAY)) {
			msleep(regs.tab[num].mask);
			num++;
		}

		written_num += num;
		regs.tab += written_num;
		num = 0;
	}

	b52_sensor_call(sensor, get_pixel_rate,
			&sensor->pixel_rate, sensor->mclk);
	pr_debug("sensor pxiel rate %d\n", sensor->pixel_rate);

	if (sensor->csi.calc_dphy)
		b52_sensor_call(sensor, get_dphy_desc,
				&sensor->csi.dphy_desc, sensor->mclk);

	if (otp_ctrl != -1)
		sensor->otp.otp_ctrl = otp_ctrl;

	if (sensor->drvdata->ops->update_otp)
		b52_sensor_call(sensor, update_otp, &sensor->otp);

	module = sensor->drvdata->module;
	for (num = 0; num < sensor->drvdata->num_module; num++)
		if (sensor->otp.module_id == module[num].id) {
			pr_info("detected module[%d].id = 0x%x\n", num, module[num].id);
			break;
		}

	if (num < sensor->drvdata->num_module)
		sensor->cur_mod_id = num;
	else
		sensor->cur_mod_id = -ENODEV;

	ret = v4l2_ctrl_handler_setup(&sensor->ctrls.ctrl_hdl);
	if (ret < 0)
		pr_err("%s: setup handler failed\n", __func__);
	sensor->sensor_init = 1;

	return ret;
}
#if 0
/* FIXME add detect vcm in future */
static int b52_sensor_detect_vcm(struct v4l2_subdev *sd)
{
	int i;
	u16 val;
	int ret;
	const struct b52_sensor_vcm *vcm;
	const struct b52_sensor_regs *id;
	const struct b52_sensor_i2c_attr *attr;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!sensor) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	if (!sensor->drvdata->module) {
		pr_err("sensor support internal vcm\n");
		return 0;
	}

	vcm = sensor->drvdata->module->vcm;
	id = &vcm->id;

	attr = vcm->attr;

	for (i = 0; i < id->num; i++) {
		ret = __b52_sensor_isp_read(attr, id->tab[i].reg,
				&val, sensor->pos);

		if (ret || val != id->tab[i].val) {
			pr_err("detect %s failed\n", vcm->name);
			pr_err("val: got %x, req %x\n", val, id->tab[i].val);
			return -ENODEV;
		}
	}

	pr_info("sensor external vcm: %s detected\n", vcm->name);
	return 0;
}
#endif
static inline int __detect_sensor(const struct b52_sensor_regs *id,
			const struct b52_sensor_i2c_attr *attr, u8 pos)
{
	int i;
	u16 val;
	int ret;

	for (i = 0; i < id->num; i++) {
		pr_err("addr 0x%x; req 0x%x\n", attr->addr, id->tab[i].reg);
		ret = __b52_sensor_isp_read(attr, id->tab[i].reg, &val, pos);

		if (ret || val != id->tab[i].val) {
			pr_err("val: got %x, req %x\n", val, id->tab[i].val);
			return -ENODEV;
		}
	}

	return 0;
}

static int b52_sensor_detect_sensor(struct v4l2_subdev *sd)
{
	int i;
	int ret;
	const struct b52_sensor_regs *id;
	const struct b52_sensor_i2c_attr *attr;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!sensor) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	id = &sensor->drvdata->id;
	for (i = 0; i < sensor->drvdata->num_i2c_attr; i++) {
		attr = &sensor->drvdata->i2c_attr[i];
		ret = __detect_sensor(id, attr, sensor->pos);
		if (!ret)
			goto sensor_detected;
	}

	pr_err("detect %s failed\n", sensor->drvdata->name);
	return ret;

sensor_detected:
	sensor->cur_i2c_idx = i;
	pr_info("sensor %s detected, i2c addr 0x%x\n",
			sensor->drvdata->name, sensor->drvdata->i2c_attr[i].addr);

	return 0;
}
/* read module id after detect the sensor. */
static int b52_sensor_detect_module(struct v4l2_subdev *sd)
{
	int ret, num;
	enum OTP_TYPE org_otp_type;
	struct b52_sensor_module *module;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (sensor->drvdata->ops->update_otp &&
		sensor->drvdata->module) {
		if (sensor->drvdata->num_module > 1) {
			/*
			 * FIXME: the default otp type maybe have set before,
			 * need write back it after read module info
			 */
			org_otp_type = sensor->otp.otp_type;
			sensor->otp.otp_type = READ_MODULE_INFO;
			ret = b52_sensor_call(sensor, update_otp, &sensor->otp);
			sensor->otp.otp_type = org_otp_type;

			if (!ret) {
				module = sensor->drvdata->module;
				for (num = 0; num < sensor->drvdata->num_module;
					num++)
					if (sensor->otp.module_id
						== module[num].id)
						break;

				if (num < sensor->drvdata->num_module) {
					sensor->cur_mod_id = num;
					goto detected;

				} else
					goto error;
			} else
				goto error;
		} else {
			pr_info("%s:just support one module for %s,use the default module directly.\n",
				__func__, sensor->drvdata->name);
			goto use_default_module_info;
		}
	} else {
		pr_info("%s: no module info for %s,use the default module.\n",
			__func__, sensor->drvdata->name);
		goto use_default_module_info;
	}

detected:
	pr_info("%s: detected module[%d].id:0x%x, name:%s for %s\n", __func__,
		sensor->cur_mod_id, module[sensor->cur_mod_id].id,
		module[sensor->cur_mod_id].name, sensor->drvdata->name);
	return 0;

use_default_module_info:
	sensor->cur_mod_id = 0;
	return 0;

error:
	sensor->cur_mod_id = -ENXIO;
	pr_err("%s: read %s module id error, check the otp function.\n",
		__func__, sensor->drvdata->name);
	return -ENXIO;
}

static int b52_sensor_get_power(struct v4l2_subdev *sd)
{
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	struct b52_sensor *sensor = to_b52_sensor(sd)
	struct device_node *pdata_np;

	pdata_np = (struct device_node *)client->dev.of_node;

	sensor->power.af_2v8 = devm_regulator_get(&client->dev, "af_2v8");
	if (IS_ERR(sensor->power.af_2v8)) {
		dev_warn(&client->dev, "Failed to get regulator af_2v8\n");
		sensor->power.af_2v8 = NULL;
	}
	sensor->power.avdd_2v8 = devm_regulator_get(&client->dev, "avdd_2v8");
	if (IS_ERR(sensor->power.avdd_2v8)) {
		dev_warn(&client->dev, "Failed to get regulator avdd_2v8\n");
		sensor->power.avdd_2v8 = NULL;
	}
	sensor->power.dovdd_1v8 = devm_regulator_get(&client->dev, "dovdd_1v8");
	if (IS_ERR(sensor->power.dovdd_1v8)) {
		dev_warn(&client->dev, "Failed to get regulator dovdd_1v8\n");
		sensor->power.dovdd_1v8 = NULL;
	}
	sensor->power.dvdd_1v2 = devm_regulator_get(&client->dev, "dvdd_1v2");
	if (IS_ERR(sensor->power.dvdd_1v2)) {
		dev_warn(&client->dev, "Failed to get regulator dvdd_1v2\n");
		sensor->power.dvdd_1v2 = NULL;
	}

	return 0;
}

static int b52_sensor_put_power(struct v4l2_subdev *sd)
{
	struct b52_sensor *sensor = to_b52_sensor(sd)
	if (sensor->power.avdd_2v8)
		devm_regulator_put(sensor->power.avdd_2v8);
	if (sensor->power.dvdd_1v2)
		devm_regulator_put(sensor->power.dvdd_1v2);
	if (sensor->power.af_2v8)
		devm_regulator_put(sensor->power.af_2v8);
	if (sensor->power.dovdd_1v8)
		devm_regulator_put(sensor->power.dovdd_1v8);
	return 0;
}



static int b52_sensor_gain_to_iso(struct v4l2_subdev *sd,
		u32 gain, u32 *iso)
{
	const struct v4l2_fract *f;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	f = &sensor->drvdata->gain2iso_ratio;

	if (!f->denominator) {
		pr_err("%s: f->denominator is zero\n", __func__);
		return -EINVAL;
	}

	*iso = gain * f->numerator / f->denominator;
	return 0;
}

static int b52_sensor_iso_to_gain(struct v4l2_subdev *sd,
		u32 iso, u32 *gain)
{
	const struct v4l2_fract *f;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	f = &sensor->drvdata->gain2iso_ratio;

	if (!f->numerator) {
		pr_err("%s: f->numerator is zero\n", __func__);
		return -EINVAL;
	}

	*gain = iso * f->denominator / f->numerator;
	return 0;
}

static int b52_sensor_to_expo_line(struct v4l2_subdev *sd,
		u32 time, u32 *lines)
{
	/*
	 * time unit: 100 us according to v4l2
	 */
	u32 us = time * 100;
	u8 i;
	u64 temp;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	i = sensor->cur_res_idx;

	if (!lines) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	temp = us * (u64)(sensor->pixel_rate);
	temp = div_u64(temp, sensor->drvdata->res[i].hts);
	*lines = (u32)div_u64(temp + 500000, 1000000);

	pr_debug("%u us, line %u, hts %u, pixle rate %u\n", us, *lines,
		sensor->drvdata->res[i].hts, sensor->pixel_rate);
	return 0;
}

static int b52_sensor_to_expo_time(struct v4l2_subdev *sd,
		u32 *time, u32 lines)
{
	/* time unit: 100 us according to v4l2 */
	u32 line_time;
	u8 i;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	i = sensor->cur_res_idx;

	if (!time) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	line_time = sensor->drvdata->res[i].hts * 100000 /
		(sensor->pixel_rate / 10000);
	/* line_time unit: 1ns */
	*time = lines * line_time / 100000;

	pr_debug("%s: %d 100us, %d line\n", __func__, *time, lines);
	return 0;
}

static int b52_sensor_g_cur_fps(struct v4l2_subdev *sd,
	struct v4l2_fract *fps)
{
	u32 i;
	int ret;
	u32 vts;
	u32 size;
	const struct b52_sensor_regs *reg;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!fps) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	i = sensor->cur_res_idx;
	reg = &sensor->drvdata->vts_reg;

	ret = b52_sensor_call(sensor, i2c_read,
			reg->tab->reg, &vts, reg->num);
	if (ret) {
		pr_err("%s: read vts failed\n", __func__);
		return ret;
	}

	size = vts * sensor->drvdata->res[i].hts;

	fps->numerator = (sensor->pixel_rate * 10) / (size / 10);
	fps->denominator = 100;

	return 0;
}

#define BANDING_STEP_50HZ	0
#define BANDING_STEP_60HZ	1
static u32 __cal_band_step(int hz, u32 pixel_rate, u32 hts)
{
	u32 banding_step;

	if (hz == BANDING_STEP_50HZ)
		banding_step = pixel_rate/100/hts;
	else if (hz == BANDING_STEP_60HZ)
		banding_step = pixel_rate/120/hts;
	else
		return 0;

	return banding_step;
}
static int b52_sensor_g_band_step(struct v4l2_subdev *sd,
		u16 *band_50hz, u16 *band_60hz)
{
	int i;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	i = sensor->cur_res_idx;

	*band_50hz = __cal_band_step(BANDING_STEP_50HZ,
		sensor->pixel_rate,
		sensor->drvdata->res[i].hts);
	*band_60hz = __cal_band_step(BANDING_STEP_60HZ,
		sensor->pixel_rate,
		sensor->drvdata->res[i].hts);

	return 0;
}

static int b52_sensor_s_flip(struct v4l2_subdev *sd,
		int hflip, int on)
{
	u32 val;
	int ret;
	const struct b52_sensor_regs *reg;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (hflip)
		reg = &sensor->drvdata->hflip;
	else
		reg = &sensor->drvdata->vflip;

	ret = b52_sensor_call(sensor, i2c_read,
			reg->tab->reg, &val, reg->num);
	if (ret)
		return ret;

	val &= ~(reg->tab->mask);

	/*
	 * reg->mask: the bit controls the flip. Like 0x2, bit1 controls.
	 * reg->tab->val:original value to get the correct orientation.
	 * Set the related bit to inverse value when flip. For example:
	 * original value is 0x4(bit2), change bit2 to 0 when flip.
	 */

	if (on)
		val |= ((~(reg->tab->val)) & (reg->tab->mask));
	else
		val |= reg->tab->val;

	ret = b52_sensor_call(sensor, i2c_write,
			reg->tab->reg, val, reg->num);

	return ret;
}

static int b52_sensor_g_param_range(struct v4l2_subdev *sd,
		int type, u16 *min, u16 *max)
{
	const struct b52_sensor_data *data;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	data = sensor->drvdata;

	if (!min || !max) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	switch (type) {
	case B52_SENSOR_GAIN:
		*min = data->gain_range[B52_SENSOR_AG].min;
		*max = data->gain_range[B52_SENSOR_AG].max;
		if (data->gain_range[B52_SENSOR_DG].min != 0) {
			*min = *min * data->gain_range[B52_SENSOR_DG].min / B52_GAIN_UNIT;
			*max = *max * data->gain_range[B52_SENSOR_DG].max / B52_GAIN_UNIT;
		}
		break;

	case B52_SENSOR_AGAIN:
		*min = data->gain_range[B52_SENSOR_AG].min;
		*max = data->gain_range[B52_SENSOR_AG].max;
		break;

	case B52_SENSOR_DGAIN:
		*min = data->gain_range[B52_SENSOR_DG].min;
		*max = data->gain_range[B52_SENSOR_DG].max;
		break;

	case B52_SENSOR_EXPO:
		*min = data->expo_range.min;
		*max = data->expo_range.max;
		break;

	case B52_SENSOR_FRACTIONALEXPO:
		*min = data->frationalexp_range.min;
		*max = data->frationalexp_range.max;
		break;

	case B52_SENSOR_VTS:
		*min = data->vts_range.min;
		*max = data->vts_range.max;
		break;

	case B52_SENSOR_REQ_VTS:
		*min = data->res[sensor->cur_res_idx].min_vts;
		*max = data->res[sensor->cur_res_idx].min_vts;
		break;

	case B52_SENSOR_REQ_HTS:
		*min = data->res[sensor->cur_res_idx].hts;
		*max = data->res[sensor->cur_res_idx].hts;
		break;

	case B52_SENSOR_FOCUS:
		*min = data->focus_range.min;
		*max = data->focus_range.max;
		break;

	default:
		pr_err("%s: wrong type\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int b52_sensor_g_sensor_attr(struct v4l2_subdev *sd,
		struct b52_sensor_i2c_attr *attr)
{
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!attr) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	*attr = sensor->drvdata->i2c_attr[sensor->cur_i2c_idx];

	return 0;
}

static int b52_sensor_g_aecagc_reg(struct v4l2_subdev *sd,
		int type, struct b52_sensor_regs *reg)
{
	const struct b52_sensor_data *data;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	data = sensor->drvdata;

	switch (type) {
	case B52_SENSOR_AGAIN:
		*reg = data->gain_reg[B52_SENSOR_AG];
		break;

	case B52_SENSOR_DGAIN:
		*reg = data->gain_reg[B52_SENSOR_DG];
		break;

	case B52_SENSOR_EXPO:
		*reg = data->expo_reg;
		break;

	case B52_SENSOR_VTS:
		*reg = data->vts_reg;
		break;

	case B52_SENSOR_FRACTIONALEXPO:
		*reg = data->frationalexp_reg;
		break;

	default:
		pr_err("%s: wrong type: %d\n", __func__, type);
		return -EINVAL;
	}

	if (!reg->tab || (reg->num == 0)) {
		pr_err("%s: reg is null\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int b52_sensor_g_info(struct v4l2_subdev *sd,
		struct b52_sensor_info *info)
{
	int i;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!sensor || !info) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	i = sensor->cur_res_idx;

	if (sensor->drvdata->res[i].min_isp_clk_freq) {
		info->type = B52_SENSOR_INFO_MIN_ISP_CLK;
		info->min_isp_clk_freq = sensor->drvdata->res[i].min_isp_clk_freq;
	} else {
		info->type = B52_SENSOR_INFO_PIXEL_PER_SEC;
		/* default 30fps */
		info->pps = sensor->drvdata->res[i].width * 30 *
			sensor->drvdata->res[i].height;
	}

	return  0;
}

static int b52_sensor_g_csi(struct v4l2_subdev *sd,
		struct mipi_csi2 *csi)
{
	struct b52_sensor *sensor = to_b52_sensor(sd);

	*csi = sensor->csi;

	return  0;
}

static int b52_sensor_gain_convert(struct v4l2_subdev *sd, u16 isp_gain,
		u16 *sensor_ag, u16 *sensor_dg)
{
	int ret = 0;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (sensor->drvdata->ops->convert_gain)
		ret = sensor->drvdata->ops->convert_gain(sd, isp_gain, sensor_ag, sensor_dg);

	return ret;
}

static int b52_sensor_expo_convert(struct v4l2_subdev *sd, u32 isp_expo,
		u32 *sensor_ae)
{
	int ret = 0;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (sensor->drvdata->ops->convert_expo)
		ret = sensor->drvdata->ops->convert_expo(sd, isp_expo, sensor_ae);

	return ret;
}

static struct b52_sensor_ops b52_sensor_def_ops = {
	.init          = b52_sensor_init,
	.i2c_read      = b52_sensor_cmd_read,
	.i2c_write     = b52_sensor_cmd_write,
	.i2c_read_without_fw = b52_sensor_isp_read,
	.i2c_write_without_fw = b52_sensor_isp_write,
	.g_cur_fmt     = b52_sensor_g_cur_fmt,
	.get_power     = b52_sensor_get_power,
	.put_power     = b52_sensor_put_power,
	.gain_convert = b52_sensor_gain_convert,
	.expo_convert = b52_sensor_expo_convert,
	.detect_sensor = b52_sensor_detect_sensor,
	.detect_module = b52_sensor_detect_module,
	/* .detect_vcm    = b52_sensor_detect_vcm,*/
	.g_cur_fps     = b52_sensor_g_cur_fps,
	.g_param_range = b52_sensor_g_param_range,
	.g_aecagc_reg  = b52_sensor_g_aecagc_reg,
	.g_sensor_attr = b52_sensor_g_sensor_attr,
	.g_band_step   = b52_sensor_g_band_step,
	.g_csi         = b52_sensor_g_csi,
	.g_info        = b52_sensor_g_info,
	.s_flip        = b52_sensor_s_flip,
	.gain_to_iso   = b52_sensor_gain_to_iso,
	.iso_to_gain   = b52_sensor_iso_to_gain,
	.to_expo_line  = b52_sensor_to_expo_line,
	.to_expo_time  = b52_sensor_to_expo_time,
};

static int b52_sensor_set_defalut(struct b52_sensor *sensor)
{
	if (!sensor) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	sensor->ops = b52_sensor_def_ops;

	if (!sensor->drvdata->ops->get_pixel_rate) {
		pr_err("error: get_pixel_rate not defined\n");
		return -EINVAL;
	} else {
		sensor->ops.get_pixel_rate =
			sensor->drvdata->ops->get_pixel_rate;
	}

	if (sensor->csi.calc_dphy) {
		if (!sensor->drvdata->ops->get_dphy_desc) {
			pr_err("error: get_dphy not defined\n");
			return -EINVAL;
		} else
			sensor->ops.get_dphy_desc =
				sensor->drvdata->ops->get_dphy_desc;
	}

	if (!sensor->drvdata->ops->update_otp) {
		pr_err("error: update_otp not defined\n");
		return -EINVAL;
	} else {
		sensor->ops.update_otp =
			sensor->drvdata->ops->update_otp;
		sensor->otp.otp_ctrl = 3;
		sensor->otp.otp_type = SENSOR_TO_SENSOR;
	}
	return 0;
}

static void b52_sensor_s_board_power(struct i2c_client *client, int on)
{
	struct gpio_desc *mut;
	struct gpio_desc *ecam1;
	struct gpio_desc *ecam2;
	struct gpio_desc *ecam3;
	struct gpio_desc *ecam4;
	struct gpio_desc *ilim;

	mut = devm_gpiod_get(&client->dev, "mut");
	if (IS_ERR(mut)) {
		dev_warn(&client->dev, "Failed to get mut gpio\n");
		mut = NULL;
	}

	ecam1 = devm_gpiod_get(&client->dev, "ecam1");
	if (IS_ERR(ecam1)) {
		dev_warn(&client->dev, "Failed to get ecam1 gpio\n");
		ecam1 = NULL;
	}

	ecam2 = devm_gpiod_get(&client->dev, "ecam2");
	if (IS_ERR(ecam2)) {
		dev_warn(&client->dev, "Failed to get ecam2 gpio\n");
		ecam2 = NULL;
	}

	ecam3 = devm_gpiod_get(&client->dev, "ecam3");
	if (IS_ERR(ecam3)) {
		dev_warn(&client->dev, "Failed to get ecam3 gpio\n");
		ecam3 = NULL;
	}

	ecam4 = devm_gpiod_get(&client->dev, "ecam4");
	if (IS_ERR(ecam4)) {
		dev_warn(&client->dev, "Failed to get ecam4 gpio\n");
		ecam4 = NULL;
	}

	ilim = devm_gpiod_get(&client->dev, "ilim");
	if (IS_ERR(ilim)) {
		dev_warn(&client->dev, "Failed to get ilim gpio\n");
		ilim = NULL;
	}

	if (on) {
		if (mut)
			gpiod_set_value_cansleep(mut, 0);
		if (ecam1)
			gpiod_set_value_cansleep(ecam1, 0);
		if (ecam2)
			gpiod_set_value_cansleep(ecam2, 0);
		if (ecam3)
			gpiod_set_value_cansleep(ecam3, 0);
		if (ecam4)
			gpiod_set_value_cansleep(ecam4, 0);
		if (ilim)
			gpiod_set_value_cansleep(ilim, 1);
	} else {
		if (mut)
			gpiod_set_value_cansleep(mut, 1);
		if (ecam1)
			gpiod_set_value_cansleep(ecam1, 1);
		if (ecam2)
			gpiod_set_value_cansleep(ecam2, 1);
		if (ecam3)
			gpiod_set_value_cansleep(ecam3, 1);
		if (ecam4)
			gpiod_set_value_cansleep(ecam4, 1);
	}
}

static int b52_sensor_s_power(struct v4l2_subdev *sd, int on)
{
	int ret = 0;
	int reset_delay = 100;
	int pwdone_delay = 500;
	struct sensor_power *power;
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (sensor->board_prop_id == 1)
		b52_sensor_s_board_power(client, on);

	if (sensor->drvdata->ops->s_power) {
		/* hold isp power */
		if (on) {
			ret = plat_tune_isp(1);
			if (ret < 0)
				return ret;
		}
		ret = sensor->drvdata->ops->s_power(sd, on);
		/* release isp power */
		if ((ret < 0) || (!on))
			WARN_ON(plat_tune_isp(0) < 0);
		return ret;
	}

	power = (struct sensor_power *) &(sensor->power);

	if (on) {
		if (power->ref_cnt++ > 0)
			return 0;

		ret = plat_tune_isp(1);
		if (ret < 0)
			goto isppw_err;

		if (sensor->i2c_dyn_ctrl) {
			ret = sc2_select_pins_state(sensor->pos - 1,
					SC2_PIN_ST_SCCB, SC2_MOD_B52ISP);
			if (ret < 0) {
				pr_err("b52 sensor i2c pin is not configured\n");
				goto st_err;
			}
		}
		clk_set_rate(sensor->clk, sensor->mclk);
		clk_prepare_enable(sensor->clk);
		power->pwdn = devm_gpiod_get(&client->dev, "pwdn");
		if (IS_ERR(power->pwdn)) {
			dev_warn(&client->dev, "Failed to get gpio pwdn\n");
			power->pwdn = NULL;
		} else {
			ret = gpiod_direction_output(power->pwdn, 0);
			if (ret < 0) {
				dev_err(&client->dev, "Failed to set gpio pwdn\n");
				goto i2c_err;
			}
		}

		power->rst = devm_gpiod_get(&client->dev, "reset");
		if (IS_ERR(power->rst)) {
			dev_warn(&client->dev, "Failed to get gpio reset\n");
			power->rst = NULL;
		} else {
			ret = gpiod_direction_output(power->rst, 1);
			if (ret < 0) {
				dev_err(&client->dev, "Failed to set gpio rst\n");
				goto rst_err;
			}
		}

		if (power->avdd_2v8) {
			regulator_set_voltage(power->avdd_2v8,
						2800000, 2800000);
			ret = regulator_enable(power->avdd_2v8);
			if (ret < 0)
				goto avdd_err;
		}

		if (power->pwdn)
			gpiod_set_value_cansleep(power->pwdn, 0);

		if (power->dovdd_1v8) {
			regulator_set_voltage(power->dovdd_1v8,
						1800000, 1800000);
			ret = regulator_enable(power->dovdd_1v8);
			if (ret < 0)
				goto dovdd_err;
		}
		if (power->dvdd_1v2) {
			regulator_set_voltage(power->dvdd_1v2,
						1200000, 1200000);
			ret = regulator_enable(power->dvdd_1v2);
			if (ret < 0)
				goto dvdd_err;
		}
		if (power->af_2v8) {
			regulator_set_voltage(power->af_2v8,
						2800000, 2800000);
			ret = regulator_enable(power->af_2v8);
			if (ret < 0)
				goto af_err;
		}

		if (power->rst) {
			gpiod_set_value_cansleep(power->rst, 1);
			/*
			 * according to SR544 power sequence
			 * driver have to delay > 10ms
			 */
			if (sensor->drvdata->reset_delay)
				reset_delay = sensor->drvdata->reset_delay;
			usleep_range(reset_delay, reset_delay + 10);
			gpiod_set_value_cansleep(power->rst, 0);
		}

		/* delay between power on and read/write sensor register */
		if (sensor->drvdata->pwdone_delay)
			pwdone_delay = sensor->drvdata->pwdone_delay;
		usleep_range(pwdone_delay, pwdone_delay + 50);

	} else {
		if (WARN_ON(power->ref_cnt == 0))
			return -EINVAL;

		if (--power->ref_cnt > 0)
			return 0;
		if (power->rst)
			gpiod_set_value_cansleep(power->rst, 1);
		if (power->dvdd_1v2)
			regulator_disable(power->dvdd_1v2);
		if (power->avdd_2v8)
			regulator_disable(power->avdd_2v8);
		if (power->pwdn)
			gpiod_set_value_cansleep(power->pwdn, 1);
		if (power->dovdd_1v8)
			regulator_disable(power->dovdd_1v8);
		if (power->af_2v8)
			regulator_disable(power->af_2v8);

		if (sensor->power.rst)
			devm_gpiod_put(&client->dev, sensor->power.rst);
		if (sensor->power.pwdn)
			devm_gpiod_put(&client->dev, sensor->power.pwdn);
		if (sensor->i2c_dyn_ctrl) {
			ret = sc2_select_pins_state(sensor->pos - 1,
					SC2_PIN_ST_GPIO, SC2_MOD_B52ISP);
			if (ret < 0)
				pr_err("b52 sensor gpio pin is not configured\n");
		}
		clk_disable_unprepare(sensor->clk);
		WARN_ON(plat_tune_isp(0) < 0);

		sensor->sensor_init = 0;
	}

	return ret;

af_err:
	if (power->dvdd_1v2)
		regulator_disable(power->dvdd_1v2);
dvdd_err:
	if (power->dovdd_1v8)
		regulator_disable(power->dovdd_1v8);
dovdd_err:
	if (power->avdd_2v8)
		regulator_disable(power->af_2v8);
avdd_err:
	if (sensor->power.rst)
		devm_gpiod_put(&client->dev, sensor->power.rst);
rst_err:
	if (sensor->power.pwdn)
		devm_gpiod_put(&client->dev, sensor->power.pwdn);
i2c_err:
	clk_disable_unprepare(sensor->clk);
	if (sensor->i2c_dyn_ctrl)
		ret = sc2_select_pins_state(sensor->pos - 1,
				SC2_PIN_ST_GPIO, SC2_MOD_B52ISP);
st_err:
	WARN_ON(plat_tune_isp(0) < 0);
isppw_err:
	power->ref_cnt--;

	return ret;
}

static int b52_sensor_s_stream(struct v4l2_subdev *sd, int enable)
{
	const struct b52_sensor_regs *regs;
	const struct b52_sensor_i2c_attr *attr;
	struct b52_sensor *sensor = to_b52_sensor(sd)
	int try_count = 3;
	int ret = 0;
	if (enable) {
		if (atomic_inc_return(&sensor->stream_cnt) > 1)
			return 0;

		regs = &sensor->drvdata->streamon;
		blocking_notifier_call_chain(&sensor->nh, 0, sensor);
	} else {
		if (atomic_dec_return(&sensor->stream_cnt) > 0)
			return 0;

		regs = &sensor->drvdata->streamoff;
	}
	attr = &sensor->drvdata->i2c_attr[sensor->cur_i2c_idx];
	while (try_count-- > 0) {
		ret = __b52_sensor_cmd_write(attr, regs, sensor->pos);
		if (ret != 0)
			pr_err("sensor set stream:%d fail\n", enable);
		else
			break;
	}
	return ret;
}

static int b52_sensor_g_mbus_config(struct v4l2_subdev *sd,
					struct v4l2_mbus_config *cfg)
{
	cfg->type = V4L2_MBUS_CSI2;
	return 0;
}
static enum v4l2_mbus_pixelcode b52_sensor_get_real_mbus(
	    struct v4l2_subdev *sd, enum v4l2_mbus_pixelcode code)
{
	int hflip;
	int vflip;
	enum v4l2_mbus_pixelcode new_code;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	if (!sensor->drvdata->flip_change_phase)
		return code;

	hflip = v4l2_ctrl_g_ctrl(sensor->ctrls.hflip);
	vflip = v4l2_ctrl_g_ctrl(sensor->ctrls.vflip);

	switch (code) {
	case V4L2_MBUS_FMT_SBGGR10_1X10:
		if (hflip && vflip)
			new_code = V4L2_MBUS_FMT_SRGGB10_1X10;
		else if (hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SGBRG10_1X10;
		else if (!hflip && vflip)
			new_code = V4L2_MBUS_FMT_SGRBG10_1X10;
		else if (!hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SBGGR10_1X10;
		break;

	case V4L2_MBUS_FMT_SGBRG10_1X10:
		if (hflip && vflip)
			new_code = V4L2_MBUS_FMT_SGRBG10_1X10;
		else if (hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SBGGR10_1X10;
		else if (!hflip && vflip)
			new_code = V4L2_MBUS_FMT_SRGGB10_1X10;
		else if (!hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SGBRG10_1X10;
		break;

	case V4L2_MBUS_FMT_SGRBG10_1X10:
		if (hflip && vflip)
			new_code = V4L2_MBUS_FMT_SGBRG10_1X10;
		else if (hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SRGGB10_1X10;
		else if (!hflip && vflip)
			new_code = V4L2_MBUS_FMT_SBGGR10_1X10;
		else if (!hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SGRBG10_1X10;
		break;

	case V4L2_MBUS_FMT_SRGGB10_1X10:
		if (hflip && vflip)
			new_code = V4L2_MBUS_FMT_SBGGR10_1X10;
		else if (hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SGRBG10_1X10;
		else if (!hflip && vflip)
			new_code = V4L2_MBUS_FMT_SGBRG10_1X10;
		else if (!hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SRGGB10_1X10;
		break;

	case V4L2_MBUS_FMT_SBGGR8_1X8:
		if (hflip && vflip)
			new_code = V4L2_MBUS_FMT_SRGGB8_1X8;
		else if (hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SGBRG8_1X8;
		else if (!hflip && vflip)
			new_code = V4L2_MBUS_FMT_SGRBG8_1X8;
		else if (!hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SBGGR8_1X8;
		break;

	case V4L2_MBUS_FMT_SGBRG8_1X8:
		if (hflip && vflip)
			new_code = V4L2_MBUS_FMT_SGRBG8_1X8;
		else if (hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SBGGR8_1X8;
		else if (!hflip && vflip)
			new_code = V4L2_MBUS_FMT_SRGGB8_1X8;
		else if (!hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SGBRG8_1X8;
		break;

	case V4L2_MBUS_FMT_SGRBG8_1X8:
		if (hflip && vflip)
			new_code = V4L2_MBUS_FMT_SGBRG8_1X8;
		else if (hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SRGGB8_1X8;
		else if (!hflip && vflip)
			new_code = V4L2_MBUS_FMT_SBGGR8_1X8;
		else if (!hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SGRBG8_1X8;
		break;

	case V4L2_MBUS_FMT_SRGGB8_1X8:
		if (hflip && vflip)
			new_code = V4L2_MBUS_FMT_SBGGR8_1X8;
		else if (hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SGRBG8_1X8;
		else if (!hflip && vflip)
			new_code = V4L2_MBUS_FMT_SGBRG8_1X8;
		else if (!hflip && !vflip)
			new_code = V4L2_MBUS_FMT_SRGGB8_1X8;
		break;

	default:
		pr_err("Not support mbus phase change of [h/v]flip\n");
		new_code = code;
		break;
	}

	return new_code;
}

static int b52_sensor_enum_mbus_code(struct v4l2_subdev *sd,
		struct v4l2_subdev_fh *fh,
		struct v4l2_subdev_mbus_code_enum *code)
{
	const struct b52_sensor_data *data;
	struct b52_sensor *sensor = to_b52_sensor(sd)

	data = sensor->drvdata;

	if (code->pad > 0 || code->index > data->num_mbus_fmt) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	code->code = b52_sensor_get_real_mbus(sd,
		data->mbus_fmt[code->index].mbus_code);

	return 0;
}

static int b52_sensor_enum_frame_size(struct v4l2_subdev *sd,
		struct v4l2_subdev_fh *fh,
		struct v4l2_subdev_frame_size_enum *fse)
{
	int i;
	const struct b52_sensor_data *data;
	struct b52_sensor *sensor = to_b52_sensor(sd)
	data = sensor->drvdata;

	if (fse->pad > 0 || fse->index > data->num_res) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < data->num_mbus_fmt; i++)
		if (fse->code == b52_sensor_get_real_mbus(sd,
			data->mbus_fmt[i].mbus_code))
			break;

	if (i >= data->num_mbus_fmt) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	fse->min_width = data->res[fse->index].width;
	fse->max_width = data->res[fse->index].width;
	fse->min_height = data->res[fse->index].height;
	fse->max_height = data->res[fse->index].height;

	return 0;
}

static int b52_sensor_enum_frame_interval(struct v4l2_subdev *sd,
		struct v4l2_subdev_fh *fh,
		struct v4l2_subdev_frame_interval_enum *fie)
{

	int i;
	u32 size;
	const struct b52_sensor_data *data;
	struct b52_sensor *sensor = to_b52_sensor(sd)
	data = sensor->drvdata;

	if (fie->pad > 0 || fie->index > data->num_res) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < data->num_mbus_fmt; i++)
		if (fie->code == b52_sensor_get_real_mbus(sd,
			data->mbus_fmt[i].mbus_code))
			break;

	if (i >= data->num_mbus_fmt) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < data->num_res; i++)
		if (fie->width == data->res[i].width &&
			fie->height == data->res[i].height)
			break;

	if (i >= data->num_res) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	size = data->res[i].min_vts * data->res[i].hts;

	fie->interval.numerator = (size * 10) /
			(sensor->pixel_rate / 1000);
	fie->interval.denominator = 10000;

	return 0;
}

static int b52_sensor_get_fmt(struct v4l2_subdev *sd,
		struct v4l2_subdev_fh *fh,
		struct v4l2_subdev_format *format)
{
	int ret = 0;
	const struct b52_sensor_data *data;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	data = sensor->drvdata;

	if (format->pad > 0) {
		pr_err("%s, error pad num\n", __func__);
		return -EINVAL;
	}

	mutex_lock(&sensor->lock);

	switch (format->which) {
	case V4L2_SUBDEV_FORMAT_TRY:
		/* FIXME */
		format->format = *v4l2_subdev_get_try_format(fh, 0);
		break;
	case V4L2_SUBDEV_FORMAT_ACTIVE:
		sensor->mf.code = b52_sensor_get_real_mbus(sd,
				data->mbus_fmt[sensor->cur_mbus_idx].mbus_code);
		format->format = sensor->mf;
		break;
	default:
		ret = -EINVAL;
		pr_err("%s, error format->which\n", __func__);
		goto error;
	}

error:
	mutex_unlock(&sensor->lock);
	return ret;
}

static int b52_sensor_set_fmt(struct v4l2_subdev *sd,
		struct v4l2_subdev_fh *fh,
		struct v4l2_subdev_format *format)
{
	int i;
	int j;
	struct b52_sensor_regs *mf_regs;
	const struct b52_sensor_data *data;
	struct v4l2_mbus_framefmt *mf = &format->format;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	data = sensor->drvdata;
	mf_regs = &sensor->mf_regs;

	if (format->pad > 0) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < data->num_mbus_fmt; i++)
		if (mf->code == b52_sensor_get_real_mbus(sd,
			data->mbus_fmt[i].mbus_code))
			break;

	if (i >= data->num_mbus_fmt) {
		pr_info("%s: mbus code not match\n", __func__);
		i = 0;
	};

	mf->code = b52_sensor_get_real_mbus(sd, data->mbus_fmt[i].mbus_code);
	mf->colorspace = data->mbus_fmt[i].colorspace;

	for (j = 0; j < data->num_res; j++) {
		if (((s_mode != 0) ? (data->res[j].sensor_mode == s_mode) : 1) &&
			mf->width == data->res[j].width &&
			mf->height == data->res[j].height)
			break;
	}

	s_mode = SENSOR_NORMAL_MODE;

	if (j >= data->num_res) {
		pr_info("%s: frame size not match\n", __func__);
		j = 0;
	}

	mf->width  = data->res[j].width;
	mf->height = data->res[j].height;
	mf->field  = V4L2_FIELD_NONE;


	if (format->which == V4L2_SUBDEV_FORMAT_ACTIVE) {
		int size = sizeof(*mf_regs->tab);

		mutex_lock(&sensor->lock);

		if (mf->code != sensor->mf.code ||
			mf->width != sensor->mf.width ||
			mf->height != sensor->mf.height) {
			memcpy(mf_regs->tab,
					data->mbus_fmt[i].regs.tab,
					size * data->mbus_fmt[i].regs.num);
			mf_regs->num = data->mbus_fmt[i].regs.num;

			memcpy(mf_regs->tab + mf_regs->num,
					data->res[j].regs.tab,
					size * data->res[j].regs.num);
			mf_regs->num += data->res[j].regs.num;
		}

		sensor->mf = *mf;
		sensor->cur_mbus_idx = i;
		sensor->cur_res_idx = j;

		mutex_unlock(&sensor->lock);
		blocking_notifier_call_chain(&sensor->nh, 0, sensor);
	}

	return 0;
}

static int b52_sensor_g_skip_top_lines(struct v4l2_subdev *sd, u32 *lines)
{
	struct b52_sensor *sensor = to_b52_sensor(sd);
	*lines = sensor->drvdata->skip_top_lines;

	return 0;
}

static int b52_sensor_g_skip_frames(struct v4l2_subdev *sd, u32 *frames)
{
	struct b52_sensor *sensor = to_b52_sensor(sd);

	*frames = sensor->drvdata->skip_frames;

	return 0;
}

static int b52_sensor_sd_open(struct v4l2_subdev *sd,
		struct v4l2_subdev_fh *fh)
{
	/* FIXME: not need put power on here */
	return v4l2_subdev_call(sd, core, s_power, 1);
}

static int b52_sensor_sd_close(struct v4l2_subdev *sd,
		struct v4l2_subdev_fh *fh)
{
	return v4l2_subdev_call(sd, core, s_power, 0);
}

static int b52_sensor_link_setup(struct media_entity *entity,
			  const struct media_pad *local,
			  const struct media_pad *remote, u32 flags)
{
	return 0;
}

static int b52_sensor_queryctrl(struct v4l2_subdev *sd,
					struct v4l2_queryctrl *qc)
{
	int i;
	int ret = -EINVAL;
	for (i = 0; i < ARRAY_SIZE(sensor_qctrl); i++)
		if (qc->id && qc->id == sensor_qctrl[i].id) {
			*qc = sensor_qctrl[i];
			ret = 0;
			break;
		}
	return ret;
}

static struct v4l2_subdev_video_ops b52_sensor_video_ops = {
	.s_stream = b52_sensor_s_stream,
	.g_mbus_config = b52_sensor_g_mbus_config,
};

static const struct v4l2_subdev_pad_ops b52_sensor_pad_ops = {
	.enum_mbus_code      = b52_sensor_enum_mbus_code,
	.enum_frame_size     = b52_sensor_enum_frame_size,
	.enum_frame_interval = b52_sensor_enum_frame_interval,
	.get_fmt             = b52_sensor_get_fmt,
	.set_fmt             = b52_sensor_set_fmt,
};

struct v4l2_subdev_sensor_ops b52_sensor_sensor_ops = {
	.g_skip_top_lines = b52_sensor_g_skip_top_lines,
	.g_skip_frames    = b52_sensor_g_skip_frames,
};

static int b52_sensor_reinit(struct b52_sensor *sensor)
{
	int cnt = 0;
	int ori_cnt;
	int ret = 0;
	const struct b52_sensor_regs *regs;
	const struct b52_sensor_i2c_attr *attr;

	if (!sensor)
		return -EINVAL;

	ori_cnt = sensor->power.ref_cnt;
	if (!ori_cnt) {
		pr_err("%s, not pwr on, no need to re-init\n", __func__);
		return 0;
	}

	cnt = ori_cnt;
	while (cnt--)
		v4l2_subdev_call(&sensor->sd, core, s_power, 0);
	msleep(100);
	cnt = ori_cnt;
	while (cnt--) {
		ret |= v4l2_subdev_call(&sensor->sd, core, s_power, 1);
		if (ret != 0)
			pr_err("%s, unable to pwr on\n", __func__);
	}

	b52_sensor_call(sensor, init);

	if (!atomic_read(&sensor->stream_cnt)) {
		pr_err("%s, no need to stm on\n", __func__);
		return 0;
	}

	regs = &sensor->drvdata->streamon;
	attr = &sensor->drvdata->i2c_attr[sensor->cur_i2c_idx];
	ret |= __b52_sensor_cmd_write(attr, regs, sensor->pos);

	return ret;
}

static int b52_sensor_esd_status(struct b52_sensor *sensor, int *status)
{
	int i;
	int ret;
	u32 val;
	const struct b52_sensor_regs *esd;

	if (!sensor || !status)
		return -EINVAL;

	esd = &sensor->drvdata->esd;

	if (!esd->num) {
		*status = SENSOR_ESD_ST_UNKNOWN;
		return 0;
	}

	for (i = 0; i < esd->num; i++) {
		ret = b52_sensor_call(sensor, i2c_read,
					  esd->tab[i].reg, &val, 1);

		if (ret || val != esd->tab[i].val) {
			*status = SENSOR_ESD_ST_DAMAGED;
			return 0;
		}
	}

	*status = SENSOR_ESD_ST_WORKING;

	return 0;
}

/* ioctl(subdev, IOCTL_XXX, arg) is handled by this one */
static long b52_sensor_ioctl(struct v4l2_subdev *sd,
				unsigned int cmd, void *arg)
{
	int ret;
	enum OTP_TYPE org_otp_type;
	struct b52_sensor *sensor = to_b52_sensor(sd);

	switch (cmd) {
	case VIDIOC_PRIVATE_B52ISP_SENSOR_OTP:
		sensor->otp.user_otp = (struct sensor_otp *)arg;
		org_otp_type = sensor->otp.otp_type;
		sensor->otp.otp_type = sensor->otp.user_otp->otp_type;
		if (sensor->otp.otp_type == SENSOR_TO_ISP)
			ret = b52_sensor_reinit(sensor);
		ret = b52_sensor_call(sensor, update_otp, &sensor->otp);
		/*
		 * The sensor_init will call the update_otp as well
		 * and with the otp_type value set by kernel,
		 * so need set back the original otp_type.
		 */
		sensor->otp.otp_type = org_otp_type;
		sensor->otp.user_otp = NULL;
		break;
	case VIDIOC_PRIVATE_B52ISP_SENSOR_REINIT:
		ret = b52_sensor_reinit(sensor);
		break;
	case VIDIOC_PRIVATE_B52ISP_SENSOR_ESD_STATUS:
		ret = b52_sensor_esd_status(sensor, (int *)arg);
		break;
	default:
		pr_err("unknown compat ioctl '%c', dir=%d, #%d (0x%08x)\n",
			_IOC_TYPE(cmd), _IOC_DIR(cmd), _IOC_NR(cmd), cmd);
		return -ENXIO;
	}

	return ret;
}
#ifdef CONFIG_COMPAT
/* FIXME: need to refine return val */
static int b52_usercopy(struct v4l2_subdev *sd,
		unsigned int cmd, void *arg)
{
	char	sbuf[128];
	void    *mbuf = NULL;
	void	*parg = arg;
	long	err  = -EINVAL;

	/*  Copy arguments into temp kernel buffer  */
	if (_IOC_DIR(cmd) != _IOC_NONE) {
		if (_IOC_SIZE(cmd) <= sizeof(sbuf)) {
			parg = sbuf;
		} else {
			/* too big to allocate from stack */
			mbuf = kmalloc(_IOC_SIZE(cmd), GFP_KERNEL);
			if (NULL == mbuf)
				return -ENOMEM;
			parg = mbuf;
		}

		err = -EFAULT;
		if (_IOC_DIR(cmd) & _IOC_WRITE) {
			unsigned int n = _IOC_SIZE(cmd);

			if (copy_from_user(parg, (void __user *)arg, n))
				goto out;

			/* zero out anything we don't copy from userspace */
			if (n < _IOC_SIZE(cmd))
				memset((u8 *)parg + n, 0, _IOC_SIZE(cmd) - n);
		} else {
			/* read-only ioctl */
			memset(parg, 0, _IOC_SIZE(cmd));
		}
	}

	/* Handles IOCTL */
	err = v4l2_subdev_call(sd, core, ioctl, cmd, parg);
	if (err == -ENOIOCTLCMD)
		err = -ENOTTY;
	if (_IOC_DIR(cmd) & _IOC_READ) {
		unsigned int n = _IOC_SIZE(cmd);
		if (copy_to_user((void __user *)arg, parg, n))
			goto out;
	}
out:
	kfree(mbuf);
	return err;
}

struct sensor_otp32 {
	enum OTP_TYPE	otp_type;
	__u16	lsc_otp_len;
	__u16	wb_otp_len;
	__u16	vcm_otp_len;
	__u16   module_data_len;
	__u32	crc_status;
	compat_caddr_t	otp_data;
	compat_caddr_t	module_data;
	compat_caddr_t	full_otp;
	__u16	full_otp_len;
	__u16	full_otp_offset;
	compat_caddr_t	read_otp_len;
	__u8	erase_otp_len;
	__u8	erase_otp_base;
	__u32 rg_typical_ratio;
	__u32 bg_typical_ratio;
	__u32 gg_typical_ratio;
};

#define VIDIOC_PRIVATE_B52ISP_SENSOR_OTP32 \
	_IOWR('V', BASE_VIDIOC_PRIVATE + 11, struct sensor_otp32)

static int get_sensor_otp32(struct sensor_otp *kp,
		struct sensor_otp32 __user *up)
{
	u32 tmp1, tmp2, tmp3, tmp4;
	if (!access_ok(VERIFY_READ, up, sizeof(struct sensor_otp32)) ||
			get_user(tmp1, &up->otp_data) ||
			get_user(tmp2, &up->module_data) ||
			get_user(tmp3, &up->full_otp) ||
			get_user(tmp4, &up->read_otp_len) ||
			get_user(kp->otp_type, &up->otp_type) ||
			get_user(kp->lsc_otp_len, &up->lsc_otp_len) ||
			get_user(kp->wb_otp_len, &up->wb_otp_len) ||
			get_user(kp->vcm_otp_len, &up->vcm_otp_len) ||
			get_user(kp->module_data_len, &up->module_data_len) ||
			get_user(kp->full_otp_offset, &up->full_otp_offset) ||
			get_user(kp->full_otp_len, &up->full_otp_len) ||
			get_user(kp->crc_status, &up->crc_status) ||
			get_user(kp->erase_otp_len, &up->erase_otp_len) ||
			get_user(kp->erase_otp_base, &up->erase_otp_base) ||
			get_user(kp->rg_typical_ratio, &up->rg_typical_ratio) ||
			get_user(kp->bg_typical_ratio, &up->bg_typical_ratio) ||
			get_user(kp->gg_typical_ratio, &up->gg_typical_ratio))
		return -EFAULT;
	kp->otp_data = compat_ptr(tmp1);
	kp->module_data = compat_ptr(tmp2);
	kp->full_otp = compat_ptr(tmp3);
	kp->read_otp_len = compat_ptr(tmp4);
	return 0;
}

static long b52_sensor_ioctl32(struct v4l2_subdev *sd,
				unsigned int cmd, void *arg)
{
	int ret = 0;
	struct sensor_otp karg;
	int compatible_arg = 1;

	switch (cmd) {
	case VIDIOC_PRIVATE_B52ISP_SENSOR_OTP32:
		cmd = VIDIOC_PRIVATE_B52ISP_SENSOR_OTP;
		get_sensor_otp32(&karg, arg);
		compatible_arg = 0;
		break;
	case VIDIOC_PRIVATE_B52ISP_SENSOR_REINIT:
	case VIDIOC_PRIVATE_B52ISP_SENSOR_ESD_STATUS:
		break;
	default:
		pr_err("unknown compat ioctl '%c', dir=%d, #%d (0x%08x)\n",
			_IOC_TYPE(cmd), _IOC_DIR(cmd), _IOC_NR(cmd), cmd);
		return -ENXIO;
	}

	if (compatible_arg)
		ret = b52_usercopy(sd, cmd, arg);
	else {
		mm_segment_t old_fs = get_fs();

		set_fs(KERNEL_DS);
		ret = b52_usercopy(sd, cmd, (void *)&karg);
		set_fs(old_fs);
	}

	return ret;
}
#endif
static struct v4l2_subdev_core_ops b52_sensor_core_ops = {
	.s_power = b52_sensor_s_power,
	.ioctl	= b52_sensor_ioctl,
	.queryctrl = b52_sensor_queryctrl,
#ifdef CONFIG_COMPAT
	.compat_ioctl32 = b52_sensor_ioctl32,
#endif

};

static struct v4l2_subdev_ops b52_sensor_sd_ops = {
	.core   = &b52_sensor_core_ops,
	.pad    = &b52_sensor_pad_ops,
	.video  = &b52_sensor_video_ops,
	.sensor = &b52_sensor_sensor_ops,
};

static const struct v4l2_subdev_internal_ops b52_sensor_sd_internal_ops = {
	.open  = b52_sensor_sd_open,
	.close = b52_sensor_sd_close,
};

static const struct media_entity_operations sensor_media_ops = {
	.link_setup = b52_sensor_link_setup,
};

static int b52_detect_sensor(struct b52_sensor *sensor)
{
	int ret;

	if (!sensor) {
		pr_err("%s, error param\n", __func__);
		return -EINVAL;
	}

	ret = b52_sensor_call(sensor, get_power);
	if (ret)
		return ret;

	ret = v4l2_subdev_call(&sensor->sd, core, s_power, 1);
	if (ret) {
		pr_err("%s, sensor power up error\n", __func__);
		goto error;
	}

	ret = b52_sensor_call(sensor, detect_sensor);

	/* try to get the module id after detected the sensor. */
	if (!ret)
		b52_sensor_call(sensor, detect_module);

#if 0
	/* FIXME support detect sensor success while VCM detect error */
	ret |= b52_sensor_call(sensor, detect_vcm);
#endif
	v4l2_subdev_call(&sensor->sd, core, s_power, 0);
	if (ret)
		goto error;

	return 0;

error:
	b52_sensor_call(sensor, put_power);
	return ret;
}

static int b52_sensor_g_ctrl(struct v4l2_ctrl *ctrl)
{
	int i;
	struct b52_sensor *sensor = container_of(
			ctrl->handler, struct b52_sensor, ctrls.ctrl_hdl);

	switch (ctrl->id) {
	case V4L2_CID_HBLANK:
		i = sensor->cur_res_idx;
		ctrl->val = sensor->drvdata->res[i].hts -
			sensor->drvdata->res[i].width;
		break;

	case V4L2_CID_VBLANK:
		i = sensor->cur_res_idx;
		ctrl->val = sensor->drvdata->res[i].min_vts -
			sensor->drvdata->res[i].height;
		break;

	case V4L2_CID_PIXEL_RATE:
		ctrl->val64 = sensor->pixel_rate;
		break;

	default:
		pr_err("%s: ctrl not support\n", __func__);
		return -EINVAL;
	}

	pr_debug("G_CTRL %08x:%d\n", ctrl->id, ctrl->val);

	return 0;
}

static int b52_sensor_s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct b52_sensor *sensor = container_of(
			ctrl->handler, struct b52_sensor, ctrls.ctrl_hdl);

	/* FIXME: implement flash config and set function */
	switch (ctrl->id) {
	case V4L2_CID_VFLIP:
		b52_sensor_call(sensor, s_flip, 0, ctrl->val);
		break;

	case V4L2_CID_HFLIP:
		b52_sensor_call(sensor, s_flip, 1, ctrl->val);
		break;

	case V4L2_CID_PRIVATE_SENSOR_OTP_CONTROL:
		sensor->otp.otp_ctrl = ctrl->val;
		break;

	default:
		pr_err("%s: ctrl %x not support\n", __func__, ctrl->id);
		return -EINVAL;
	}

	return 0;
}

static struct v4l2_ctrl_ops b52_sensor_ctrl_ops = {
	.g_volatile_ctrl = b52_sensor_g_ctrl,
	.s_ctrl          = b52_sensor_s_ctrl,
};

static struct v4l2_ctrl_config b52_sensor_otp_ctrl_cfg = {
	.ops = &b52_sensor_ctrl_ops,
	.id = V4L2_CID_PRIVATE_SENSOR_OTP_CONTROL,
	.name = "B52 Sensor OTP Control",
	.type = V4L2_CTRL_TYPE_INTEGER,
	.min = V4L2_CID_SENSOR_OTP_CONTROL_NONE,
	.max = V4L2_CID_SENSOR_OTP_CONTROL_WB | V4L2_CID_SENSOR_OTP_CONTROL_LENC,
	.step = 1,
	.def = V4L2_CID_SENSOR_OTP_CONTROL_WB | V4L2_CID_SENSOR_OTP_CONTROL_LENC,
};

static int b52_s_ctrl(struct v4l2_ctrl *ctrl)
{
	int ret = 0;

	switch (ctrl->id) {
	case V4L2_CID_PRIVATE_B52_VIDEO_MODE:
		s_mode = ctrl->val;
		break;
	default:
		return -EINVAL;
	}

	return ret;
}
static const struct v4l2_ctrl_ops b52_ctrl_ops = {
	.s_ctrl = b52_s_ctrl,
};

static struct v4l2_ctrl_config b52_ctrl_video_mode_cfg = {
	.ops = &b52_ctrl_ops,
	.id = V4L2_CID_PRIVATE_B52_VIDEO_MODE,
	.name = "video mode",
	.type = V4L2_CTRL_TYPE_INTEGER,
	.min = VIDEO_TO_NORMAL,
	.max = VIDEO_TO_CALL,
	.step = 1,
	.def = VIDEO_TO_NORMAL,
};

static int b52_sensor_init_ctrls(struct b52_sensor *sensor)
{
	int i;
	u32 min = 0;
	u32 max = 0;
	struct v4l2_ctrl *ctrl;
	struct b52isp_sensor_ctrls *ctrls;
	const struct b52_sensor_data *data = sensor->drvdata;

	ctrls = &sensor->ctrls;

	v4l2_ctrl_handler_init(&ctrls->ctrl_hdl, 9);

	ctrls->hflip = v4l2_ctrl_new_std(&ctrls->ctrl_hdl,
			&b52_sensor_ctrl_ops,
			V4L2_CID_HFLIP, 0, 1, 1, 0);

	ctrls->vflip = v4l2_ctrl_new_std(&ctrls->ctrl_hdl,
			&b52_sensor_ctrl_ops,
			V4L2_CID_VFLIP, 0, 1, 1, 0);

	ctrl = v4l2_ctrl_new_std(&ctrls->ctrl_hdl,
			&b52_sensor_ctrl_ops,
			V4L2_CID_ANALOGUE_GAIN,
			data->gain_range[B52_SENSOR_AG].min,
			data->gain_range[B52_SENSOR_AG].max, 1,
			data->gain_range[B52_SENSOR_AG].min);
	if (ctrl != NULL)
		ctrl->flags |= V4L2_CTRL_FLAG_VOLATILE |
			V4L2_CTRL_FLAG_READ_ONLY;

/* FIXME: use vts not vb */
	ctrl = v4l2_ctrl_new_std(&ctrls->ctrl_hdl,
			&b52_sensor_ctrl_ops,
			V4L2_CID_VBLANK, data->vts_range.min,
			data->vts_range.max, 1, data->vts_range.min);
	if (ctrl != NULL)
		ctrl->flags |= V4L2_CTRL_FLAG_VOLATILE |
			V4L2_CTRL_FLAG_READ_ONLY;

	ctrl = v4l2_ctrl_new_std(&ctrls->ctrl_hdl,
			&b52_sensor_ctrl_ops,
			V4L2_CID_FOCUS_ABSOLUTE, data->focus_range.min,
			data->focus_range.max, 1, data->focus_range.min);
	if (ctrl != NULL)
		ctrl->flags |= V4L2_CTRL_FLAG_VOLATILE |
			V4L2_CTRL_FLAG_READ_ONLY;

	if (sensor->drvdata->num_res > 0)
		min = max = sensor->drvdata->res[0].hts -
			sensor->drvdata->res[0].width;
	for (i = 1; i < sensor->drvdata->num_res; i++) {
		min = min_t(u32, min, sensor->drvdata->res[i].hts
				- sensor->drvdata->res[i].width);
		max = max_t(u32, max, sensor->drvdata->res[i].hts
				- sensor->drvdata->res[i].width);
	}
	ctrl = v4l2_ctrl_new_std(&ctrls->ctrl_hdl,
			&b52_sensor_ctrl_ops,
			V4L2_CID_HBLANK, min, max, 1, min);
	if (ctrl != NULL)
		ctrl->flags |= V4L2_CTRL_FLAG_VOLATILE |
			V4L2_CTRL_FLAG_READ_ONLY;

	ctrl = v4l2_ctrl_new_std(&ctrls->ctrl_hdl,
			&b52_sensor_ctrl_ops,
			V4L2_CID_PIXEL_RATE, 0, 0, 1, 0);
	if (ctrl != NULL)
		ctrl->flags |= V4L2_CTRL_FLAG_VOLATILE |
			V4L2_CTRL_FLAG_READ_ONLY;

	v4l2_ctrl_new_custom(&ctrls->ctrl_hdl, &b52_sensor_otp_ctrl_cfg, NULL);

	v4l2_ctrl_new_custom(&ctrls->ctrl_hdl, &b52_ctrl_video_mode_cfg, NULL);
	sensor->sd.ctrl_handler = &ctrls->ctrl_hdl;

	return ctrls->ctrl_hdl.error;
}

static int b52_sensor_alloc_fmt_regs(struct b52_sensor *sensor)
{
	int i;
	u32 reg_num = 0;
	u32 total_reg_num = 0;

	for (i = 0; i < sensor->drvdata->num_res; i++)
		reg_num = max_t(u32, reg_num,
			sensor->drvdata->res[i].regs.num);

	total_reg_num = reg_num;
	reg_num = 0;

	for (i = 0; i < sensor->drvdata->num_mbus_fmt; i++)
		reg_num = max_t(u32,
			reg_num, sensor->drvdata->mbus_fmt[i].regs.num);

	total_reg_num += reg_num;

	sensor->mf_regs.tab = devm_kzalloc(sensor->dev,
		total_reg_num * sizeof(struct regval_tab), GFP_KERNEL);

	if (!sensor->mf_regs.tab) {
		pr_err("%s failed\n", __func__);
		return -ENOMEM;
	}

	return 0;
}

static const struct of_device_id fimc_is_sensor_of_match[];
static const struct of_device_id b52_sensor_of_match[];

static int b52_sensor_probe(struct i2c_client *client,
				const struct i2c_device_id *id)
{
	int ret = 0;
	struct device *dev = &client->dev;
	struct b52_sensor *sensor;
	const struct of_device_id *of_id;
	struct v4l2_subdev *sd;
	struct device_node *np = dev->of_node;
	u32 skip_detect;

	of_id = of_match_node(b52_sensor_of_match, dev->of_node);
	if (!of_id)
		return -ENODEV;

	sensor = devm_kzalloc(dev, sizeof(*sensor), GFP_KERNEL);
	if (!sensor)
		return -ENOMEM;

	sensor->drvdata = of_id->data;
	sensor->dev = dev;

	if (of_get_property(np, "sc2-i2c-dyn-ctrl", NULL))
		sensor->i2c_dyn_ctrl = 1;

	/* default the board prop is DKB */
	if (of_get_property(np, "pxa1908_cmtb_board", NULL))
		sensor->board_prop_id = 1;

	ret = of_property_read_u32(np, "sensor-pos", (u32 *)&sensor->pos);
	if (ret < 0) {
		dev_err(dev, "failed to get sensor position, errno %d\n", ret);
		return ret;
	}

	ret = of_property_read_u32(np, "mclk", &sensor->mclk);
	if (ret < 0) {
		dev_err(dev, "failed to get mclk, errno %d\n", ret);
		return ret;
	}
	sensor->clk = devm_clk_get(dev, "SC2MCLK");
	if (IS_ERR(sensor->clk)) {
		dev_err(dev, "failed to get SC2MCLK clock\n");
		return -ENODEV;
	}
	sensor->csi.dphy_desc.nr_lane = sensor->drvdata->nr_lane;
	if (!sensor->csi.dphy_desc.nr_lane) {
		dev_err(dev, "the csi lane number is zero\n");
		return -EINVAL;
	}
	sensor->csi.dphy_desc.clk_freq = sensor->drvdata->mipi_clk_bps >> 1;
	if (sensor->csi.dphy_desc.clk_freq > 1500 * MHZ ||
		sensor->csi.dphy_desc.clk_freq < MHZ) {
		dev_err(dev, "the mipi clock maybe wrong %s\n",
				sensor->drvdata->name);
		return -EINVAL;
	}
	sensor->csi.calc_dphy = sensor->drvdata->calc_dphy;
	if (!sensor->csi.calc_dphy) {
		ret = of_property_read_u32(np, "dphy3", &sensor->csi.dphy[0]);
		if (ret < 0) {
			dev_err(dev, "failed to dphy3, errno %d\n", ret);
			return ret;
		}
		ret = of_property_read_u32(np, "dphy5", &sensor->csi.dphy[1]);
		if (ret < 0) {
			dev_err(dev, "failed to dphy5, errno %d\n", ret);
			return ret;
		}
		ret = of_property_read_u32(np, "dphy6", &sensor->csi.dphy[2]);
		if (ret < 0) {
			dev_err(dev, "failed to dphy6, errno %d\n", ret);
			return ret;
		}
	}

	sd = &sensor->sd;
	v4l2_i2c_subdev_init(sd, client, &b52_sensor_sd_ops);
	sd->internal_ops = &b52_sensor_sd_internal_ops;
	if (strlen(sensor->drvdata->name) > 15)
		dev_err(dev, "The sensor name:%s is too long!\n",
			sensor->drvdata->name);
	sprintf(sd->name, "sensor:%s", sensor->drvdata->name);
	sensor->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;

	b52_sensor_set_defalut(sensor);

	ret = of_property_read_u32(np, "assume_exist", &skip_detect);
	if ((!(ret < 0)) && skip_detect) {
		dev_info(dev, "ASSUME %s detected\n", of_id->compatible);
		goto detect_done;
	}
	ret = b52_detect_sensor(sensor);
	if (ret)
		return ret;
detect_done:
	/* add the module name into subdev name if it be detected */
	if (sensor->drvdata->module && sensor->drvdata->num_module > 0) {
		if (sensor->cur_mod_id >= 0 && sensor->cur_mod_id <= 255
			&& sensor->drvdata->module[sensor->cur_mod_id].name) {
			if (strlen(sd->name) +
				strlen(sensor->drvdata->module[sensor->cur_mod_id].name) >
				V4L2_SUBDEV_NAME_SIZE - 2)
				dev_err(dev, "The sensor/module name is too long, can't make them together.\n");
			else {
				sd->name[strlen(sd->name)] = ',';
				strncat(sd->name, sensor->drvdata->module[sensor->cur_mod_id].name,
					strlen(sensor->drvdata->module[sensor->cur_mod_id].name));
				sd->name[V4L2_SUBDEV_NAME_SIZE - 1] = '\0';
				dev_info(dev, "The subdev name with module name: %s\n", sd->name);
			}
		} else
			dev_err(dev, "can't get the module name, check the module support list.\n");
	}
	ret = b52_sensor_alloc_fmt_regs(sensor);
	if (ret)
		return ret;

	ret = b52_sensor_init_ctrls(sensor);
	if (ret)
		goto error;

	BLOCKING_INIT_NOTIFIER_HEAD(&sensor->nh);
	mutex_init(&sensor->lock);

	sensor->pad.flags = MEDIA_PAD_FL_SOURCE;
	sd->entity.ops = &sensor_media_ops;
	sd->entity.type = MEDIA_ENT_T_V4L2_SUBDEV_SENSOR;
	ret = media_entity_init(&sd->entity, 1, &sensor->pad, 0);
	if (ret)
		goto error;
	return ret;
#if 0
	sensor->mf.code = data->mbus_fmt[0].mbus_code;
	sensor->mf.colorspace = data->mbus_fmt[0].colorspace;
	sensor->mf.width = data->res[0].width;
	sensor->mf.height = data->res[0].height;
	sensor->mf.filed = V4L2_FIELD_NONE;
#endif
error:
	v4l2_ctrl_handler_free(&sensor->ctrls.ctrl_hdl);

	return ret;
}

static int b52_sensor_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct b52_sensor *sensor = to_b52_sensor(sd);

	b52_sensor_call(sensor, put_power);
	v4l2_ctrl_handler_free(&sensor->ctrls.ctrl_hdl);
	media_entity_cleanup(&sd->entity);
	v4l2_device_unregister_subdev(sd);
	devm_kfree(sensor->dev, sensor);

	return 0;
}

#define DRIVER_NAME "b52-sensor"
static const struct i2c_device_id b52_sensor_ids[] = {
	{ }
};

static const struct of_device_id b52_sensor_of_match[] = {
#ifdef CONFIG_B52_CAMERA_IMX219
	{
		.compatible	= "sony,imx219",
		.data       = &b52_imx219,
	},
#endif
#ifdef CONFIG_B52_CAMERA_OV5642
	{
		.compatible	= "ovt,ov5642",
		.data       = &b52_ov5642,
	},
#endif
#ifdef CONFIG_B52_CAMERA_OV13850
	{
		.compatible	= "ovt,ov13850",

#ifdef CONFIG_B52_CAMERA_OV13850_13M
		.data       = &b52_ov13850_13M,
#else
		.data       = &b52_ov13850_8M,
#endif
	},
#endif
#ifdef CONFIG_B52_CAMERA_OV13850R2A
	{
		.compatible	= "ovt,ov13850r2a",
		.data       = &b52_ov13850r2a_13M,
	},
#endif
#ifdef CONFIG_B52_CAMERA_OV8858
	{
		.compatible = "ovt,ov8858r2a",
		.data = &b52_ov8858,
	},
#endif

#ifdef CONFIG_B52_CAMERA_OV8858_FRONT
	{
		.compatible = "ovt,ov8858r2a_front",
		.data = &b52_ov8858_front,
	},
#endif
#ifdef CONFIG_B52_CAMERA_OV5648
	{
		.compatible = "ovt,ov5648",
		.data = &b52_ov5648,
	},
#endif
#ifdef CONFIG_B52_CAMERA_OV2680
	{
		.compatible = "ovt,ov2680",
		.data = &b52_ov2680,
	},
#endif
#ifdef CONFIG_B52_CAMERA_SR544
	{
		.compatible = "samsung,sr544",
		.data = &b52_sr544,
	},
#endif
#ifdef CONFIG_B52_CAMERA_HI551
	{
		.compatible = "hynix,hi551",
		.data = &b52_hi551,
	},
#endif
#ifdef CONFIG_B52_CAMERA_S5K5E3
	{
		.compatible = "samsung,s5k5e3",
		.data = &b52_s5k5e3,
	},
#endif
#ifdef CONFIG_B52_CAMERA_OV5670
	{
		.compatible = "ovt,ov5670",
		.data = &b52_ov5670,
	},
#endif
#ifdef CONFIG_B52_CAMERA_S5K3L2
	{
		.compatible = "samsung,s5k3l2",
		.data = &b52_s5k3l2,
	},
#endif
#ifdef CONFIG_B52_CAMERA_S5K4H5
	{
		.compatible = "samsung,s5k4h5",
		.data = &b52_s5k4h5,
	},
#endif
#ifdef CONFIG_B52_CAMERA_OV8865
	{
		.compatible = "ovt,ov8865",
		.data = &b52_ov8865,
	},
#endif
	{  }
};

const struct b52_sensor_data *memory_sensor_match(char *sensor_name)
{
	int i;

	if (!sensor_name) {
		pr_err("%s, parameter is NULL\n", __func__);
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(b52_sensor_of_match); i++)
		if (!strcmp(sensor_name, b52_sensor_of_match[i].compatible))
			return b52_sensor_of_match[i].data;

	return NULL;
}
EXPORT_SYMBOL(memory_sensor_match);

static struct i2c_driver b52_sensor_driver = {
	.driver = {
		.of_match_table	= b52_sensor_of_match,
		.name		= DRIVER_NAME,
		.owner		= THIS_MODULE,
	},
	.probe		= b52_sensor_probe,
	.remove		= b52_sensor_remove,
	.id_table	= b52_sensor_ids,
};

module_i2c_driver(b52_sensor_driver);

MODULE_DESCRIPTION("A common b52 sensor driver");
MODULE_AUTHOR("Jianle Wang <wangjl@marvell.com>");
MODULE_LICENSE("GPL");
