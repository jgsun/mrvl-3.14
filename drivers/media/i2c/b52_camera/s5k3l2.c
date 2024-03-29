/* Marvell ISP S5K3L2 Driver
 *
 * Copyright (C) 2009-2010 Marvell International Ltd.
 *
 * Based on mt9v011 -Micron 1/4-Inch VGA Digital Image OV5642
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
#include <linux/crc32.h>
#include "s5k3l2.h"
#include <media/mv_sc2_twsi_conf.h>
#include <linux/clk.h>
static int S5K3L2_get_mipiclock(struct v4l2_subdev *sd, u32 *rate, u32 mclk)
{
	u32 op_sys_clk_div;
	u32 secnd_pll_mul;
	u32 secnd_pre_pll_div;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	b52_sensor_call(sensor, i2c_read, 0x030a, &op_sys_clk_div, 1);
	b52_sensor_call(sensor, i2c_read, 0x030e, &secnd_pll_mul, 1);
	b52_sensor_call(sensor, i2c_read, 0x030c, &secnd_pre_pll_div, 1);
	*rate = mclk / op_sys_clk_div * secnd_pll_mul / secnd_pre_pll_div / 2;
	return 0;
}

static int S5K3L2_get_dphy_desc(struct v4l2_subdev *sd,
			struct csi_dphy_desc *dphy_desc, u32 mclk)
{
	S5K3L2_get_mipiclock(sd, &dphy_desc->clk_freq, mclk);
	dphy_desc->hs_prepare = 58;
	dphy_desc->hs_zero  = 100;

	return 0;
}
static int S5K3L2_get_pixelclock(struct v4l2_subdev *sd, u32 *rate, u32 mclk)
{
	u32 pll_mul;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	b52_sensor_call(sensor, i2c_read, 0x0306, &pll_mul, 1);
	*rate = mclk / 8 * pll_mul / 2;
	return 0;
}
static char S5K3L2_vcm_read_reg(struct v4l2_subdev *sd, char reg)
{
	const struct b52_sensor_i2c_attr attr = {
		.reg_len = I2C_8BIT,
		.val_len = I2C_8BIT,
		.addr = 0x0c,
	};
	struct b52_cmd_i2c_data data;
	struct regval_tab tab;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	data.attr = &attr;
	data.tab = &tab;
	data.num = 1;
	data.pos = sensor->pos;

	tab.reg = reg;
	tab.mask = 0xff;
	b52_cmd_read_i2c(&data);
	return tab.val;
}
static char S5K3L2_eflash_read_reg(struct v4l2_subdev *sd, short reg)
{
	const struct b52_sensor_i2c_attr attr = {
		.reg_len = I2C_16BIT,
		.val_len = I2C_8BIT,
		.addr = 0x58,
	};
	struct b52_cmd_i2c_data data;
	struct regval_tab tab;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	data.attr = &attr;
	data.tab = &tab;
	data.num = 1;
	data.pos = sensor->pos;

	tab.reg = reg;
	tab.mask = 0xff;
	b52_cmd_read_i2c(&data);
	return tab.val;
}
static void S5K3L2_eflash_write_reg(struct v4l2_subdev *sd, short reg, char val)
{
	const struct b52_sensor_i2c_attr attr = {
		.reg_len = I2C_16BIT,
		.val_len = I2C_8BIT,
		.addr = 0x58,
	};
	struct b52_cmd_i2c_data data;
	struct regval_tab tab;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	data.attr = &attr;
	data.tab = &tab;
	data.num = 1;
	data.pos = sensor->pos;

	tab.reg = reg;
	tab.val = val;
	tab.mask = 0xff;
	b52_cmd_write_i2c(&data);
	return;
}
#define ER BIT(7)
#define PG BIT(1)
#define EFLSH_PAGE_SIZE 1024
static void S5K3L2_erase_page(struct v4l2_subdev *sd, char page)
{
	char val =  0;
	const struct b52_sensor_i2c_attr attr = {
		.reg_len = I2C_8BIT,
		.val_len = I2C_8BIT,
		.addr = 0x58,
	};
	struct b52_cmd_i2c_data data;
	struct regval_tab tab;
	struct b52_sensor *sensor = to_b52_sensor(sd);
	data.attr = &attr;
	data.tab = &tab;
	data.num = 1;
	data.pos = sensor->pos;

	val = ER | PG | (page<<2);
	tab.reg = val;
	tab.val = 0xee;
	tab.mask = 0xff;
	/* wait for last step over */
	do
		usleep_range(100, 300);
	while (S5K3L2_vcm_read_reg(sd, 0x05) & 0x02);

	b52_cmd_write_i2c(&data);
	/* wait for last step over */
	do
		usleep_range(2500, 3000);
	while (S5K3L2_vcm_read_reg(sd, 0x05) & 0x02);
}
static int S5K3L2_otp_write(struct v4l2_subdev *sd,
		unsigned int offset, char *buffer, int len)
{
	unsigned short head, tail, tmp_addr;
	char *tmp_buffer;
	int i = 0;
	head = rounddown(offset, EFLSH_PAGE_SIZE);
	tail = roundup(offset + len, EFLSH_PAGE_SIZE);
	if (buffer == NULL || len == 0)
		return -EINVAL;
	tmp_buffer =  devm_kzalloc(sd->dev, tail - head, GFP_KERNEL);
	/* read the  head */
	tmp_addr = head;
	while (tmp_addr < offset)
		tmp_buffer[i++] = S5K3L2_eflash_read_reg(sd, tmp_addr++);
	/* read the  tail */
	tmp_addr = offset + len;
	i = len + offset - head;
	while (tmp_addr < tail)
		tmp_buffer[i++] = S5K3L2_eflash_read_reg(sd, tmp_addr++);
	/* fill the buffer */
	tmp_addr = offset - head;
	i = 0;
	while (i < len)
		tmp_buffer[tmp_addr++] = buffer[i++];
	tmp_addr = head;
	while (tmp_addr < tail) {
		S5K3L2_erase_page(sd, tmp_addr>>10);
		tmp_addr += EFLSH_PAGE_SIZE;
	}

	tmp_addr = head;
	i = 0;
	while (tmp_addr < tail)
		S5K3L2_eflash_write_reg(sd, tmp_addr++, tmp_buffer[i++]);

	return 0;
}
#define GROUP1_LEN 0x100
#define GROUP2_LEN 0x800
#define GROUP3_LEN 0x100
#define GROUP4_LEN 0x800

#define MODULE_OFFSET	0x08b0
#define AF_OFFSET	0x0100
#define GWB_OFFSET	0x0140
#define WB_OFFSET	0x0900
#define LSC_OFFSET	0x0a0c
static int S5K3L2_read_data(struct v4l2_subdev *sd,
				struct b52_sensor_otp *otp)
{
	int i, len, tmp_len = 0;
	int ret = 0;
	char *paddr = NULL;
	ushort bank_addr;
	char *bank_grp1 = devm_kzalloc(sd->dev, GROUP1_LEN, GFP_KERNEL);
	char *bank_grp2 = devm_kzalloc(sd->dev, GROUP2_LEN, GFP_KERNEL);
	char *bank_grp3 = devm_kzalloc(sd->dev, GROUP3_LEN, GFP_KERNEL);
	char *bank_grp4 = devm_kzalloc(sd->dev, GROUP4_LEN, GFP_KERNEL);
	len = otp->user_otp->module_data_len;
	if (len > 0) {
		bank_addr = MODULE_OFFSET;
		for (i = 0; i < len; i++)
			bank_grp1[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
		paddr = otp->user_otp->module_data;
		if (copy_to_user(paddr, &bank_grp1[0],
							len)) {
			ret = -EIO;
			goto err;
		}
	}
	len = otp->user_otp->vcm_otp_len;
	if (len != 0 || otp->user_otp->wb_otp_len != 0) {
		bank_addr =  AF_OFFSET;
		for (i = 0; i < len; i++)
			bank_grp2[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
		if (len > 0) {
			paddr = (char *)otp->user_otp->otp_data + tmp_len;
			if (copy_to_user(paddr,
					&bank_grp2[0],
					len)) {
				ret = -EIO;
				goto err;
			}
			tmp_len += len;
		}
		len = otp->user_otp->wb_otp_len/2;
		bank_addr =  GWB_OFFSET;
		for (i = 0; i < len; i++)
			bank_grp2[i] =  S5K3L2_eflash_read_reg(sd, bank_addr++);
		if (len > 0) {
			paddr = (char *) otp->user_otp->otp_data + tmp_len;
			if (copy_to_user(paddr,
				&bank_grp2[0], len)) {
				ret = -EIO;
				goto err;
			}
			tmp_len += len;
		}
	}
	len = otp->user_otp->wb_otp_len/2;
	if (len > 0) {
		bank_addr =  WB_OFFSET;
		for (i = 0; i < len; i++)
			bank_grp3[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
		paddr = (char *)otp->user_otp->otp_data + tmp_len;
		if (copy_to_user(paddr,
				&bank_grp3[0], len)) {
			ret = -EIO;
			goto err;
		}
		tmp_len += len;
	}
	len = otp->user_otp->lsc_otp_len;
	if (len > 0) {
		bank_addr =  LSC_OFFSET;
		for (i = 0; i < len; i++)
			bank_grp4[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
		paddr = (char *)(otp->user_otp->otp_data + tmp_len);
		if (copy_to_user(paddr, &bank_grp4[0], len)) {
			ret = -EIO;
			goto err;
		}
	}
err:
	devm_kfree(sd->dev, bank_grp1);
	devm_kfree(sd->dev, bank_grp2);
	devm_kfree(sd->dev, bank_grp3);
	devm_kfree(sd->dev, bank_grp4);
	return ret;
}

static void makeCRCtable(unsigned long *table, unsigned long id)
{
	unsigned long i, j, k;
	for (i = 0; i < 256; ++i) {
		k = i;
		for (j = 0; j < 8; ++j) {
			if (k & 1)
				k = (k >> 1) ^ id;
			else
				k >>= 1;
		}
		table[i] = k;
	}
}

static unsigned long getCRC(unsigned short *mem, signed long count,
	unsigned short *crcH, unsigned short *crcL, unsigned long *table)
{
	unsigned long CRC = 0;
	unsigned char mem0, mem1;
	int i;
	CRC = ~CRC;
	for (i = 0; i < count; i++) {
		mem0 = (unsigned char)(mem[i] & 0x00ff);
		mem1 = (unsigned char)((mem[i] >> 8) & 0x00ff);
		CRC = table[(CRC ^ (mem0)) & 0xFF] ^ (CRC >> 8);
		CRC = table[(CRC ^ (mem1)) & 0xFF] ^ (CRC >> 8);
	}
	CRC = ~CRC;
	if (crcH)
		*crcH = (unsigned short)((CRC >> 16) & (0x0000ffff));
	if (crcL)
		*crcL = (unsigned short)((CRC) & (0x0000ffff));
	return CRC;
}


static int S5K3L2_verify_crc(struct v4l2_subdev *sd,
				struct b52_sensor_otp *otp)
{
	int i;
	int ret = 0;
	unsigned short crcH, crcL;
	unsigned short tmpH, tmpL;
	ushort bank_addr;
	unsigned long *table =  devm_kzalloc(sd->dev,
					256 * sizeof(long), GFP_KERNEL);
	char *bank_grp1 = devm_kzalloc(sd->dev, GROUP1_LEN, GFP_KERNEL);
	char *bank_grp2 = devm_kzalloc(sd->dev, GROUP2_LEN, GFP_KERNEL);
	char *bank_grp3 = devm_kzalloc(sd->dev, GROUP3_LEN, GFP_KERNEL);
	char *bank_grp4 = devm_kzalloc(sd->dev, GROUP4_LEN, GFP_KERNEL);
	makeCRCtable(table, 0xEDB88320);
	bank_addr = 0;
	for (i = 0; i < GROUP1_LEN; i++)
		bank_grp1[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
	getCRC((unsigned short *)bank_grp1,
				GROUP1_LEN / 2 - 2, &crcH, &crcL, table);

	tmpL = bank_grp1[GROUP1_LEN - 4] | (bank_grp1[GROUP1_LEN - 3]  << 8);
	tmpH = bank_grp1[GROUP1_LEN - 2] | (bank_grp1[GROUP1_LEN - 1]  << 8);
	if (tmpL != crcL || tmpH != crcH) {
		ret = 2;
		pr_err("verify the group1 crc fail\n");
		goto out;
	}
	bank_addr = GROUP1_LEN;
	for (i = 0; i < GROUP2_LEN; i++)
		bank_grp2[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
	getCRC((unsigned short *)bank_grp2,
				GROUP2_LEN / 2 - 2, &crcH, &crcL, table);

	tmpL = bank_grp2[GROUP2_LEN - 4] | (bank_grp2[GROUP2_LEN - 3]  << 8);
	tmpH = bank_grp2[GROUP2_LEN - 2] | (bank_grp2[GROUP2_LEN - 1]  << 8);
	if (tmpL != crcL || tmpH != crcH) {
		ret = 2;
		pr_err("verify the group2 crc fail\n");
		goto out;
	}
	bank_addr = GROUP1_LEN + GROUP2_LEN;
	for (i = 0; i < GROUP3_LEN; i++)
		bank_grp3[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
	getCRC((unsigned short *)bank_grp3,
				GROUP3_LEN / 2 - 2, &crcH, &crcL, table);

	tmpL = bank_grp3[GROUP3_LEN - 4] | (bank_grp3[GROUP3_LEN - 3]  << 8);
	tmpH = bank_grp3[GROUP3_LEN - 2] | (bank_grp3[GROUP3_LEN - 1]  << 8);
	if (tmpL != crcL || tmpH != crcH) {
		ret = 2;
		pr_err("verify the group3 crc fail\n");
		goto out;
	}
	bank_addr = GROUP1_LEN + GROUP2_LEN + GROUP3_LEN;
	for (i = 0; i < GROUP4_LEN; i++)
		bank_grp4[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
	getCRC((unsigned short *)bank_grp4,
				GROUP4_LEN / 2 - 2, &crcH, &crcL, table);

	tmpL = bank_grp4[GROUP4_LEN - 4] | (bank_grp4[GROUP4_LEN - 3]  << 8);
	tmpH = bank_grp4[GROUP4_LEN - 2] | (bank_grp4[GROUP4_LEN - 1]  << 8);
	if (tmpL != crcL || tmpH != crcH) {
		ret = 2;
		pr_err("verify the group4 crc fail\n");
		goto out;
	}
out:
	otp->user_otp->crc_status = ret;
	devm_kfree(sd->dev, bank_grp1);
	devm_kfree(sd->dev, bank_grp2);
	devm_kfree(sd->dev, bank_grp3);
	devm_kfree(sd->dev, bank_grp4);
	devm_kfree(sd->dev, table);
	return 0;
}

static int S5K3L2_gen_crc(struct v4l2_subdev *sd,
				struct b52_sensor_otp *otp)
{
	int i;
	unsigned short crcH, crcL;
	unsigned char crcGen[4];
	ushort bank_addr;
	unsigned long *table =  devm_kzalloc(sd->dev,
					256 * sizeof(long), GFP_KERNEL);
	char *bank_grp1 = devm_kzalloc(sd->dev, GROUP1_LEN, GFP_KERNEL);
	char *bank_grp2 = devm_kzalloc(sd->dev, GROUP2_LEN, GFP_KERNEL);
	char *bank_grp3 = devm_kzalloc(sd->dev, GROUP3_LEN, GFP_KERNEL);
	char *bank_grp4 = devm_kzalloc(sd->dev, GROUP4_LEN, GFP_KERNEL);
	makeCRCtable(table, 0xEDB88320);

	bank_addr = 0;
	for (i = 0; i < GROUP1_LEN; i++)
		bank_grp1[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
	getCRC((unsigned short *)bank_grp1,
				GROUP1_LEN / 2 - 2, &crcH, &crcL, table);
	crcGen[0] = crcL & 0xff;
	crcGen[1] = (crcL >> 8) & 0xff;
	crcGen[2] = crcH & 0xff;
	crcGen[3] = (crcH >> 8) & 0xff;
	S5K3L2_otp_write(sd, GROUP1_LEN - 4, crcGen, 4);
	bank_addr = GROUP1_LEN;
	for (i = 0; i < GROUP2_LEN; i++)
		bank_grp2[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
	getCRC((unsigned short *)bank_grp2,
				GROUP2_LEN / 2 - 2, &crcH, &crcL, table);
	crcGen[0] = crcL & 0xff;
	crcGen[1] = (crcL >> 8) & 0xff;
	crcGen[2] = crcH & 0xff;
	crcGen[3] = (crcH >> 8) & 0xff;
	S5K3L2_otp_write(sd, GROUP1_LEN + GROUP2_LEN - 4, crcGen, 4);

	bank_addr = GROUP1_LEN + GROUP2_LEN;
	for (i = 0; i < GROUP3_LEN; i++)
		bank_grp3[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
	getCRC((unsigned short *)bank_grp3,
				GROUP3_LEN / 2 - 2, &crcH, &crcL, table);
	crcGen[0] = crcL & 0xff;
	crcGen[1] = (crcL >> 8) & 0xff;
	crcGen[2] = crcH & 0xff;
	crcGen[3] = (crcH >> 8) & 0xff;
	S5K3L2_otp_write(sd, GROUP1_LEN + GROUP2_LEN
					+ GROUP3_LEN - 4, crcGen, 4);

	bank_addr = GROUP1_LEN + GROUP2_LEN + GROUP3_LEN;
	for (i = 0; i < GROUP4_LEN; i++)
		bank_grp4[i] = S5K3L2_eflash_read_reg(sd, bank_addr++);
	getCRC((unsigned short *)bank_grp4,
				GROUP4_LEN / 2 - 2, &crcH, &crcL, table);
	crcGen[0] = crcL & 0xff;
	crcGen[1] = (crcL >> 8) & 0xff;
	crcGen[2] = crcH & 0xff;
	crcGen[3] = (crcH >> 8) & 0xff;
	S5K3L2_otp_write(sd, GROUP1_LEN + GROUP2_LEN
				+ GROUP3_LEN + GROUP4_LEN - 4, crcGen, 4);

	devm_kfree(sd->dev, bank_grp1);
	devm_kfree(sd->dev, bank_grp2);
	devm_kfree(sd->dev, bank_grp3);
	devm_kfree(sd->dev, bank_grp4);
	devm_kfree(sd->dev, table);
	return 0;
}

static int S5K3L2_update_otp(struct v4l2_subdev *sd,
				struct b52_sensor_otp *otp)
{
	int ret =  -1;
	char *module_id;
	char *tmp_write = NULL;
	if (otp->user_otp == NULL)
		return -EINVAL;
	if (otp->otp_type ==  ISP_TO_SENSOR) {
		if (otp->user_otp->module_data_len)
			S5K3L2_otp_write(sd, MODULE_OFFSET,
						otp->user_otp->module_data,
						otp->user_otp->module_data_len);
		if (otp->user_otp->vcm_otp_len)
			S5K3L2_otp_write(sd, AF_OFFSET,
						otp->user_otp->otp_data,
						otp->user_otp->vcm_otp_len);
		tmp_write = otp->user_otp->otp_data +
					otp->user_otp->vcm_otp_len;
		if (otp->user_otp->wb_otp_len)
			S5K3L2_otp_write(sd, GWB_OFFSET,
						tmp_write,
						otp->user_otp->wb_otp_len);
		tmp_write = otp->user_otp->otp_data +
					otp->user_otp->vcm_otp_len +
					otp->user_otp->wb_otp_len;
		if (otp->user_otp->lsc_otp_len)
			S5K3L2_otp_write(sd, LSC_OFFSET,
						tmp_write,
						otp->user_otp->lsc_otp_len);
		if (otp->user_otp->full_otp_len)
			S5K3L2_otp_write(sd, otp->user_otp->full_otp_offset,
					otp->user_otp->full_otp,
					otp->user_otp->full_otp_len);
		return 0;
	}
	if (otp->otp_type ==  SENSOR_TO_ISP) {
		module_id = otp->user_otp->module_data;
		ret = S5K3L2_read_data(sd, otp);
		if (otp->user_otp->module_data_len > 0)
			pr_err("Marvell_Unifiled_OTP_ID_INF for S5K3L2: Module=0x%x, Lens=0x%x, VCM=0x%x, DriverIC=0x%x\n",
				*module_id, 0, 0, 0);
		return ret;
	}
	if (otp->otp_type ==  VERIFY_CRC)
		ret = S5K3L2_verify_crc(sd, otp);
	if (otp->otp_type ==  GEN_CRC)
		ret = S5K3L2_gen_crc(sd, otp);
	return ret;
}

static int S5K3L2_s_power(struct v4l2_subdev *sd, int on)
{
	int ret = 0;
	int reset_delay = 100;
	struct sensor_power *power;
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	struct b52_sensor *sensor = to_b52_sensor(sd);

	power = (struct sensor_power *) &(sensor->power);
	if (on) {
		if (power->ref_cnt++ > 0)
			return 0;
		power->pwdn = devm_gpiod_get(&client->dev, "pwdn");
		if (IS_ERR(power->pwdn)) {
			dev_warn(&client->dev, "Failed to get gpio pwdn\n");
			power->pwdn = NULL;
		} else {
			ret = gpiod_direction_output(power->pwdn, 0);
			if (ret < 0) {
				dev_err(&client->dev, "Failed to set gpio pwdn\n");
				goto st_err;
			}
		}

		power->rst = devm_gpiod_get(&client->dev, "reset");
		if (IS_ERR(power->rst)) {
			dev_warn(&client->dev, "Failed to get gpio reset\n");
			power->rst = NULL;
		} else {
			ret = gpiod_direction_output(power->rst, 0);
			if (ret < 0) {
				dev_err(&client->dev, "Failed to set gpio rst\n");
				goto rst_err;
			}
		}
		if (power->dovdd_1v8) {
			regulator_set_voltage(power->dovdd_1v8,
						1800000, 1800000);
			ret = regulator_enable(power->dovdd_1v8);
			if (ret < 0)
				goto dovdd_err;
		}
		if (power->avdd_2v8) {
			regulator_set_voltage(power->avdd_2v8,
						2800000, 2800000);
			ret = regulator_enable(power->avdd_2v8);
			if (ret < 0)
				goto avdd_err;
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
		if (power->pwdn)
			gpiod_set_value_cansleep(power->pwdn, 0);

		clk_set_rate(sensor->clk, sensor->mclk);
		clk_prepare_enable(sensor->clk);

		if (power->rst) {
			if (sensor->drvdata->reset_delay)
				reset_delay = sensor->drvdata->reset_delay;
			usleep_range(reset_delay, reset_delay + 10);
			gpiod_set_value_cansleep(power->rst, 0);
		}
		if (sensor->i2c_dyn_ctrl) {
			ret = sc2_select_pins_state(sensor->pos - 1,
					SC2_PIN_ST_SCCB, SC2_MOD_B52ISP);
			if (ret < 0) {
				pr_err("b52 sensor i2c pin is not configured\n");
				goto i2c_err;
			}
		}
	} else {
		if (WARN_ON(power->ref_cnt == 0))
			return -EINVAL;

		if (--power->ref_cnt > 0)
			return 0;

		if (check_load_firmware()) {
			int distance =  0x0;
			b52isp_set_focus_distance(distance, 0);
		}

		if (sensor->i2c_dyn_ctrl) {
			ret = sc2_select_pins_state(sensor->pos - 1,
					SC2_PIN_ST_GPIO, SC2_MOD_B52ISP);
			if (ret < 0)
				pr_err("b52 sensor gpio pin is not configured\n");
		}
		if (power->rst)
			gpiod_set_value_cansleep(power->rst, 1);
		clk_disable_unprepare(sensor->clk);
		if (power->pwdn)
			gpiod_set_value_cansleep(power->pwdn, 1);
		if (power->dvdd_1v2)
			regulator_disable(power->dvdd_1v2);
		if (power->dovdd_1v8)
			regulator_disable(power->dovdd_1v8);
		if (power->avdd_2v8)
			regulator_disable(power->avdd_2v8);
		if (power->af_2v8)
			regulator_disable(power->af_2v8);
		if (sensor->power.rst)
			devm_gpiod_put(&client->dev, sensor->power.rst);
		if (sensor->power.pwdn)
			devm_gpiod_put(&client->dev, sensor->power.pwdn);
		sensor->sensor_init = 0;
	}

	return ret;
i2c_err:
	clk_disable_unprepare(sensor->clk);
	if (power->af_2v8)
		regulator_disable(power->af_2v8);
af_err:
	if (power->dvdd_1v2)
		regulator_disable(power->dvdd_1v2);
dvdd_err:
	if (power->dovdd_1v8)
		regulator_disable(power->dovdd_1v8);
avdd_err:
	if (sensor->power.rst)
		devm_gpiod_put(&client->dev, sensor->power.rst);
dovdd_err:
	if (power->avdd_2v8)
		regulator_disable(power->af_2v8);
rst_err:
	if (sensor->power.pwdn)
		devm_gpiod_put(&client->dev, sensor->power.pwdn);

st_err:
	power->ref_cnt--;
	return ret;
}
