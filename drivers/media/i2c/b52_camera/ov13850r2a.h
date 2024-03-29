/* Marvell ISP OV13850R2A Driver
 *
 * Copyright (C) 2009-2010 Marvell International Ltd.
 *
 * Based on mt9v011 -Micron 1/4-Inch VGA Digital Image OV13850R2A
 *
 * Copyright (c) 2009 Mauro Carvalho Chehab (mchehab@redhat.com)
 * This code is placed under the terms of the GNU General Public License v2
 */

#ifndef	B52_OV13850R2A_H
#define	B52_OV13850R2A_H

#include <media/b52-sensor.h>

#define OTP_DRV_START_ADDR  0x7220
#define OTP_DRV_INFO_GROUP_COUNT  3
#define OTP_DRV_INFO_SIZE  5
#define OTP_DRV_AWB_GROUP_COUNT 3
#define OTP_DRV_AWB_SIZE  5
#define OTP_DRV_LSC_GROUP_COUNT  3
#define OTP_DRV_LSC_SIZE  62
#define OTP_DRV_LSC_REG_ADDR  0x5200
#define OTP_DRV_VCM_GROUP_COUNT  3
#define OTP_DRV_VCM_SIZE  3
/*
 * The typical value should always in line with the golden module,
 * otherwise with lead raw data abnormal.
 */
#define DEFAULT_RG_TYPICAL_RATIO 0x12f
#define DEFAULT_BG_TYPICAL_RATIO 0x11f

/* raw10,XVCLK=24Mhz, MIPI 12000Mbps */
static struct regval_tab OV13850R2A_13M_res_init[] = {
	{0x0102, 0x01},
	{0x0300, 0x00},
	{0x0301, 0x00},
	{0x0302, 0x32},
	{0x0303, 0x00},
	{0x030a, 0x00},
	{0x300f, 0x11},
	{0x3010, 0x01},
	{0x3011, 0x76},
	{0x3012, 0x41},
	{0x3013, 0x12},
	{0x3014, 0x11},
	{0x301f, 0x03},
	{0x3106, 0x00},
	{0x3210, 0x47},
	{0x3500, 0x00},
	{0x3501, 0xc0},
	{0x3502, 0x00},
	{0x3503, 0x27}, /* preview flicker in high dynamic scenes */
	{0x3506, 0x00},
	{0x3507, 0x02},
	{0x3508, 0x00},
	{0x350a, 0x00},
	{0x350b, 0x80},
	{0x350e, 0x00},
	{0x350f, 0x10},
	{0x351a, 0x00},
	{0x351b, 0x10},
	{0x351c, 0x00},
	{0x351d, 0x20},
	{0x351e, 0x00},
	{0x351f, 0x40},
	{0x3520, 0x00},
	{0x3521, 0x80},
	{0x3600, 0xc0},
	{0x3601, 0xfc},
	{0x3602, 0x02},
	{0x3603, 0x78},
	{0x3604, 0xb1},
	{0x3605, 0x95},
	{0x3606, 0x73},
	{0x3607, 0x07},
	{0x3609, 0x40},
	{0x360a, 0x30},
	{0x360b, 0x91},
	{0x360C, 0x09},
	{0x360f, 0x02},
	{0x3611, 0x10},
	{0x3612, 0x08},
	{0x3613, 0x33},
	{0x3614, 0x2a},
	{0x3615, 0x0c},
	{0x3616, 0x0e},
	{0x3641, 0x02},
	{0x3660, 0x82},
	{0x3668, 0x54},
	{0x3669, 0x00},
	{0x366a, 0x3f},
	{0x3667, 0xa0},
	{0x3702, 0x40},
	{0x3703, 0x44},
	{0x3704, 0x2c},
	{0x3705, 0x01},
	{0x3706, 0x15},
	{0x3707, 0x44},
	{0x3708, 0x3c},
	{0x3709, 0x1f},
	{0x370a, 0x24},
	{0x370b, 0x3c},
	{0x3710, 0x28},
	{0x3716, 0x03},
	{0x3718, 0x10},
	{0x3719, 0x0c},
	{0x371a, 0x08},
	{0x371b, 0x01},
	{0x371c, 0xfc},
	{0x3720, 0x55},
	{0x3722, 0x84},
	{0x3728, 0x40},
	{0x372a, 0x05},
	{0x372b, 0x02},
	{0x372e, 0x22},
	{0x372f, 0xa0},
	{0x3730, 0x02},
	{0x3731, 0x5c},
	{0x3732, 0x02},
	{0x3733, 0x70},
	{0x3738, 0x02},
	{0x3739, 0x72},
	{0x373a, 0x02},
	{0x373b, 0x74},
	{0x3740, 0x01},
	{0x3741, 0xd0},
	{0x3742, 0x00},
	{0x3743, 0x01},
	{0x3748, 0x21},
	{0x3749, 0x22},
	{0x374a, 0x28},
	{0x3760, 0x13},
	{0x3761, 0x33},
	{0x3762, 0x86},
	{0x3763, 0x16},
	{0x3767, 0x24},
	{0x3768, 0x06},
	{0x3769, 0x45},
	{0x376c, 0x23},
	{0x376f, 0x80},
	{0x3773, 0x06},
	{0x3780, 0x90},
	{0x3781, 0x00},
	{0x3782, 0x01},
	{0x3d84, 0x00},
	{0x3d85, 0x17},
	{0x3d8c, 0x73},
	{0x3d8d, 0xbf},
	{0x3800, 0x00},
	{0x3801, 0x0C},
	{0x3802, 0x00},
	{0x3803, 0x04},
	{0x3804, 0x10},
	{0x3805, 0x93},
	{0x3806, 0x0c},
	{0x3807, 0x4B},
	{0x3808, 0x10},
	{0x3809, 0x80},
	{0x380a, 0x0c},
	{0x380b, 0x40},
	{0x380c, 0x11},
	{0x380d, 0xa0},
	{0x380e, 0x0d},
	{0x380f, 0x00},
	{0x3810, 0x00},
	{0x3811, 0x04},
	{0x3812, 0x00},
	{0x3813, 0x04},
	{0x3814, 0x11},
	{0x3815, 0x11},
	{0x3820, 0x00},
	{0x3821, 0x04},
	{0x3823, 0x00},
	{0x3826, 0x00},
	{0x3827, 0x02},
	{0x3834, 0x00},
	{0x3835, 0x14}, /* vts_auto_disable to resolve FPN */
	{0x3836, 0x04},
	{0x3837, 0x01},
	{0x4000, 0xf1},
	{0x4001, 0x00},
	{0x400b, 0x0c},
	{0x4011, 0x00},
	{0x401a, 0x00},
	{0x401b, 0x00},
	{0x401c, 0x00},
	{0x401d, 0x00},
	{0x4020, 0x03},
	{0x4021, 0x6C},
	{0x4022, 0x0D},
	{0x4023, 0x17},
	{0x4024, 0x0D},
	{0x4025, 0xFC},
	{0x4026, 0x0D},
	{0x4027, 0xFF},
	{0x4028, 0x00},
	{0x4029, 0x02},
	{0x402a, 0x04},
	{0x402b, 0x08},
	{0x402c, 0x02},
	{0x402d, 0x02},
	{0x402e, 0x0c},
	{0x402f, 0x08},
	{0x403d, 0x2c},
	{0x403f, 0x7F},
	{0x4041, 0x07},
	{0x4500, 0x82},
	{0x4501, 0x38},
	{0x458b, 0x00},
	{0x459c, 0x00},
	{0x459d, 0x00},
	{0x459e, 0x00},
	{0x4601, 0x04},
	{0x4602, 0x22},
	{0x4603, 0x00},
	/* {0x4800, 0x24}, gate mode for marvell */
	{0x4837, 0x0d},
	{0x4d00, 0x04},
	{0x4d01, 0x42},
	{0x4d02, 0xd1},
	{0x4d03, 0x90},
	{0x4d04, 0x66},
	{0x4d05, 0x65},
	{0x4d0b, 0x00},
	{0x5000, 0x0e},
	{0x5001, 0x03}, /*enable Manual White Balance gain for WB OTP*/
	{0x5002, 0x07},
	{0x5003, 0x4f},
	{0x5013, 0x40},
	{0x501c, 0x00},
	{0x501d, 0x10},
	{0x5100, 0x30},
	{0x5101, 0x02},
	{0x5102, 0x01},
	{0x5103, 0x01},
	{0x5104, 0x02},
	{0x5105, 0x01},
	{0x5106, 0x01},
	{0x5107, 0x00},
	{0x5108, 0x00},
	{0x5109, 0x00},
	{0x510f, 0xfc},
	{0x5110, 0xf0},
	{0x5111, 0x10},
	{0x536d, 0x02},
	{0x536e, 0x67},
	{0x536f, 0x01},
	{0x5370, 0x4c},
	{0x5400, 0x00},
	{0x5400, 0x00},
	{0x5401, 0x71},
	{0x5402, 0x00},
	{0x5403, 0x00},
	{0x5404, 0x00},
	{0x5405, 0x80},
	{0x540c, 0x05},
	{0x5501, 0x00},
	{0x5b00, 0x00},
	{0x5b01, 0x00},
	{0x5b02, 0x01},
	{0x5b03, 0xff},
	{0x5b04, 0x02},
	{0x5b05, 0x6c},
	{0x5b09, 0x02},
	{0x5e00, 0x00},
	{0x5e10, 0x1c},
};

static struct regval_tab OV13850R2A_fmt_raw10[] = {
};

static struct regval_tab OV13850R2A_res_13M[] = {
	{0x3808, 0x10},
	{0x3809, 0x80},
	{0x380a, 0x0c},
	{0x380b, 0x40},
};
static struct regval_tab OV13850R2A_res_12M_crop[] = {
	{0x3808, 0x0f},
	{0x3809, 0xe0},
	{0x380a, 0x08},
	{0x380b, 0xee},
};
static struct regval_tab OV13850R2A_id[] = {
	{0x300A, 0xd8, 0xff},
	{0x300B, 0x50, 0xff},
	{0x302A, 0xB2, 0xff},
};
static struct regval_tab OV13850R2A_vts[] = {
	{0x380e, 0x0d, 0x7f},
	{0x380f, 0x60, 0xff},
};
static struct regval_tab OV13850R2A_stream_on[] = {
	{0x0100, 0x01, 0xff},
};
static struct regval_tab OV13850R2A_stream_off[] = {
	{0x0100, 0x00, 0xff},
};
static struct regval_tab OV13850R2A_expo[] = {
	{0x3500, 0x00, 0xff},
	{0x3501, 0x00, 0xff},
	{0x3502, 0x00, 0x0f},
};
static struct regval_tab OV13850R2A_ag[] = {
	{0x350a, 0x00, 0xff},
	{0x350b, 0x00, 0xff},
};
static struct regval_tab OV13850R2A_af[] = {
	{0x3618, 0x00, 0xff},
	{0x3619, 0x00, 0xff},
};
static struct regval_tab OV13850R2A_vflip[] = {
	{0x3820, 0x00, 0x4},
};
static struct regval_tab OV13850R2A_hflip[] = {
	{0x3821, 0x04, 0x4},
};
static struct b52_sensor_i2c_attr OV13850R2A_i2c_attr[] = {
	[0] = {
		.reg_len = I2C_16BIT,
		.val_len = I2C_8BIT,
		.addr = 0x10,
	},
	[1] = {
		.reg_len = I2C_16BIT,
		.val_len = I2C_8BIT,
		.addr = 0x36,
	},
};

static struct b52_sensor_module OV13850R2A_MODULE_INFO[] = {
	[0] = {
		.id = 0x16,
		.name = "0x0016",
	},
	[1] = {
		.id = 0x0d,
		.name = "0x000d",
	},
	[2] = {
		.id = 0x09,
		.name = "0x0009",
	},
};

#define N_OV13850R2A_I2C_ATTR ARRAY_SIZE(OV13850R2A_i2c_attr)
#define N_OV13850R2A_13M_INIT ARRAY_SIZE(OV13850R2A_13M_res_init)
#define N_OV13850R2A_ID ARRAY_SIZE(OV13850R2A_id)
#define N_OV13850R2A_FMT_RAW10 ARRAY_SIZE(OV13850R2A_fmt_raw10)
#define N_OV13850R2A_13M ARRAY_SIZE(OV13850R2A_res_13M)
#define N_OV13850R2A_12M_CROP ARRAY_SIZE(OV13850R2A_res_12M_crop)
#define N_OV13850R2A_VTS ARRAY_SIZE(OV13850R2A_vts)
#define N_OV13850R2A_EXPO ARRAY_SIZE(OV13850R2A_expo)
#define N_OV13850R2A_AG ARRAY_SIZE(OV13850R2A_ag)
#define N_OV13850R2A_AF ARRAY_SIZE(OV13850R2A_af)
#define N_OV13850R2A_VFLIP ARRAY_SIZE(OV13850R2A_vflip)
#define N_OV13850R2A_HFLIP ARRAY_SIZE(OV13850R2A_hflip)
#define N_OV13850R2A_STREAM_ON ARRAY_SIZE(OV13850R2A_stream_on)
#define N_OV13850R2A_STREAM_OFF ARRAY_SIZE(OV13850R2A_stream_off)
#define N_OV13850R2A_MODULE_INFO ARRAY_SIZE(OV13850R2A_MODULE_INFO)

static struct b52_sensor_mbus_fmt OV13850R2A_fmt = {
	.mbus_code	= V4L2_MBUS_FMT_SBGGR10_1X10,
	.colorspace	= V4L2_COLORSPACE_SRGB,
	.regs = {
		.tab = OV13850R2A_fmt_raw10,
		.num = N_OV13850R2A_FMT_RAW10,
	}
};
static struct b52_sensor_resolution OV13850R2A_13M_res[] = {
	[0] = {
		 .width = 4224,
		 .height = 3136,
		 .hts = 0x11a0,
		 .min_vts = 0x0d00,
		 .prop = SENSOR_RES_BINING1,
		 .regs = {
			.tab = OV13850R2A_res_13M,
			.num = N_OV13850R2A_13M,
		},
	},
	[1] = {
		 .width = 4064,
		 .height = 2286,
		 .hts = 0x11a0,
		 .min_vts = 0x0d00,
		 .prop = SENSOR_RES_CROPPED,
		 .regs = {
			.tab = OV13850R2A_res_12M_crop,
			.num = N_OV13850R2A_12M_CROP,
		},
	},
};

static int OV13850R2A_get_pixelclock(struct v4l2_subdev *sd,
					u32 *rate, u32 mclk);
static int OV13850R2A_get_dphy_desc(struct v4l2_subdev *sd,
			struct csi_dphy_desc *dphy_desc, u32 mclk);
static int OV13850R2A_update_otp(struct v4l2_subdev *sd,
				struct b52_sensor_otp *opt);

static struct b52_sensor_spec_ops OV13850R2A_ops = {
	.get_pixel_rate = OV13850R2A_get_pixelclock,
	.get_dphy_desc = OV13850R2A_get_dphy_desc,
	.update_otp = OV13850R2A_update_otp,
	.s_power = NULL,
};

struct b52_sensor_data b52_ov13850r2a_13M = {
	.name = "ovt.ov13850r2a",
	.type = OVT_SENSOR,
	.i2c_attr = OV13850R2A_i2c_attr,
	.num_i2c_attr = N_OV13850R2A_I2C_ATTR,
	.id = {
		.tab = OV13850R2A_id,
		.num = N_OV13850R2A_ID,
	},
	.global_setting = {
		.tab = OV13850R2A_13M_res_init,
		.num = N_OV13850R2A_13M_INIT,
	},
	.mbus_fmt = &OV13850R2A_fmt,
	.num_mbus_fmt = 1,
	.res = OV13850R2A_13M_res,
	.num_res = 2,
	.streamon = {
		.tab = OV13850R2A_stream_on,
		.num = N_OV13850R2A_STREAM_ON,
	},
	.streamoff = {
		.tab = OV13850R2A_stream_off,
		.num = N_OV13850R2A_STREAM_OFF,
	},
	.gain2iso_ratio = {
		.numerator = 100,
		.denominator = 0x10,
	},
	.vts_range = {0X0ba0, 0x7fff},
	.gain_range = {
		[B52_SENSOR_AG] = {0x0010, 0x00f8},
		[B52_SENSOR_DG] = {0x0010, 0x0010},
	},
	.expo_range = {0x00010, 0xb90},
	.focus_range = {0x0010, 0x03ff},
	.vts_reg = {
		.tab = OV13850R2A_vts,
		.num = N_OV13850R2A_VTS,
	},
	.expo_reg = {
		.tab = OV13850R2A_expo,
		.num = N_OV13850R2A_EXPO,
	},
	.gain_reg = {
		[B52_SENSOR_AG] = {
			.tab = OV13850R2A_ag,
			.num = N_OV13850R2A_AG,
		},
		[B52_SENSOR_DG] = {
			.tab = NULL,
			.num = 0,
		},
	},
	.af_reg = {
		.tab = OV13850R2A_af,
		.num = N_OV13850R2A_AF,
	},
	.hflip = {
		.tab = OV13850R2A_hflip,
		.num = N_OV13850R2A_HFLIP,
	},
	.vflip = {
		.tab = OV13850R2A_vflip,
		.num = N_OV13850R2A_VFLIP,
	},

	.flip_change_phase = 0,
	.gain_shift = 0x00,
	.expo_shift = 0x08,
/*	.calc_dphy = 1, */
	.nr_lane = 4,
	.mipi_clk_bps = 1200000000,
	.ops = &OV13850R2A_ops,
	.module = OV13850R2A_MODULE_INFO,
	.num_module = N_OV13850R2A_MODULE_INFO,
	.reset_delay = 100,
};

#endif
