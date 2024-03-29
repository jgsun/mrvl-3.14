/* Marvell ISP OV8865 Driver
 *
 * Copyright (C) 2009-2010 Marvell International Ltd.
 *
 * Based on mt9v011 -Micron 1/4-Inch VGA Digital Image OV8865
 *
 * Copyright (c) 2009 Mauro Carvalho Chehab (mchehab@redhat.com)
 * This code is placed under the terms of the GNU General Public License v2
 */

#ifndef	B52_OV8865_H
#define	B52_OV8865_H

#include <media/b52-sensor.h>

#define OTP_DRV_START_ADDR  0x7010
#define OTP_DRV_LENC_START_ADDR 0x703a
#define OTP_DRV_LENC_SIZE  62
#define OTP_DRV_LSC_REG_ADDR  0x5800

/*
 * The typical value should always in line with the golden module,
 * otherwise with lead raw data abnormal.
 */
#define DEFAULT_RG_TYPICAL_RATIO 0x12f
#define DEFAULT_BG_TYPICAL_RATIO 0x11f

/*
 * Sysclk 148.2Mhz mipi speed 754 Mbps/lane
 * HTS:1940, VTS:2544
 * 3264 x 2448 30fps 4lane 26Mhz input clock
 */
struct regval_tab OV8865_res_init[] = {
	{0x0103, 0x01},
	{SENSOR_MDELAY, SENSOR_MDELAY, 5},
	{0x0100, 0x00},
	{0x0100, 0x00},
	{0x0100, 0x00},
	{0x0100, 0x00},
	{0x3638, 0xff},
	{0x0302, 0x1d},
	{0x0303, 0x00},
	{0x0304, 0x03},
	{0x030b, 0x02},
	{0x030d, 0x39},
	{0x030e, 0x00},
	{0x030f, 0x04},
	{0x0312, 0x01},
	{0x031e, 0x0c},
	{0x3015, 0x01},
	{0x3018, 0x72},
	{0x3020, 0x93},
	{0x3022, 0x01},
	{0x3031, 0x0a},
	{0x3106, 0x01},
	{0x3305, 0xf1},
	{0x3308, 0x00},
	{0x3309, 0x28},
	{0x330a, 0x00},
	{0x330b, 0x20},
	{0x330c, 0x00},
	{0x330d, 0x00},
	{0x330e, 0x00},
	{0x330f, 0x40},
	{0x3307, 0x04},
	{0x3604, 0x04},
	{0x3602, 0x30},
	{0x3605, 0x00},
	{0x3607, 0x20},
	{0x3608, 0x11},
	{0x3609, 0x68},
	{0x360a, 0x40},
	{0x360c, 0xdd},
	{0x360e, 0x0c},
	{0x3610, 0x07},
	{0x3612, 0x86},
	{0x3613, 0x58},
	{0x3614, 0x28},
	{0x3617, 0x40},
	{0x3618, 0x5a},
	{0x3619, 0x9b},
	{0x361c, 0x00},
	{0x361d, 0x60},
	{0x3631, 0x60},
	{0x3633, 0x10},
	{0x3634, 0x10},
	{0x3635, 0x10},
	{0x3636, 0x10},
	{0x3641, 0x55},
	{0x3646, 0x86},
	{0x3647, 0x27},
	{0x364a, 0x1b},
	{0x3500, 0x00},
	{0x3501, 0x98},
	{0x3502, 0x60},
	{0x3503, 0x30},/*Gain change no delay, exposure delay 1 frame*/
	{0x3508, 0x02},
	{0x3509, 0x00},
	{0x3700, 0x48},
	{0x3701, 0x18},
	{0x3702, 0x50},
	{0x3703, 0x32},
	{0x3704, 0x28},
	{0x3705, 0x00},
	{0x3706, 0x70},
	{0x3707, 0x08},
	{0x3708, 0x48},
	{0x3709, 0x80},
	{0x370a, 0x01},
	{0x370b, 0x70},
	{0x370c, 0x07},
	{0x3718, 0x14},
	{0x3719, 0x31},
	{0x3712, 0x44},
	{0x3714, 0x12},
	{0x371e, 0x31},
	{0x371f, 0x7f},
	{0x3720, 0x0a},
	{0x3721, 0x0a},
	{0x3724, 0x04},
	{0x3725, 0x04},
	{0x3726, 0x0c},
	{0x3728, 0x0a},
	{0x3729, 0x03},
	{0x372a, 0x06},
	{0x372b, 0xa6},
	{0x372c, 0xa6},
	{0x372d, 0xa6},
	{0x372e, 0x0c},
	{0x372f, 0x20},
	{0x3730, 0x02},
	{0x3731, 0x0c},
	{0x3732, 0x28},
	{0x3733, 0x10},
	{0x3734, 0x40},
	{0x3736, 0x30},
	{0x373a, 0x04},
	{0x373b, 0x18},
	{0x373c, 0x14},
	{0x373e, 0x06},
	{0x3755, 0x40},
	{0x3758, 0x00},
	{0x3759, 0x4c},
	{0x375a, 0x0c},
	{0x375b, 0x26},
	{0x375c, 0x40},
	{0x375d, 0x04},
	{0x375e, 0x00},
	{0x375f, 0x28},
	{0x3767, 0x1e},
	{0x3768, 0x04},
	{0x3769, 0x20},
	{0x376c, 0xc0},
	{0x376d, 0xc0},
	{0x376a, 0x08},
	{0x3761, 0x00},
	{0x3762, 0x00},
	{0x3763, 0x00},
	{0x3766, 0xff},
	{0x376b, 0x42},
	{0x3772, 0x46},
	{0x3773, 0x04},
	{0x3774, 0x2c},
	{0x3775, 0x13},
	{0x3776, 0x10},
	{0x37a0, 0x88},
	{0x37a1, 0x7a},
	{0x37a2, 0x7a},
	{0x37a3, 0x02},
	{0x37a4, 0x00},
	{0x37a5, 0x09},
	{0x37a6, 0x00},
	{0x37a7, 0x88},
	{0x37a8, 0xb0},
	{0x37a9, 0xb0},
	{0x3760, 0x00},
	{0x376f, 0x01},
	{0x37aa, 0x88},
	{0x37ab, 0x5c},
	{0x37ac, 0x5c},
	{0x37ad, 0x55},
	{0x37ae, 0x19},
	{0x37af, 0x19},
	{0x37b0, 0x00},
	{0x37b1, 0x00},
	{0x37b2, 0x00},
	{0x37b3, 0x84},
	{0x37b4, 0x84},
	{0x37b5, 0x66},
	{0x37b6, 0x00},
	{0x37b7, 0x00},
	{0x37b8, 0x00},
	{0x37b9, 0xff},
	{0x3800, 0x00},
	{0x3801, 0x0c},
	{0x3802, 0x00},
	{0x3803, 0x0c},
	{0x3804, 0x0c},
	{0x3805, 0xd3},
	{0x3806, 0x09},
	{0x3807, 0xa3},
	{0x3808, 0x0c},
	{0x3809, 0xc0},
	{0x380a, 0x09},
	{0x380b, 0x90},
	{0x380c, 0x07},/*HTS H*/
	{0x380d, 0x94},/*HTS L*/
	{0x380e, 0x09},/*VTS H*/
	{0x380f, 0xf0},/*VTS L*/
	{0x3810, 0x00},
	{0x3811, 0x04},
	{0x3813, 0x02},
	{0x3814, 0x01},
	{0x3815, 0x01},
	{0x3820, 0x00},
	{0x3821, 0x46},
	{0x382a, 0x01},
	{0x382b, 0x01},
	{0x3830, 0x04},
	{0x3836, 0x01},
	{0x3837, 0x18},
	{0x3841, 0xff},
	{0x3846, 0x48},
	{0x3d85, 0x06},
	{0x3d8c, 0x75},
	{0x3d8d, 0xef},
	{0x3f08, 0x16},
	{0x4000, 0xf1},
	{0x4001, 0x04},
	{0x4005, 0x10},
	{0x400b, 0x0c},
	{0x400d, 0x10},
	{0x401b, 0x00},
	{0x401d, 0x00},
	{0x4020, 0x02},
	{0x4021, 0x40},
	{0x4022, 0x03},
	{0x4023, 0x3f},
	{0x4024, 0x07},
	{0x4025, 0xc0},
	{0x4026, 0x08},
	{0x4027, 0xbf},
	{0x4028, 0x00},
	{0x4029, 0x02},
	{0x402a, 0x04},
	{0x402b, 0x04},
	{0x402c, 0x02},
	{0x402d, 0x02},
	{0x402e, 0x08},
	{0x402f, 0x02},
	{0x401f, 0x00},
	{0x4034, 0x3f},
	{0x4300, 0xff},
	{0x4301, 0x00},
	{0x4302, 0x0f},
	{0x4500, 0x68},
	{0x4503, 0x10},
	{0x4601, 0x10},
	{0x481f, 0x32},
	{0x4837, 0x15},
	{0x4850, 0x10},
	{0x4851, 0x32},
	{0x4b00, 0x2a},
	{0x4b0d, 0x00},
	{0x4d00, 0x04},
	{0x4d01, 0x18},
	{0x4d02, 0xc3},
	{0x4d03, 0xff},
	{0x4d04, 0xff},
	{0x4d05, 0xff},
	{0x5000, 0x96},
	{0x5001, 0x01},
	{0x5002, 0x08},
	{0x5901, 0x00},
	{0x5e00, 0x00},
	{0x5e01, 0x41},
	/*{0x0100, 0x01},*/
	{0x5b00, 0x02},
	{0x5b01, 0xd0},
	{0x5b02, 0x03},
	{0x5b03, 0xff},
	{0x5b05, 0x6c},
	{0x5780, 0xfc},
	{0x5781, 0xdf},
	{0x5782, 0x3f},
	{0x5783, 0x08},
	{0x5784, 0x0c},
	{0x5786, 0x20},
	{0x5787, 0x40},
	{0x5788, 0x08},
	{0x5789, 0x08},
	{0x578a, 0x02},
	{0x578b, 0x01},
	{0x578c, 0x01},
	{0x578d, 0x0c},
	{0x578e, 0x02},
	{0x578f, 0x01},
	{0x5790, 0x01},
	{0x5800, 0x1d},
	{0x5801, 0x0e},
	{0x5802, 0x0c},
	{0x5803, 0x0c},
	{0x5804, 0x0f},
	{0x5805, 0x22},
	{0x5806, 0x0a},
	{0x5807, 0x06},
	{0x5808, 0x05},
	{0x5809, 0x05},
	{0x580a, 0x07},
	{0x580b, 0x0a},
	{0x580c, 0x06},
	{0x580d, 0x02},
	{0x580e, 0x00},
	{0x580f, 0x00},
	{0x5810, 0x03},
	{0x5811, 0x07},
	{0x5812, 0x06},
	{0x5813, 0x02},
	{0x5814, 0x00},
	{0x5815, 0x00},
	{0x5816, 0x03},
	{0x5817, 0x07},
	{0x5818, 0x09},
	{0x5819, 0x06},
	{0x581a, 0x04},
	{0x581b, 0x04},
	{0x581c, 0x06},
	{0x581d, 0x0a},
	{0x581e, 0x19},
	{0x581f, 0x0d},
	{0x5820, 0x0b},
	{0x5821, 0x0b},
	{0x5822, 0x0e},
	{0x5823, 0x22},
	{0x5824, 0x23},
	{0x5825, 0x28},
	{0x5826, 0x29},
	{0x5827, 0x27},
	{0x5828, 0x13},
	{0x5829, 0x26},
	{0x582a, 0x33},
	{0x582b, 0x32},
	{0x582c, 0x33},
	{0x582d, 0x16},
	{0x582e, 0x14},
	{0x582f, 0x30},
	{0x5830, 0x31},
	{0x5831, 0x30},
	{0x5832, 0x15},
	{0x5833, 0x26},
	{0x5834, 0x23},
	{0x5835, 0x21},
	{0x5836, 0x23},
	{0x5837, 0x05},
	{0x5838, 0x36},
	{0x5839, 0x27},
	{0x583a, 0x28},
	{0x583b, 0x26},
	{0x583c, 0x24},
	{0x583d, 0xdf},
};

struct regval_tab OV8865_fmt_raw10[] = {
};

struct regval_tab OV8865_res_2M[] = {
};
struct regval_tab OV8865_res_8M[] = {

};
struct regval_tab OV8865_id[] = {
	{0x300b, 0x88, 0xff},
	{0x300c, 0x65, 0xff},
};
struct regval_tab OV8865_vts[] = {
	{0x380e, 0x09, 0x7f},
	{0x380f, 0xF0, 0xff},
};
struct regval_tab OV8865_stream_on[] = {
	{0x0100, 0x01, 0xff},
};
struct regval_tab OV8865_stream_off[] = {
	{0x0100, 0x00, 0xff},
};
struct regval_tab OV8865_expo[] = {
	{0x3500, 0x00, 0x0f},
	{0x3501, 0x00, 0xff},
	{0x3502, 0x00, 0xf0},
};
struct regval_tab OV8865_ag[] = {
	{0x3508, 0x00, 0x1f},
	{0x3509, 0x80, 0xff},
};
struct regval_tab OV8865_af[] = {
	{0x3618, 0x00, 0xff},
	{0x3619, 0x00, 0xff},
};
struct regval_tab OV8865_vflip[] = {
	{0x3820, 0x00, 0x06},
};
struct regval_tab OV8865_hflip[] = {
	{0x3821, 0x46, 0x06},
};

struct b52_sensor_i2c_attr OV8865_i2c_attr[] = {
	[0] = {
		.reg_len = I2C_16BIT,
		.val_len = I2C_8BIT,
		.addr = 0x10,
	},
};
/* if want to enable multi-module feature,
 * please enable READ_MODULE_INFO otp_type at first */
static struct b52_sensor_module OV8865_MODULE_INFO[] = {
	[0] = {
		.id = 0x3,
		.name = "0x0003",
	},
};
#define N_OV8865_I2C_ATTR ARRAY_SIZE(OV8865_i2c_attr)
#define N_OV8865_INIT ARRAY_SIZE(OV8865_res_init)
#define N_OV8865_ID ARRAY_SIZE(OV8865_id)
#define N_OV8865_FMT_RAW10 ARRAY_SIZE(OV8865_fmt_raw10)
#define N_OV8865_2M ARRAY_SIZE(OV8865_res_2M)
#define N_OV8865_8M ARRAY_SIZE(OV8865_res_8M)
#define N_OV8865_VTS ARRAY_SIZE(OV8865_vts)
#define N_OV8865_EXPO ARRAY_SIZE(OV8865_expo)
#define N_OV8865_AG ARRAY_SIZE(OV8865_ag)
#define N_OV8865_AF ARRAY_SIZE(OV8865_af)
#define N_OV8865_VFLIP ARRAY_SIZE(OV8865_vflip)
#define N_OV8865_HFLIP ARRAY_SIZE(OV8865_hflip)
#define N_OV8865_STREAM_ON ARRAY_SIZE(OV8865_stream_on)
#define N_OV8865_STREAM_OFF ARRAY_SIZE(OV8865_stream_off)
#define N_OV8865_MODULE_INFO ARRAY_SIZE(OV8865_MODULE_INFO)

struct b52_sensor_mbus_fmt OV8865_fmt = {
	.mbus_code	= V4L2_MBUS_FMT_SBGGR10_1X10,
	.colorspace	= V4L2_COLORSPACE_SRGB,
	.regs = {
		.tab = OV8865_fmt_raw10,
		.num = N_OV8865_FMT_RAW10,
	}
};
struct b52_sensor_resolution OV8865_res[] = {
	[0] = {
		 .width = 3264,
		 .height = 2448,
		 .hts = 0x0794*2,
		 .min_vts = 0x09F0,
		 .prop = SENSOR_RES_BINING1,
		 .regs = {
			.tab = OV8865_res_8M,
			.num = N_OV8865_8M,
		},
	},
};

static int OV8865_get_pixelclock(struct v4l2_subdev *sd, u32 *rate, u32 mclk);
static int OV8865_get_dphy_desc(struct v4l2_subdev *sd,
		struct csi_dphy_desc *dphy_desc, u32 mclk);
static int OV8865_update_otp(struct v4l2_subdev *sd,
		struct b52_sensor_otp *otp);

struct b52_sensor_spec_ops ov8865_ops = {
	.get_pixel_rate = OV8865_get_pixelclock,
	.get_dphy_desc = OV8865_get_dphy_desc,
	.update_otp = OV8865_update_otp,
};

struct b52_sensor_data b52_ov8865 = {
	.name = "ovt.ov8865",
	.type = OVT_SENSOR,
	.i2c_attr = OV8865_i2c_attr,
	.num_i2c_attr = N_OV8865_I2C_ATTR,
	.id = {
		.tab = OV8865_id,
		.num = N_OV8865_ID,
	},
	.global_setting = {
	.tab = OV8865_res_init,
	.num = N_OV8865_INIT,

	},
	.mbus_fmt = &OV8865_fmt,
	.num_mbus_fmt = 1,
	.res = OV8865_res,
	.num_res = 1,
	.streamon = {
		.tab = OV8865_stream_on,
		.num = N_OV8865_STREAM_ON,
	},
	.streamoff = {
		.tab = OV8865_stream_off,
		.num = N_OV8865_STREAM_OFF,
	},
	.gain2iso_ratio = {
		.numerator = 100,
		.denominator = 0x10,
	},
	.vts_range = {0x09f0, 0x7fff},
	.gain_range = {
		[B52_SENSOR_AG] = {0x0010, 0x00f8},
		[B52_SENSOR_DG] = {0x0010, 0x0010},
	},
	.expo_range = {0x0002, 0x09E0},
	.focus_range = {0x0010, 0x03ff},
	.vts_reg = {
		.tab = OV8865_vts,
		.num = N_OV8865_VTS,
	},
	.expo_reg = {
		.tab = OV8865_expo,
		.num = N_OV8865_EXPO,
	},
	.gain_reg = {
		[B52_SENSOR_AG] = {
			.tab = OV8865_ag,
			.num = N_OV8865_AG,
		},
		[B52_SENSOR_DG] = {
			.tab = NULL,
			.num = 0,
		},
	},
	.af_reg = {
		.tab = OV8865_af,
		.num = N_OV8865_AF,
	},
	.hflip = {
		.tab = OV8865_hflip,
		.num = N_OV8865_HFLIP,
	},
	.vflip = {
		.tab = OV8865_vflip,
		.num = N_OV8865_VFLIP,
	},
	.flip_change_phase = 0,
	.gain_shift = 0x03,
	.expo_shift = 0x08,
	.calc_dphy = 1,
	.nr_lane = 4,
	.mipi_clk_bps = 754000000,
	.ops = &ov8865_ops,
	.module = OV8865_MODULE_INFO,
	.num_module = N_OV8865_MODULE_INFO,
	.pwdone_delay = 800,
};

#endif
