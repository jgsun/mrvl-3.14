/*
 * sound/soc/pxa/mmp-map-be-dai-v2.c
 * Base on mmp-be-dai.c
 *
 * Copyright (C) 2015 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/initval.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <linux/mfd/mmp-map-v2.h>

/* DEI2S/AUXI2S audio private data */
struct map_be_dai_private {
	struct device *dev;
	struct map_private *map_priv;
	int dai_fmt;
	int running_cnt;

	/* dei2s slot configuration */
	unsigned int dei2s_if1_tx[2];
	unsigned int dei2s_if1_rx[2];
	int dei2s_if1_tx_num;
	int dei2s_if1_rx_num;
	unsigned int dei2s_if2_tx[2];
	unsigned int dei2s_if2_rx[2];
	int dei2s_if2_tx_num;
	int dei2s_if2_rx_num;

	/* check if the channel is in used */
	unsigned int ch_bit_map;
	/* Indication if i2s is configured */
	bool i2s_config[4];
};

/* Set SYSCLK */
static int mmp_map2_set_be_dai_sysclk(struct snd_soc_dai *cpu_dai,
				    int clk_id, unsigned int freq, int dir)
{
	struct map_be_dai_private *map_be_dai_priv;
	struct map_private *map_priv;
	u32 reg, val;
	int ret = 0;

	map_be_dai_priv = snd_soc_dai_get_drvdata(cpu_dai);
	map_priv = map_be_dai_priv->map_priv;

	/* if FM opened, we shouldn't let bt open */
	if (cpu_dai->id == 1 && map_priv->bt_fm_sel)
		return 0;

	if (map_be_dai_priv->i2s_config[cpu_dai->id - 1])
		return 0;

	if (cpu_dai->id > 1) {
		switch (cpu_dai->id) {
		case 2:
			reg = MAP_PDM_BCLK_DIV;
			break;
		case 3:
			reg = MAP_DMIC12_CLK_DIV;
			break;
		case 4:
			reg = MAP_DMIC34_CLK_DIV;
			break;
		default:
			return -EINVAL;
		}

		if (clk_id == APLL_32K)
			val = 0x10010030;
		else if (clk_id == VCTCXO_26M)
			val = 0x10c00659;
		else
			return -EINVAL;
	} else {
		reg =	MAP_I2S3_BCLK_DIV;

		/* this value will be changed if apll1 fclk changes */
		if (clk_id == APLL_32K) {
			switch (freq) {
			case 8000:
				val = 0x10010120;
				break;
			case 16000:
				val = 0x10010090;
				break;
			case 32000:
				val = 0x10010048;
				break;
			case 44100:
				val = 0x11b95a00;
				break;
			case 48000:
				val = 0x10010030;
				break;
			case 96000:
				val = 0x10010018;
				break;
			default:
				return -EINVAL;
			}
		} else if (clk_id == VCTCXO_26M) {
			switch (freq) {
			case 8000:
				val = 0x10200659;
				break;
			case 16000:
				val = 0x10400659;
				break;
			case 32000:
				val = 0x10800659;
				break;
			case 44100:
				val = 0x13721fbd;
				break;
			case 48000:
				val = 0x11800659;
				break;
			case 96000:
				val = 0x13000659;
				break;
			default:
				return -EINVAL;
			}
		} else
			return -EINVAL;
	}

	map_raw_write(map_priv, reg, val);

	return ret;
}

/* need to consider use clkdiv or add clock source for these interfaces */
static int mmp_map2_set_be_dai_clkdiv(struct snd_soc_dai *cpu_dai,
		int div_id, int div)
{
	struct map_be_dai_private *map_be_dai_priv;
	struct map_private *map_priv;
	unsigned int addr;

	map_be_dai_priv = snd_soc_dai_get_drvdata(cpu_dai);
	map_priv = map_be_dai_priv->map_priv;

	/* if FM opened, we shouldn't let bt open */
	if (cpu_dai->id == 1 && map_priv->bt_fm_sel)
		return 0;

	if (map_be_dai_priv->i2s_config[cpu_dai->id - 1])
		return 0;

	if (1 == cpu_dai->id)
		addr =	MAP_I2S3_BCLK_DIV;
	else
		return -EINVAL;
	/* set dai divider <0:27> */
	map_raw_write(map_priv, addr, div);

	return 0;
}

static int mmp_map2_set_be_dai_fmt(struct snd_soc_dai *cpu_dai,
				 unsigned int fmt)
{
	struct map_be_dai_private *map_be_dai_priv;
	struct map_private *map_priv;
	unsigned int inf = 0, addr;

	map_be_dai_priv = snd_soc_dai_get_drvdata(cpu_dai);
	map_priv = map_be_dai_priv->map_priv;

	/* if FM opened, we shouldn't let bt open */
	if (cpu_dai->id == 1 && map_priv->bt_fm_sel)
		return 0;

	if (map_be_dai_priv->i2s_config[cpu_dai->id - 1])
		return 0;

	if (1 == cpu_dai->id) {
		addr =	MAP_I2S3_CTRL_REG;
		inf = map_raw_read(map_priv, addr);
	} else
		return -EINVAL;

	/* set master/slave audio interface */
	switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBM_CFM:
		inf &= ~MAP_I2S_MASTER;
		break;
	case SND_SOC_DAIFMT_CBS_CFS:
		inf |= MAP_I2S_MASTER;
		break;
	default:
		return -EINVAL;
	}

	inf &= ~MAP_DEI2S_MODE_MASK;
	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:
		inf |= MAP_DEI2S_MODE_I2S_FORMAT;
		break;
	case SND_SOC_DAIFMT_RIGHT_J:
		inf |= MAP_DEI2S_MODE_RIGHT_JUST;
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		inf |= MAP_DEI2S_MODE_LEFT_JUST;
		break;
	case SND_SOC_DAIFMT_DSP_A:
		inf |= MAP_DEI2S_MODE_PCM_FORMAT;
		inf &= ~MAP_DEI2S_PCM_MODE_B;
		inf |= MAP_BCLK_POL;
		inf |= MAP_PCM_WIDTH_SEL;
		break;
	case SND_SOC_DAIFMT_DSP_B:
		inf |= MAP_DEI2S_MODE_PCM_FORMAT;
		inf |= MAP_DEI2S_PCM_MODE_B;
		break;
	default:
		inf &= ~MAP_I2S_MODE_I2S_FORMAT;
		break;
	}
	map_raw_write(map_priv, addr, inf);
	return 0;
}

static int mmp_map2_be_hw_params(struct snd_pcm_substream *substream,
			       struct snd_pcm_hw_params *params,
			       struct snd_soc_dai *dai)
{
	struct map_be_dai_private *map_be_dai_priv;
	struct map_private *map_priv;
	unsigned int inf = 0, addr;

	map_be_dai_priv = snd_soc_dai_get_drvdata(dai);
	map_priv = map_be_dai_priv->map_priv;

	/* if FM opened, we shouldn't let bt open */
	if (dai->id == 1 && map_priv->bt_fm_sel)
		return 0;

	if (map_be_dai_priv->i2s_config[dai->id - 1])
		return 0;

	switch (dai->id) {
	case 1:
		addr =	MAP_I2S3_CTRL_REG;
		inf = map_raw_read(map_priv, addr);

		break;
	case 2:
	case 3:
	case 4:
		return 0;
	default:
		return -EINVAL;
	}
	inf &= ~MAP_DEI2S_WLEN_MASK;
	/* bit size */
	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S16_LE:
		inf |= MAP_DEI2S_WLEN_16_BIT;
		break;
	case SNDRV_PCM_FORMAT_S20_3LE:
		inf |= MAP_DEI2S_WLEN_20_BIT;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
		inf |= MAP_DEI2S_WLEN_24_BIT;
		break;
	default:
		return -EINVAL;
	}
	map_raw_write(map_priv, addr, inf);

	/* sample rate */
	if (1 == dai->id)
		map_set_port_freq(map_priv, I2S3, params_rate(params));

	map_be_dai_priv->i2s_config[dai->id - 1] = true;

	if (1 == dai->id)
		map_reset_port(map_priv, I2S3);
	else
		return -EINVAL;

	return 0;
}

static int mmp_map2_be_startup(struct snd_pcm_substream *substream,
	struct snd_soc_dai *dai)
{
	struct map_be_dai_private *map_be_dai_priv;
	struct map_private *map_priv;

	if (dai->active)
		return 0;

	map_be_dai_priv = snd_soc_dai_get_drvdata(dai);
	map_priv = map_be_dai_priv->map_priv;
	map_be_active(map_priv);

	return 0;
}

static void mmp_map2_be_shutdown(struct snd_pcm_substream *substream,
	struct snd_soc_dai *dai)
{
	struct map_be_dai_private *map_be_dai_priv;
	struct map_private *map_priv;

	if (dai->active)
		return;
	map_be_dai_priv = snd_soc_dai_get_drvdata(dai);
	map_priv = map_be_dai_priv->map_priv;
	map_be_reset(map_priv);

	map_be_dai_priv->i2s_config[dai->id - 1] = false;

	return;
}

static int mmp_map2_be_trigger(struct snd_pcm_substream *substream, int cmd,
			     struct snd_soc_dai *dai)
{
	struct map_be_dai_private *map_be_dai_priv;
	struct map_private *map_priv;
	unsigned int inf = 0, addr, stream;
	int ret = 0;

	map_be_dai_priv = snd_soc_dai_get_drvdata(dai);
	map_priv = map_be_dai_priv->map_priv;
	stream = substream->stream;

	/* if FM opened, we shouldn't let bt open */
	if (dai->id == 1 && map_priv->bt_fm_sel)
		return 0;

	switch (dai->id) {
	case 1:
		addr =	MAP_I2S3_CTRL_REG;
		break;
	case 2:
		addr = PDM_CTRL;
		break;
	case 3:
	case 4:
		addr = DMIC_CTRL;
		break;
	default:
		return -EINVAL;
	}

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		if (dai->id == 1) {
			inf = map_raw_read(map_priv, addr);
			/*
			 * note: For be dai, DAC side is for capture.
			 * So I2S_REC_EN should be set. Playback is
			 * similar. This is opposite to fe dai.
			 */
			if (stream == SNDRV_PCM_STREAM_PLAYBACK)
				inf |= I2S_GEN_EN;
			else
				inf |= I2S_REC_EN;
			map_raw_write(map_priv, addr, inf);
		} else if (dai->id == 2) {
			inf |= PDM_OUT_ENABLE | PDM_OUT_MODE | PDM_OUT_AUDIO;
			map_raw_write(map_priv, addr, inf);
		} else if (dai->id == 3) {
			/*
			 * set bit5, choose dmic sample rate same as dsp1
			 * bit4:3: 0x1, dmic clk src is mclk hi
			 * bit2:1: 0x1, decimation rate is 16.
			 * dmic SR= (147456000/48) / (4 * 16) =48k.
			 */
			inf |= DMIC12_ENABLE | 0x2a;
			map_raw_write(map_priv, addr, inf);
		} else if (dai->id == 4) {
			inf |= DMIC34_ENABLE | (0x2a << 8);
			map_raw_write(map_priv, addr, inf);
		}
		/* apply the change */
		map_apply_change(map_priv);
		break;

	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
		if (dai->id == 1) {
			inf = map_raw_read(map_priv, addr);
			if (stream == SNDRV_PCM_STREAM_PLAYBACK)
				inf &= ~I2S_GEN_EN;
			else
				inf &= ~I2S_REC_EN;
			map_raw_write(map_priv, addr, inf);
		} else if (dai->id == 2) {
			inf &= ~(PDM_OUT_ENABLE | PDM_OUT_MODE | PDM_OUT_AUDIO);
			map_raw_write(map_priv, addr, inf);
		} else if (dai->id == 3) {
			inf &= ~DMIC12_ENABLE;
			map_raw_write(map_priv, addr, inf);
		} else if (dai->id == 4) {
			inf &= ~DMIC34_ENABLE;
			map_raw_write(map_priv, addr, inf);
		}
		/* apply the change */
		map_apply_change(map_priv);

		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

static int mmp_map2_be_set_channel_map(struct snd_soc_dai *dai,
				unsigned int tx_num, unsigned int *tx_slot,
				unsigned int rx_num, unsigned int *rx_slot)
{
	struct map_be_dai_private *map_be_dai_priv;
	struct map_private *map_priv;
	int i;

	map_be_dai_priv = snd_soc_dai_get_drvdata(dai);
	map_priv = map_be_dai_priv->map_priv;

	/* if FM opened, we shouldn't let bt open */
	if (dai->id == 1 && map_priv->bt_fm_sel)
		return 0;


	if (map_be_dai_priv->i2s_config[dai->id - 1])
		return 0;

	/* Fixme: 1<->channel 0; 2<->channel 1 */
	for (i = 0; i < tx_num; i++) {
		if (map_be_dai_priv->ch_bit_map & (1 << tx_slot[i])) {
			pr_err("the tx channel[%d] is in used", tx_slot[i]);
			return -EINVAL;
		}
		map_be_dai_priv->ch_bit_map |= 1 << tx_slot[i];
	}
	for (i = 0; i < rx_num; i++) {
		if (map_be_dai_priv->ch_bit_map & (1 << rx_slot[i])) {
			pr_err("the rx channel[%d] is in used", rx_slot[i]);
			return -EINVAL;
		}
		map_be_dai_priv->ch_bit_map |= 1 << rx_slot[i];
	}

	return 0;
}

#define MMP_MAP_RATES SNDRV_PCM_RATE_8000_192000
#define MMP_MAP_FORMATS (SNDRV_PCM_FMTBIT_S8 | \
		SNDRV_PCM_FMTBIT_S16_LE | \
		SNDRV_PCM_FMTBIT_S24_LE | \
		SNDRV_PCM_FMTBIT_S24_LE | \
		SNDRV_PCM_FMTBIT_S32_LE)

static int mmp_map2_aux_mute(struct snd_soc_dai *dai, int mute, int direction)
{
	struct map_be_dai_private *be_dai_priv = snd_soc_dai_get_drvdata(dai);
	struct map_private *map_priv = be_dai_priv->map_priv;
	unsigned int reg, val;

	if (direction == SNDRV_PCM_STREAM_PLAYBACK) {
		reg = MAP_DATAPATH_FLOW_CTRL_REG_3;
		val = map_raw_read(map_priv, reg);

		if (mute) {
			mmp_map_dsp1_mute(map_priv, mute, AUX);
			mmp_map_dsp2_mute(map_priv, mute, AUX);
		} else {
			/* check if dsp bypass mode */
			if (((val >> 16) & 0xf) == 7)
				mmp_map_dsp1_mute(map_priv, mute, AUX);
			else if (((val >> 16) & 0xf) == 8)
				mmp_map_dsp2_mute(map_priv, mute, AUX);
		}
	} else {
		reg = MAP_DATAPATH_FLOW_CTRL_REG_2;
		val = map_raw_read(map_priv, reg);

		if (mute)
			mmp_map_dsp1a_mute(map_priv, mute, AUX);
		else {
			/* check if dsp bypass mode */
			if (((val >> 8) & 0x7) == 3)
				mmp_map_dsp1a_mute(map_priv, mute, AUX);
			if (((val >> 11) & 0x7) == 3)
				mmp_map_dsp1a_mute(map_priv, mute, AUX);
		}
	}
	return 0;
}

static int mmp_map2_pdm_mute(struct snd_soc_dai *dai, int mute, int direction)
{
	struct map_be_dai_private *be_dai_priv = snd_soc_dai_get_drvdata(dai);
	struct map_private *map_priv = be_dai_priv->map_priv;
	unsigned int reg, val;

	reg = PDM_CTRL;
	val = map_raw_read(map_priv, reg);

	if (!(val & 0x80)) {
		/* pout1 is selected */
		reg = MAP_DATAPATH_FLOW_CTRL_REG_1;
		val = map_raw_read(map_priv, reg);
		val = (val >> 16) & 0xf;

		/* check if dsp bypass mode */
		if ((val == 0) || (val == 7))
			mmp_map_dsp1_mute(map_priv, mute, OUT1);
		else if (val == 5)
			mmp_map_dsp2_mute(map_priv, mute, OUT1);
		else if (val == 6) {
			mmp_map_dsp1_mute(map_priv, mute, OUT1);
			mmp_map_dsp2_mute(map_priv, mute, OUT1);
		}
	} else {
		/* pout2 is selected */
		reg = MAP_DATAPATH_FLOW_CTRL_REG_1;
		val = map_raw_read(map_priv, reg);
		val = (val >> 20) & 0xf;

		/* check if dsp bypass mode */
		if ((val == 0) || (val == 7))
			mmp_map_dsp2_mute(map_priv, mute, OUT2);
		else if (val == 5)
			mmp_map_dsp1_mute(map_priv, mute, OUT2);
		else if (val == 6) {
			mmp_map_dsp1_mute(map_priv, mute, OUT2);
			mmp_map_dsp2_mute(map_priv, mute, OUT2);
		}
	}

	return 0;
}


static int mmp_map2_dmic_mute(struct snd_soc_dai *dai, int mute, int direction)
{
	struct map_be_dai_private *be_dai_priv = snd_soc_dai_get_drvdata(dai);
	struct map_private *map_priv = be_dai_priv->map_priv;
	unsigned int reg, val;

	reg = MAP_ADC_PROCESSING_REG;
	val = map_raw_read(map_priv, reg);
	/* Fixme: check if dsp bypass mode */
	if (!(val & 0x2400) && (mute == 0))
		return 0;

	if (dai->id == 3)
		mmp_map_dsp1a_mute(map_priv, mute, IN1);
	else  if (dai->id == 4)
		mmp_map_dsp1a_mute(map_priv, mute, IN2);

	return 0;
}

static struct snd_soc_dai_ops mmp_map2_be_ops = {
	.startup	= mmp_map2_be_startup,
	.shutdown	= mmp_map2_be_shutdown,
	.trigger	= mmp_map2_be_trigger,
	.hw_params	= mmp_map2_be_hw_params,
	.set_sysclk	= mmp_map2_set_be_dai_sysclk,
	.set_clkdiv     = mmp_map2_set_be_dai_clkdiv,
	.set_fmt	= mmp_map2_set_be_dai_fmt,
	.set_channel_map = mmp_map2_be_set_channel_map,
	.mute_stream	= mmp_map2_aux_mute,
};

static struct snd_soc_dai_ops mmp_map2_be_pdm_ops = {
	.startup	= mmp_map2_be_startup,
	.shutdown	= mmp_map2_be_shutdown,
	.trigger	= mmp_map2_be_trigger,
	.hw_params	= mmp_map2_be_hw_params,
	.set_sysclk	= mmp_map2_set_be_dai_sysclk,
	.set_clkdiv     = mmp_map2_set_be_dai_clkdiv,
	.set_fmt	= mmp_map2_set_be_dai_fmt,
	.set_channel_map = mmp_map2_be_set_channel_map,
	.mute_stream	= mmp_map2_pdm_mute,
};

static struct snd_soc_dai_ops mmp_map2_be_dmic_ops = {
	.startup	= mmp_map2_be_startup,
	.shutdown	= mmp_map2_be_shutdown,
	.trigger	= mmp_map2_be_trigger,
	.hw_params	= mmp_map2_be_hw_params,
	.set_sysclk	= mmp_map2_set_be_dai_sysclk,
	.set_clkdiv     = mmp_map2_set_be_dai_clkdiv,
	.set_fmt	= mmp_map2_set_be_dai_fmt,
	.set_channel_map = mmp_map2_be_set_channel_map,
	.mute_stream	= mmp_map2_dmic_mute,
};

struct snd_soc_dai_driver mmp_map2_be_dais[] = {
	/* map be cpu dai */
	{
		.name = "map-be-aux-dai",
		.id = 1,
		.playback = {
			.stream_name  = "BT_VC_DL",
			.channels_min = 1,
			.channels_max = 128,
			.rates = MMP_MAP_RATES,
			.formats = MMP_MAP_FORMATS,
		},
		.capture = {
			.stream_name  = "BT_VC_UL",
			.channels_min = 1,
			.channels_max = 2,
			.rates = MMP_MAP_RATES,
			.formats = MMP_MAP_FORMATS,
		},
		.ops = &mmp_map2_be_ops,
	},
	{
		.name = "map-be-pdm-out",
		.id = 2,
		.playback = {
			.stream_name  = "PDM_OUT",
			.channels_min = 1,
			.channels_max = 2,
			.rates = MMP_MAP_RATES,
			.formats = MMP_MAP_FORMATS,
		},
		.ops = &mmp_map2_be_pdm_ops,
	},
	{
		.name = "map-be-dmic12",
		.id = 3,
		.capture = {
			.stream_name  = "DMIC12_PDM",
			.channels_min = 1,
			.channels_max = 2,
			.rates = MMP_MAP_RATES,
			.formats = MMP_MAP_FORMATS,
		},
		.ops = &mmp_map2_be_dmic_ops,
	},
	{
		.name = "map-be-dmic34",
		.id = 4,
		.capture = {
			.stream_name  = "DMIC34_PDM",
			.channels_min = 1,
			.channels_max = 2,
			.rates = MMP_MAP_RATES,
			.formats = MMP_MAP_FORMATS,
		},
		.ops = &mmp_map2_be_dmic_ops,
	},
};

static const struct snd_soc_component_driver mmp_map2_be_component = {
	.name           = "mmp-map-be-v2",
};

static int mmp_map2_be_dai_probe(struct platform_device *pdev)
{
	struct map_private *map_priv = dev_get_drvdata(pdev->dev.parent);
	struct map_be_dai_private *map_be_dai_priv;
	int ret;

	map_be_dai_priv = devm_kzalloc(&pdev->dev,
		sizeof(struct map_be_dai_private), GFP_KERNEL);
	if (map_be_dai_priv == NULL)
		return -ENOMEM;

	map_be_dai_priv->map_priv = map_priv;

	map_be_dai_priv->dai_fmt = (unsigned int) -1;
	platform_set_drvdata(pdev, map_be_dai_priv);

	ret = snd_soc_register_component(&pdev->dev, &mmp_map2_be_component,
				mmp_map2_be_dais, ARRAY_SIZE(mmp_map2_be_dais));
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to register MAP be dai\n");
		return ret;
	}

	return ret;
}

static int mmp_map2_be_dai_remove(struct platform_device *pdev)
{
	snd_soc_unregister_component(&pdev->dev);
	return 0;
}

static struct platform_driver mmp_map2_be_dai_driver = {
	.driver = {
		.name = "mmp-map-be-v2",
		.owner = THIS_MODULE,
	},
	.probe = mmp_map2_be_dai_probe,
	.remove = mmp_map2_be_dai_remove,
};

module_platform_driver(mmp_map2_be_dai_driver);

MODULE_AUTHOR("Leilei Shang<shangll@marvell.com>");
MODULE_DESCRIPTION("MMP MAP 2.0 BE DAI Interface");
