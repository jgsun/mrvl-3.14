/*
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
#include <linux/pxa2xx_ssp.h>
#include <linux/io.h>
#include <linux/of.h>

#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/initval.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/dmaengine_pcm.h>
#include "mmp-sspa.h"

/*
 * SSPA audio private data
 */
struct sspa_priv {
	struct ssp_device *sspa;
	struct snd_dmaengine_dai_dma_data *dma_params;
	unsigned int burst_size;
};

/*
 * Set the SSPA audio DMA parameters and sample size.
 * Can be called multiple times by oss emulation.
 */
static int mmp_sspa_dummy_hw_params(struct snd_pcm_substream *substream,
			       struct snd_pcm_hw_params *params,
			       struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	struct sspa_priv *sspa_priv = snd_soc_dai_get_drvdata(dai);
	struct ssp_device *sspa = sspa_priv->sspa;
	struct snd_dmaengine_dai_dma_data *dma_params;

	dma_params = &sspa_priv->dma_params[substream->stream];
	dma_params->addr = substream->stream == SNDRV_PCM_STREAM_PLAYBACK ?
				(sspa->phys_base + SSPA_TXD) :
				(sspa->phys_base + SSPA_RXD);

	dma_params->maxburst = sspa_priv->burst_size;
	snd_soc_dai_set_dma_data(cpu_dai, substream, dma_params);
	return 0;
}

static int mmp_sspa_dummy_probe(struct snd_soc_dai *dai)
{
	struct sspa_priv *priv = dev_get_drvdata(dai->dev);

	snd_soc_dai_set_drvdata(dai, priv);
	return 0;

}

#define MMP_SSPA_RATES SNDRV_PCM_RATE_8000_192000
#define MMP_SSPA_FORMATS (SNDRV_PCM_FMTBIT_S8 | \
		SNDRV_PCM_FMTBIT_S16_LE | \
		SNDRV_PCM_FMTBIT_S24_LE | \
		SNDRV_PCM_FMTBIT_S24_LE | \
		SNDRV_PCM_FMTBIT_S32_LE)

static struct snd_soc_dai_ops mmp_sspa_dummy_dai_ops = {
	.hw_params	= mmp_sspa_dummy_hw_params,
};

static struct snd_soc_dai_driver mmp_sspa_dummy_dai = {
	.probe = mmp_sspa_dummy_probe,
	.playback = {
		.channels_min = 1,
		.channels_max = 128,
		.rates = MMP_SSPA_RATES,
		.formats = MMP_SSPA_FORMATS,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 2,
		.rates = MMP_SSPA_RATES,
		.formats = MMP_SSPA_FORMATS,
	},
	.ops = &mmp_sspa_dummy_dai_ops,
};

static const struct snd_soc_component_driver mmp_sspa_dummy_component = {
	.name		= "mmp-sspa-dummy",
};

#ifdef CONFIG_OF
static const struct of_device_id pxa_ssp_dummy_of_ids[] = {
	{ .compatible = "mrvl,mmp-sspa-dai-dummy", },
};
#endif


static int asoc_mmp_sspa_dummy_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct sspa_priv *priv;
	struct resource *res;
	char const *platform_driver_name;
	int ret;

	priv = devm_kzalloc(&pdev->dev,
				sizeof(struct sspa_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->sspa = devm_kzalloc(&pdev->dev,
				sizeof(struct ssp_device), GFP_KERNEL);
	if (priv->sspa == NULL)
		return -ENOMEM;

	priv->sspa->pdev = pdev;
	priv->dma_params = devm_kzalloc(&pdev->dev,
			2 * sizeof(struct snd_dmaengine_dai_dma_data),
			GFP_KERNEL);
	if (priv->dma_params == NULL)
		return -ENOMEM;


	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		dev_err(&pdev->dev, "no memory resource defined\n");
		return -ENODEV;
	}

	priv->sspa->mmio_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(priv->sspa->mmio_base))
		return PTR_ERR(priv->sspa->mmio_base);

	priv->sspa->phys_base = res->start;

	if (of_property_read_string(np,
				"platform_driver_name",
				&platform_driver_name)) {
		dev_err(&pdev->dev,
			"Missing platform_driver_name property in the DT\n");
		return -EINVAL;
	}

	if (of_property_read_u32(np, "burst_size",
				     &priv->burst_size)) {
		dev_err(&pdev->dev,
			"Missing DMA burst size\n");
		return -EINVAL;
	}

	platform_set_drvdata(pdev, priv);

	ret = devm_snd_soc_register_component(&pdev->dev, &mmp_sspa_dummy_component,
					       &mmp_sspa_dummy_dai, 1);
	if (ret != 0) {
		dev_err(&pdev->dev, "Failed to register DAI\n");
		return ret;
	}

	if (strcmp(platform_driver_name, "tdma_platform") == 0)
		ret = mmp_pcm_platform_register(&pdev->dev);

	return ret;
}

static int asoc_mmp_sspa_dummy_remove(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	char const *platform_driver_name;

	if (of_property_read_string(np,
				"platform_driver_name",
				&platform_driver_name)) {
		dev_err(&pdev->dev,
			"Missing platform_driver_name property in the DT\n");
		return -EINVAL;
	}

	if (strcmp(platform_driver_name, "tdma_platform") == 0)
		mmp_pcm_platform_unregister(&pdev->dev);

	return 0;
}

static struct platform_driver asoc_mmp_sspa_dummy_driver = {
	.driver = {
		.name = "mmp-sspa-dai-dummy",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(pxa_ssp_dummy_of_ids),
	},
	.probe = asoc_mmp_sspa_dummy_probe,
	.remove = asoc_mmp_sspa_dummy_remove,
};

module_platform_driver(asoc_mmp_sspa_dummy_driver);

MODULE_AUTHOR("Leilei Shang <shangll@marvell.com>");
MODULE_DESCRIPTION("MMP SSPA DUMMY SoC Interface");
MODULE_LICENSE("GPL v2");
