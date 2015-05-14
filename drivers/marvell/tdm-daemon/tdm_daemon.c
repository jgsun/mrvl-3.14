/*
 * Copyright (c) [2009-2013] Marvell International Ltd. and its affiliates. All rights reserved.
 * This software file (the "File") is owned and distributed by Marvell
 * International Ltd. and/or its affiliates ("Marvell") under the following
 * licensing terms.
 * If you received this File from Marvell and you have entered into a commercial
 * license agreement (a "Commercial License") with Marvell, the File is licensed
 * to you under the terms of the applicable Commercial License.
 *
 */
#include <stdarg.h>
#include <linux/types.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/of_device.h>
#include "tee_client_api.h"

#define	TDM_DEFAULT_EXPIRE_TIME	30
#define	TDM_DAEMON_SCHED_TIME	20
#define	TDM_DUMP_MAX_COUNT 10
enum action_type {
	TDM_CRASH_ACTION_RESET = 1,
	TDM_CRASH_ACTION_CLAIM_USB
};

static int tdm_enable;
static int tdm_expire_time = TDM_DEFAULT_EXPIRE_TIME;
static struct workqueue_struct *tdm_wq;
static struct delayed_work tdm_work;
static enum action_type tdm_action = TDM_CRASH_ACTION_RESET;

#define TEE_TDM_CMD_KICKWD      (0x00000001)
#define TEE_TDM_CMD_STOPWD      (0x00000002)
#define TEE_TDM_CMD_SET_DBGDATA_REGION   (0x00000005)

#define TZDD_NAME "tzdd"

#define TEE_TDM_SRV_UUID \
{ 0x00000011,    \
	0x0000,        \
	0x0000,        \
	{            \
		0x00,    \
		0x00,    \
		0x00,    \
		0x00,    \
		0x00,    \
		0x00,    \
		0x00,    \
		0x00,    \
	},           \
}

typedef struct _TDMDbgDataRegion {
	uint8_t  desc[8];
	uint32_t addr;
	uint32_t size;
} TDMDbgDataRegion;

static TDMDbgDataRegion tdm_dump_data[TDM_DUMP_MAX_COUNT];
static const TEEC_UUID _g_TDM_TEEApp = TEE_TDM_SRV_UUID;
static TEEC_Context g_tdm_tee_cntx;
static TEEC_Session g_tdm_tee_ss;

static TEEC_Result _call_tee(uint32_t cmd, uint32_t ms, uint32_t crash_action)
{
	TEEC_Result result;
	TEEC_Operation operation;

	if (cmd == TEE_TDM_CMD_KICKWD) {
		operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
				TEEC_NONE, TEEC_NONE, TEEC_NONE);
		operation.params[0].value.a = ms;
		operation.params[0].value.b = crash_action;
	} else
		operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	result = TEEC_InvokeCommand(&g_tdm_tee_ss, cmd, &operation, NULL);
	if (TEEC_SUCCESS != result) {
		pr_err("TEEC_InvokeCommand[0x%x] failed: 0x%x\n", cmd, result);
		goto cleanup;
	}

	result = TEEC_SUCCESS;

cleanup:
	return result;
}


int32_t TDMKickWatchDog(uint32_t ms, uint32_t crash_action)
{
	TEEC_Result result;
	result = _call_tee(TEE_TDM_CMD_KICKWD, ms, crash_action);
	if (result != TEEC_SUCCESS)
		return -1;
	else
		return 0;
}

int32_t TDMStopWatchDog(void)
{
	TEEC_Result result;
	result = _call_tee(TEE_TDM_CMD_STOPWD, 0, 0);
	if (result != TEEC_SUCCESS)
		return -1;
	else
		return 0;
}

int32_t TDMSetDbgDataRegion(TDMDbgDataRegion *region_array, uint32_t region_count)
{
	TEEC_Result result;
	TEEC_Operation operation;
	TEEC_SharedMemory input;
	uint32_t size;

	size = region_count * sizeof(TDMDbgDataRegion);
	input.size  = size;
	input.flags = TEEC_MEM_INPUT;
	input.buffer = (uint8_t *)region_array;

	result = TEEC_RegisterSharedMemory(&g_tdm_tee_cntx, &input);
	if (result != TEEC_SUCCESS) {
		pr_err("TEEC_RegisterSharedMemory failed: 0x%x\n", result);
		goto cleanup1;
	}

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
			TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	operation.params[0].memref.parent = &input;
	operation.params[0].memref.size = size;
	operation.params[1].value.a = region_count;

	result = TEEC_InvokeCommand(&g_tdm_tee_ss,
			TEE_TDM_CMD_SET_DBGDATA_REGION, &operation, NULL);
	if (TEEC_SUCCESS != result) {
		pr_err("TEEC_InvokeCommand[0x%x] failed: 0x%x\n",
				TEE_TDM_CMD_SET_DBGDATA_REGION, result);
		goto cleanup2;
	}

	result = TEEC_SUCCESS;

cleanup2:
	TEEC_ReleaseSharedMemory(&input);
cleanup1:
	return result;
}

static ssize_t tdm_enable_read(struct file *file, char __user *buffer,
		size_t count, loff_t *ppos)
{
	pr_info("%d\n", tdm_enable);

	return 0;
}

static ssize_t tdm_enable_write(struct file *file,
		const char __user *buff,
		size_t len, loff_t *ppos)
{
	int val;

	sscanf(buff, "%d\n", &val);
	if (val < 0)
		return -EINVAL;
	val = !!val;

	if (val == tdm_enable)
		return len;

	tdm_enable = val;
	if (tdm_enable) {
		TDMKickWatchDog(tdm_expire_time * MSEC_PER_SEC, tdm_action);
		queue_delayed_work(tdm_wq, &tdm_work, TDM_DAEMON_SCHED_TIME * HZ);
	} else {
		TDMStopWatchDog();
		cancel_delayed_work_sync(&tdm_work);
	}
	return len;
}

static const struct file_operations tdm_enable_ops = {
	.read		= tdm_enable_read,
	.write		= tdm_enable_write,
};


static ssize_t tdm_action_read(struct file *file, char __user *buffer,
		size_t count, loff_t *ppos)
{
	switch (tdm_action) {
	case TDM_CRASH_ACTION_RESET:
		pr_info("TDM will trigger system reset when detect hang!\n");
		break;
	case TDM_CRASH_ACTION_CLAIM_USB:
		pr_info("TDM will set system to debug state when detect hang!\n");
		break;
	default:
		pr_info("Unknow TDM action!\n");
	}

	return 0;
}

static ssize_t tdm_action_write(struct file *file,
		const char __user *buff,
		size_t len, loff_t *ppos)
{
	int val;

	sscanf(buff, "%d\n", &val);
	if ((val != TDM_CRASH_ACTION_RESET) && (val != TDM_CRASH_ACTION_CLAIM_USB)) {
		pr_err("There are only two tdm actions supported.\n1 - RESET 2 - CLAIM_USB");
		return -EINVAL;
	}

	if (val != tdm_action)
		tdm_action = val;

	return len;
}

static const struct file_operations tdm_action_ops = {
	.read		= tdm_action_read,
	.write		= tdm_action_write,
};

static ssize_t tdm_expire_time_read(struct file *file, char __user *buffer,
		size_t count, loff_t *ppos)
{
	pr_info("TDM watch dog expire time is %ds\n", tdm_expire_time);

	return 0;
}

static ssize_t tdm_expire_time_write(struct file *file,
		const char __user *buff,
		size_t len, loff_t *ppos)
{
	int val;

	sscanf(buff, "%d", &val);

	if (val < TDM_DEFAULT_EXPIRE_TIME)
		val = TDM_DEFAULT_EXPIRE_TIME;
	if (val != tdm_expire_time)
		tdm_expire_time = val;

	return len;
}

static const struct file_operations tdm_expire_time_ops = {
	.read		= tdm_expire_time_read,
	.write		= tdm_expire_time_write,
};

static inline void tdm_debugfs_init(void)
{
	struct dentry *tdm_action_dentry, *tdm_expire_time_dentry, *tdm_enable_dentry;

	tdm_enable_dentry = debugfs_create_file("tdm_enable", S_IRUGO | S_IFREG,
			NULL, NULL, &tdm_enable_ops);
	if (!tdm_enable_dentry || (tdm_enable_dentry == ERR_PTR(-ENODEV)))
		pr_err("TDM: create enable debugfs failed\n.");

	tdm_action_dentry = debugfs_create_file("tdm_action", S_IRUGO | S_IFREG,
			NULL, NULL, &tdm_action_ops);
	if (!tdm_action_dentry || (tdm_action_dentry == ERR_PTR(-ENODEV)))
		pr_err("TDM: create action debugfs failed\n.");

	tdm_expire_time_dentry = debugfs_create_file("tdm_expire_time", S_IRUGO | S_IFREG,
			NULL, NULL, &tdm_expire_time_ops);
	if (!tdm_expire_time_dentry || (tdm_expire_time_dentry == ERR_PTR(-ENODEV)))
		pr_err("TDM: create expire time debugfs failed.\n");

	return;
}

static void tdm_kick_work_func(struct work_struct *work)
{
	if (!tdm_enable)
		return;

	pr_debug("TDM work daemon kick tdm watchdog\n");
	TDMKickWatchDog(tdm_expire_time * MSEC_PER_SEC, tdm_action);
	/*
	 * set workqueue scheduled intval
	 * be sure the intval < timeout to feed wdt timely
	 */
	queue_delayed_work(tdm_wq, &tdm_work, TDM_DAEMON_SCHED_TIME * HZ);
}

static int tdm_set_dump_format(struct platform_device *pdev)
{
	int dump_count, i = 0;
	struct device_node *np, *child_np;
	const char *desc;

	np = pdev->dev.of_node;

	dump_count = of_get_child_count(np);
	if (!dump_count) {
		dev_notice(&pdev->dev, "%s, tdm use default debug data format\n", __func__);
		return 0;
	}

	for_each_child_of_node(np, child_np) {
		if (of_property_read_string(child_np, "description", &desc))
			return -EINVAL;
		strncpy(tdm_dump_data[i].desc, desc, 8);
		if (of_property_read_u32(child_np, "addr", &tdm_dump_data[i].addr))
			return -EINVAL;
		if (of_property_read_u32(child_np, "size", &tdm_dump_data[i].size))
			return -EINVAL;
		i++;
	}

	TDMSetDbgDataRegion(tdm_dump_data, dump_count);

	return 0;
}

static int tdm_tzdd_init(void)
{
	TEEC_Result result;

	result = TEEC_InitializeContext(TZDD_NAME, &g_tdm_tee_cntx);
	if (result != TEEC_SUCCESS) {
		pr_err("TEEC_InitializeContext failed: 0x%x\n", result);
		goto err_cleanup1;
	}

	result = TEEC_OpenSession(&g_tdm_tee_cntx, &g_tdm_tee_ss, &_g_TDM_TEEApp,
			TEEC_LOGIN_APPLICATION, NULL, NULL, NULL);
	if (result != TEEC_SUCCESS) {
		pr_err("TEEC_OpenSession failed: 0x%x\n", result);
		goto err_cleanup2;
	}

	return 0;

err_cleanup2:
	TEEC_FinalizeContext(&g_tdm_tee_cntx);
err_cleanup1:
	return -1;
}

static int tdm_probe(struct platform_device *pdev)
{
	int ret;

	ret = tdm_tzdd_init();
	if (ret) {
		dev_err(&pdev->dev, "tdm tzdd fail\n");
		goto err;
	}

	tdm_set_dump_format(pdev);

	INIT_DELAYED_WORK(&tdm_work, tdm_kick_work_func);
	tdm_wq = alloc_workqueue("tdm_workqueue", WQ_HIGHPRI |
			WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!tdm_wq) {
		dev_err(&pdev->dev, "tdm alloc_workqueue failed\n");
		ret = -ENOMEM;
		goto err;
	}

	tdm_debugfs_init();

	if (tdm_enable) {
		TDMKickWatchDog(tdm_expire_time * MSEC_PER_SEC, tdm_action); /* default 30s */
		queue_delayed_work(tdm_wq, &tdm_work, TDM_DAEMON_SCHED_TIME * HZ);
	}
	return 0;

err:
	return ret;
}

static int tdm_remove(struct platform_device *pdev)
{
	if (tdm_enable)
		TDMStopWatchDog();
	TEEC_CloseSession(&g_tdm_tee_ss);
	TEEC_FinalizeContext(&g_tdm_tee_cntx);

	return 0;
}

static void tdm_shutdown(struct platform_device *pdev)
{
	if (tdm_enable)
		TDMStopWatchDog();
	TEEC_CloseSession(&g_tdm_tee_ss);
	TEEC_FinalizeContext(&g_tdm_tee_cntx);

	return;
}

#ifdef CONFIG_PM
static int tdm_suspend(struct platform_device *pdev, pm_message_t state)
{
	if (tdm_enable) {
		TDMStopWatchDog();
		cancel_delayed_work_sync(&tdm_work);
	}
	return 0;
}

static int tdm_resume(struct platform_device *pdev)
{
	if (tdm_enable) {
		TDMKickWatchDog(tdm_expire_time * MSEC_PER_SEC, tdm_action);
		queue_delayed_work(tdm_wq, &tdm_work, TDM_DAEMON_SCHED_TIME * HZ);
	}

	return 0;
}

#else
#define tdm_suspend NULL
#define tdm_resume  NULL
#endif /* CONFIG_PM */

#ifdef CONFIG_OF
static const struct of_device_id pxa_tdm_match[] = {
	{ .compatible = "marvell,pxa-tdm", .data = NULL},
	{},
};
MODULE_DEVICE_TABLE(of, pxa_tdm_match);
#endif

static struct platform_driver tdm_driver = {
	.probe		= tdm_probe,
	.remove		= tdm_remove,
	.shutdown	= tdm_shutdown,
	.suspend	= tdm_suspend,
	.resume		= tdm_resume,
	.driver		= {
		.name	= "pxa-tdm",
		.of_match_table	= of_match_ptr(pxa_tdm_match),
	},
};

module_platform_driver(tdm_driver);
MODULE_AUTHOR("Xiaolong Ye<yexl@marvell.com>, ");
MODULE_DESCRIPTION("TDM Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:tdm");
