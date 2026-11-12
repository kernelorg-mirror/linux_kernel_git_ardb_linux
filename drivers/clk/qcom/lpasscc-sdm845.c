// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_clock.h>
#include <linux/pm_runtime.h>
#include <linux/module.h>
#include <linux/regmap.h>

#include <dt-bindings/clock/qcom,lpass-sdm845.h>

#include "clk-regmap.h"
#include "clk-branch.h"

static struct clk_branch lpass_q6ss_ahbm_aon_clk = {
	.halt_reg = 0x12000,
	.halt_check = BRANCH_VOTED,
	.clkr = {
		.enable_reg = 0x12000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "lpass_q6ss_ahbm_aon_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch lpass_q6ss_ahbs_aon_clk = {
	.halt_reg = 0x1f000,
	.halt_check = BRANCH_VOTED,
	.clkr = {
		.enable_reg = 0x1f000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "lpass_q6ss_ahbs_aon_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch lpass_qdsp6ss_core_clk = {
	.halt_reg = 0x20,
	/* CLK_OFF would not toggle until LPASS is out of reset */
	.halt_check = BRANCH_HALT_SKIP,
	.clkr = {
		.enable_reg = 0x20,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "lpass_qdsp6ss_core_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch lpass_qdsp6ss_xo_clk = {
	.halt_reg = 0x38,
	/* CLK_OFF would not toggle until LPASS is out of reset */
	.halt_check = BRANCH_HALT_SKIP,
	.clkr = {
		.enable_reg = 0x38,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "lpass_qdsp6ss_xo_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch lpass_qdsp6ss_sleep_clk = {
	.halt_reg = 0x3c,
	/* CLK_OFF would not toggle until LPASS is out of reset */
	.halt_check = BRANCH_HALT_SKIP,
	.clkr = {
		.enable_reg = 0x3c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "lpass_qdsp6ss_sleep_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static const struct regmap_config lpass_cc_regmap_config = {
	.name		= "cc",
	.reg_bits	= 32,
	.reg_stride	= 4,
	.val_bits	= 32,
	.fast_io	= true,
};

static const struct regmap_config lpass_qdsp6ss_regmap_config = {
	.name		= "qdsp6ss",
	.reg_bits	= 32,
	.reg_stride	= 4,
	.val_bits	= 32,
	.fast_io	= true,
};

static struct clk_regmap *lpass_cc_sdm845_clocks[] = {
	[LPASS_Q6SS_AHBM_AON_CLK] = &lpass_q6ss_ahbm_aon_clk.clkr,
	[LPASS_Q6SS_AHBS_AON_CLK] = &lpass_q6ss_ahbs_aon_clk.clkr,
	[LPASS_QDSP6SS_XO_CLK] = &lpass_qdsp6ss_xo_clk.clkr,
	[LPASS_QDSP6SS_SLEEP_CLK] = &lpass_qdsp6ss_sleep_clk.clkr,
	[LPASS_QDSP6SS_CORE_CLK] = &lpass_qdsp6ss_core_clk.clkr,
};

/* Register the clocks @first to @last, which are in MMIO region @index */
static int lpass_cc_sdm845_register(struct platform_device *pdev, int index,
				    const struct regmap_config *config,
				    unsigned int first, unsigned int last)
{
	struct regmap *regmap;
	void __iomem *base;
	unsigned int i;
	int ret;

	base = devm_platform_ioremap_resource(pdev, index);
	if (IS_ERR(base))
		return PTR_ERR(base);

	regmap = devm_regmap_init_mmio(&pdev->dev, base, config);
	if (IS_ERR(regmap))
		return PTR_ERR(regmap);

	for (i = first; i <= last; i++) {
		lpass_cc_sdm845_clocks[i]->regmap = regmap;
		ret = devm_clk_hw_register(&pdev->dev,
					   &lpass_cc_sdm845_clocks[i]->hw);
		if (ret)
			return ret;
	}

	return 0;
}

static struct clk_hw *lpass_cc_sdm845_hw_get(struct of_phandle_args *clkspec,
					     void *data)
{
	unsigned int idx = clkspec->args[0];

	if (idx >= ARRAY_SIZE(lpass_cc_sdm845_clocks))
		return ERR_PTR(-EINVAL);

	return &lpass_cc_sdm845_clocks[idx]->hw;
}

/*
 * The registers are only accessible while GCC_LPASS_SWAY_CLK is on. If the DT
 * describes it as the interface clock, let runtime PM turn it on and off: the
 * clock core keeps the device resumed while any of its clocks is prepared,
 * and while it accesses the registers otherwise. Without autosuspend, it is
 * turned off as soon as the last clock is unprepared, e.g., before the LPASS
 * is reset when the ADSP is stopped, which turns it off as well.
 */
static int lpass_cc_sdm845_pm_init(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct clk *iface;
	int ret;

	if (!of_property_present(dev->of_node, "clocks"))
		return 0;

	ret = devm_pm_runtime_enable(dev);
	if (ret)
		return ret;

	ret = devm_pm_clk_create(dev);
	if (ret)
		return ret;

	iface = clk_get(dev, "iface");
	if (IS_ERR(iface))
		return dev_err_probe(dev, PTR_ERR(iface),
				     "failed to get the interface clock\n");

	ret = pm_clk_add_clk(dev, iface);
	if (ret)
		clk_put(iface);

	return ret;
}

static int lpass_cc_sdm845_probe(struct platform_device *pdev)
{
	int ret;

	/* Runtime PM must be enabled before the clocks are registered */
	ret = lpass_cc_sdm845_pm_init(pdev);
	if (ret)
		return ret;

	ret = lpass_cc_sdm845_register(pdev, 0, &lpass_cc_regmap_config,
				       LPASS_Q6SS_AHBM_AON_CLK,
				       LPASS_Q6SS_AHBS_AON_CLK);
	if (ret)
		return ret;

	ret = lpass_cc_sdm845_register(pdev, 1, &lpass_qdsp6ss_regmap_config,
				       LPASS_QDSP6SS_XO_CLK,
				       LPASS_QDSP6SS_CORE_CLK);
	if (ret)
		return ret;

	/*
	 * Use a single provider for the clocks in both regions: with one for
	 * each, the clocks of one region would be looked up in the provider for
	 * the other, which returns NULL for clocks it doesn't have, so that
	 * consumers would get a dummy clock.
	 */
	return devm_of_clk_add_hw_provider(&pdev->dev, lpass_cc_sdm845_hw_get,
					   NULL);
}

static const struct of_device_id lpass_cc_sdm845_match_table[] = {
	{ .compatible = "qcom,sdm845-lpasscc" },
	{ }
};
MODULE_DEVICE_TABLE(of, lpass_cc_sdm845_match_table);

static const struct dev_pm_ops lpass_cc_sdm845_pm_ops = {
	RUNTIME_PM_OPS(pm_clk_suspend, pm_clk_resume, NULL)
};

static struct platform_driver lpass_cc_sdm845_driver = {
	.probe		= lpass_cc_sdm845_probe,
	.driver		= {
		.name	= "sdm845-lpasscc",
		.of_match_table = lpass_cc_sdm845_match_table,
		.pm	= pm_ptr(&lpass_cc_sdm845_pm_ops),
	},
};

subsys_platform_driver(lpass_cc_sdm845_driver);

MODULE_DESCRIPTION("QTI LPASS_CC SDM845 Driver");
MODULE_LICENSE("GPL v2");
