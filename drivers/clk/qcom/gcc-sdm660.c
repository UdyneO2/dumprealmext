// SPDX-License-Identifier: GPL-2.0-only
/*
<<<<<<< HEAD
 * Copyright (c) 2016-2017, 2019-2020, The Linux Foundation. All rights reserved.
=======
 * Copyright (c) 2016-2017, 2019-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
 */

#include <linux/bitops.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/regmap.h>
#include <linux/reset-controller.h>
#include <dt-bindings/clock/qcom,gcc-sdm660.h>
#include <linux/mfd/syscon.h>

#include "clk-pll.h"
#include "clk-alpha-pll.h"
#include "clk-branch.h"
#include "clk-debug.h"
#include "common.h"
#include "clk-regmap.h"
#include "clk-rcg.h"
#include "reset.h"
#include "vdd-level-660.h"

static DEFINE_VDD_REGULATORS(vdd_dig, VDD_DIG_NUM, 1, vdd_corner);
static DEFINE_VDD_REGULATORS(vdd_dig_ao, VDD_DIG_NUM, 1, vdd_corner);

enum {
	P_XO,
	P_CORE_BI_PLL_TEST_SE,
	P_GPLL0_OUT_MAIN,
	P_GPLL1_OUT_MAIN,
	P_GPLL4_OUT_MAIN,
	P_PLL0_EARLY_DIV_CLK_SRC,
	P_PLL1_EARLY_DIV_CLK_SRC,
	P_SLEEP_CLK,
};

static const struct parent_map gcc_parent_map_0[] = {
	{ P_XO, 0 },
	{ P_GPLL0_OUT_MAIN, 1 },
	{ P_PLL0_EARLY_DIV_CLK_SRC, 6 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const char * const gcc_parent_names_0[] = {
	"xo",
	"gpll0_out_main",
	"gpll0_out_early_div",
	"core_bi_pll_test_se",
};

static const struct parent_map gcc_parent_map_1[] = {
	{ P_XO, 0 },
	{ P_GPLL0_OUT_MAIN, 1 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const char * const gcc_parent_names_1[] = {
	"xo",
	"gpll0_out_main",
	"core_bi_pll_test_se",
};

static const char * const gcc_parent_names_ao_1[] = {
	"cxo_a",
	"gpll0_ao_out_main",
	"core_bi_pll_test_se",
};

static const struct parent_map gcc_parent_map_2[] = {
	{ P_XO, 0 },
	{ P_GPLL0_OUT_MAIN, 1 },
	{ P_SLEEP_CLK, 5 },
	{ P_PLL0_EARLY_DIV_CLK_SRC, 6 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const char * const gcc_parent_names_2[] = {
	"xo",
	"gpll0_out_main",
	"core_pi_sleep_clk",
	"gpll0_out_early_div",
	"core_bi_pll_test_se",
};

static const struct parent_map gcc_parent_map_3[] = {
	{ P_XO, 0 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const char * const gcc_parent_names_3[] = {
	"xo",
	"core_bi_pll_test_se",
};

static const struct parent_map gcc_parent_map_4[] = {
	{ P_XO, 0 },
	{ P_SLEEP_CLK, 5 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const char * const gcc_parent_names_4[] = {
	"xo",
	"core_pi_sleep_clk",
	"core_bi_pll_test_se",
};

static const struct parent_map gcc_parent_map_5[] = {
	{ P_XO, 0 },
	{ P_GPLL4_OUT_MAIN, 5 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const char * const gcc_parent_names_5[] = {
	"xo",
	"gpll4_out_main",
	"core_bi_pll_test_se",
};

static const struct parent_map gcc_parent_map_6[] = {
	{ P_XO, 0 },
	{ P_GPLL0_OUT_MAIN, 1 },
	{ P_PLL0_EARLY_DIV_CLK_SRC, 3 },
	{ P_GPLL1_OUT_MAIN, 4 },
	{ P_GPLL4_OUT_MAIN, 5 },
	{ P_PLL1_EARLY_DIV_CLK_SRC, 6 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const char * const gcc_parent_names_6[] = {
	"xo",
	"gpll0_out_main",
	"gpll0_out_early_div",
	"gpll1_out_main",
	"gpll4_out_main",
	"gpll1_out_early_div",
	"core_bi_pll_test_se",
};

static const struct parent_map gcc_parent_map_7[] = {
	{ P_XO, 0 },
	{ P_GPLL0_OUT_MAIN, 1 },
	{ P_GPLL4_OUT_MAIN, 5 },
	{ P_PLL0_EARLY_DIV_CLK_SRC, 6 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const char * const gcc_parent_names_7[] = {
	"xo",
	"gpll0_out_main",
	"gpll4_out_main",
	"gpll0_out_early_div",
	"core_bi_pll_test_se",
};

static const struct parent_map gcc_parent_map_8[] = {
	{ P_XO, 0 },
	{ P_GPLL0_OUT_MAIN, 1 },
	{ P_PLL0_EARLY_DIV_CLK_SRC, 2 },
	{ P_GPLL4_OUT_MAIN, 5 },
	{ P_CORE_BI_PLL_TEST_SE, 7 },
};

static const char * const gcc_parent_names_8[] = {
	"xo",
	"gpll0_out_main",
	"gpll0_out_early_div",
	"gpll4_out_main",
	"core_bi_pll_test_se",
};

static struct clk_fixed_factor xo = {
	.mult = 1,
	.div = 1,
	.hw.init = &(struct clk_init_data){
		.name = "xo",
		.parent_names = (const char *[]){ "cxo" },
		.num_parents = 1,
		.ops = &clk_fixed_factor_ops,
	},
};

static unsigned int soft_vote_gpll0;

static struct clk_alpha_pll gpll0_out_main = {
	.offset = 0x0,
	.soft_vote = &soft_vote_gpll0,
	.soft_vote_mask = PLL_SOFT_VOTE_PRIMARY,
	.flags = SUPPORTS_FSM_VOTE,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_DEFAULT],
	.clkr = {
		.enable_reg = 0x52000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gpll0_out_main",
			.parent_names = (const char *[]){ "xo" },
			.num_parents = 1,
			.ops = &clk_alpha_pll_ops,
		},
	},
};

static struct clk_alpha_pll gpll0_ao_out_main = {
	.offset = 0x0,
	.soft_vote = &soft_vote_gpll0,
	.soft_vote_mask = PLL_SOFT_VOTE_CPU,
	.flags = SUPPORTS_FSM_VOTE,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_DEFAULT],
	.clkr = {
		.enable_reg = 0x52000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gpll0_ao_out_main",
			.parent_names = (const char *[]){ "cxo_a" },
			.num_parents = 1,
			.ops = &clk_alpha_pll_ops,
		},
	},
};

static struct clk_fixed_factor gpll0_out_early_div = {
	.mult = 1,
	.div = 2,
	.hw.init = &(struct clk_init_data){
		.name = "gpll0_out_early_div",
		.parent_names = (const char *[]){ "gpll0_out_main" },
		.num_parents = 1,
		.ops = &clk_fixed_factor_ops,
	},
};

static struct clk_alpha_pll gpll1_out_main = {
	.offset = 0x1000,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_DEFAULT],
	.clkr = {
		.enable_reg = 0x52000,
		.enable_mask = BIT(1),
		.hw.init = &(struct clk_init_data){
			.name = "gpll1_out_main",
			.parent_names = (const char *[]){ "xo" },
			.num_parents = 1,
			.ops = &clk_alpha_pll_ops,
		},
	},
};

static struct clk_fixed_factor gpll1_out_early_div = {
	.mult = 1,
	.div = 2,
	.hw.init = &(struct clk_init_data){
		.name = "gpll1_out_early_div",
		.parent_names = (const char *[]){ "gpll1_out_main" },
		.num_parents = 1,
		.ops = &clk_fixed_factor_ops,
	},
};

static struct clk_alpha_pll gpll4_out_main = {
	.offset = 0x77000,
	.regs = clk_alpha_pll_regs[CLK_ALPHA_PLL_TYPE_DEFAULT],
	.clkr = {
		.enable_reg = 0x52000,
		.enable_mask = BIT(4),
		.hw.init = &(struct clk_init_data){
			.name = "gpll4_out_main",
			.parent_names = (const char *[]){ "xo" },
			.num_parents = 1,
			.ops = &clk_alpha_pll_ops,
		},
	},
};

static const struct freq_tbl ftbl_blsp1_qup1_i2c_apps_clk_src[] = {
	F(19200000, P_XO, 1, 0, 0),
	F(50000000, P_GPLL0_OUT_MAIN, 12, 0, 0),
	{ }
};

static struct clk_rcg2 blsp1_qup1_i2c_apps_clk_src = {
	.cmd_rcgr = 0x19020,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_blsp1_qup1_i2c_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_qup1_i2c_apps_clk_src",
		.parent_names = gcc_parent_names_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 50000000),
	},
};

static const struct freq_tbl ftbl_blsp1_qup1_spi_apps_clk_src[] = {
	F(960000, P_XO, 10, 1, 2),
	F(4800000, P_XO, 4, 0, 0),
	F(9600000, P_XO, 2, 0, 0),
	F(15000000, P_GPLL0_OUT_MAIN, 10, 1, 4),
	F(19200000, P_XO, 1, 0, 0),
	F(25000000, P_GPLL0_OUT_MAIN, 12, 1, 2),
	F(50000000, P_GPLL0_OUT_MAIN, 12, 0, 0),
	{ }
};

static struct clk_rcg2 blsp1_qup1_spi_apps_clk_src = {
	.cmd_rcgr = 0x1900c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_qup1_spi_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_qup1_spi_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 25000000,
				NOMINAL, 50000000),
	},
};

static struct clk_rcg2 blsp1_qup2_i2c_apps_clk_src = {
	.cmd_rcgr = 0x1b020,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_blsp1_qup1_i2c_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_qup2_i2c_apps_clk_src",
		.parent_names = gcc_parent_names_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 50000000),
	},
};

static struct clk_rcg2 blsp1_qup2_spi_apps_clk_src = {
	.cmd_rcgr = 0x1b00c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_qup1_spi_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_qup2_spi_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 25000000,
				NOMINAL, 50000000),
	},
};

static struct clk_rcg2 blsp1_qup3_i2c_apps_clk_src = {
	.cmd_rcgr = 0x1d020,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_blsp1_qup1_i2c_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_qup3_i2c_apps_clk_src",
		.parent_names = gcc_parent_names_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 50000000),
	},
};

static struct clk_rcg2 blsp1_qup3_spi_apps_clk_src = {
	.cmd_rcgr = 0x1d00c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_qup1_spi_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_qup3_spi_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 25000000,
				NOMINAL, 50000000),
	},
};

static struct clk_rcg2 blsp1_qup4_i2c_apps_clk_src = {
	.cmd_rcgr = 0x1f020,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_blsp1_qup1_i2c_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_qup4_i2c_apps_clk_src",
		.parent_names = gcc_parent_names_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 50000000),
	},
};

static struct clk_rcg2 blsp1_qup4_spi_apps_clk_src = {
	.cmd_rcgr = 0x1f00c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_qup1_spi_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_qup4_spi_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 25000000,
				NOMINAL, 50000000),
	},
};

static const struct freq_tbl ftbl_blsp1_uart1_apps_clk_src[] = {
	F(3686400, P_GPLL0_OUT_MAIN, 1, 96, 15625),
	F(7372800, P_GPLL0_OUT_MAIN, 1, 192, 15625),
	F(14745600, P_GPLL0_OUT_MAIN, 1, 384, 15625),
	F(16000000, P_GPLL0_OUT_MAIN, 5, 2, 15),
	F(19200000, P_XO, 1, 0, 0),
	F(24000000, P_GPLL0_OUT_MAIN, 5, 1, 5),
	F(32000000, P_GPLL0_OUT_MAIN, 1, 4, 75),
	F(40000000, P_GPLL0_OUT_MAIN, 15, 0, 0),
	F(46400000, P_GPLL0_OUT_MAIN, 1, 29, 375),
	F(48000000, P_GPLL0_OUT_MAIN, 12.5, 0, 0),
	F(51200000, P_GPLL0_OUT_MAIN, 1, 32, 375),
	F(56000000, P_GPLL0_OUT_MAIN, 1, 7, 75),
	F(58982400, P_GPLL0_OUT_MAIN, 1, 1536, 15625),
	F(60000000, P_GPLL0_OUT_MAIN, 10, 0, 0),
	F(63157895, P_GPLL0_OUT_MAIN, 9.5, 0, 0),
	{ }
};

static struct clk_rcg2 blsp1_uart1_apps_clk_src = {
	.cmd_rcgr = 0x1a00c,
	.mnd_width = 16,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_uart1_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_uart1_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 31578947,
				NOMINAL, 63157895),
	},
};

static struct clk_rcg2 blsp1_uart2_apps_clk_src = {
	.cmd_rcgr = 0x1c00c,
	.mnd_width = 16,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_uart1_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp1_uart2_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 31578947,
				NOMINAL, 63157895),
	},
};

static struct clk_rcg2 blsp2_qup1_i2c_apps_clk_src = {
	.cmd_rcgr = 0x26020,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_blsp1_qup1_i2c_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_qup1_i2c_apps_clk_src",
		.parent_names = gcc_parent_names_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 50000000),
	},
};

static struct clk_rcg2 blsp2_qup1_spi_apps_clk_src = {
	.cmd_rcgr = 0x2600c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_qup1_spi_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_qup1_spi_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 25000000,
				NOMINAL, 50000000),
	},
};

static struct clk_rcg2 blsp2_qup2_i2c_apps_clk_src = {
	.cmd_rcgr = 0x28020,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_blsp1_qup1_i2c_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_qup2_i2c_apps_clk_src",
		.parent_names = gcc_parent_names_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 50000000),
	},
};

static struct clk_rcg2 blsp2_qup2_spi_apps_clk_src = {
	.cmd_rcgr = 0x2800c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_qup1_spi_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_qup2_spi_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 25000000,
				NOMINAL, 50000000),
	},
};

static struct clk_rcg2 blsp2_qup3_i2c_apps_clk_src = {
	.cmd_rcgr = 0x2a020,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_blsp1_qup1_i2c_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_qup3_i2c_apps_clk_src",
		.parent_names = gcc_parent_names_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 50000000),
	},
};

static struct clk_rcg2 blsp2_qup3_spi_apps_clk_src = {
	.cmd_rcgr = 0x2a00c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_qup1_spi_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_qup3_spi_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 25000000,
				NOMINAL, 50000000),
	},
};

static struct clk_rcg2 blsp2_qup4_i2c_apps_clk_src = {
	.cmd_rcgr = 0x2c020,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_blsp1_qup1_i2c_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_qup4_i2c_apps_clk_src",
		.parent_names = gcc_parent_names_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 50000000),
	},
};

static struct clk_rcg2 blsp2_qup4_spi_apps_clk_src = {
	.cmd_rcgr = 0x2c00c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_qup1_spi_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_qup4_spi_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 25000000,
				NOMINAL, 50000000),
	},
};

static struct clk_rcg2 blsp2_uart1_apps_clk_src = {
	.cmd_rcgr = 0x2700c,
	.mnd_width = 16,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_uart1_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_uart1_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 31578947,
				NOMINAL, 63157895),
	},
};

static struct clk_rcg2 blsp2_uart2_apps_clk_src = {
	.cmd_rcgr = 0x2900c,
	.mnd_width = 16,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_blsp1_uart1_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "blsp2_uart2_apps_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 31578947,
				NOMINAL, 63157895),
	},
};

static const struct freq_tbl ftbl_gp1_clk_src[] = {
	F(19200000, P_XO, 1, 0, 0),
	F(100000000, P_GPLL0_OUT_MAIN, 6, 0, 0),
	F(200000000, P_GPLL0_OUT_MAIN, 3, 0, 0),
	{ }
};

static struct clk_rcg2 gp1_clk_src = {
	.cmd_rcgr = 0x64004,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_2,
	.freq_tbl = ftbl_gp1_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "gp1_clk_src",
		.parent_names = gcc_parent_names_2,
		.num_parents = 5,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 50000000,
				LOW, 100000000,
				NOMINAL, 200000000),
	},
};

static struct clk_rcg2 gp2_clk_src = {
	.cmd_rcgr = 0x65004,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_2,
	.freq_tbl = ftbl_gp1_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "gp2_clk_src",
		.parent_names = gcc_parent_names_2,
		.num_parents = 5,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 50000000,
				LOW, 100000000,
				NOMINAL, 200000000),
	},
};

static struct clk_rcg2 gp3_clk_src = {
	.cmd_rcgr = 0x66004,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_2,
	.freq_tbl = ftbl_gp1_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "gp3_clk_src",
		.parent_names = gcc_parent_names_2,
		.num_parents = 5,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 50000000,
				LOW, 100000000,
				NOMINAL, 200000000),
	},
};

static const struct freq_tbl ftbl_hmss_gpll0_clk_src[] = {
	F(300000000, P_GPLL0_OUT_MAIN, 2, 0, 0),
	F(600000000, P_GPLL0_OUT_MAIN, 1, 0, 0),
	{ }
};

static struct clk_rcg2 hmss_gpll0_clk_src = {
	.cmd_rcgr = 0x4805c,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_hmss_gpll0_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "hmss_gpll0_clk_src",
		.parent_names = gcc_parent_names_ao_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP1_AO(
				LOWER, 600000000),
	},
};

static const struct freq_tbl ftbl_hmss_gpll4_clk_src[] = {
	F(384000000, P_GPLL4_OUT_MAIN, 4, 0, 0),
	F(768000000, P_GPLL4_OUT_MAIN, 2, 0, 0),
	F(1536000000, P_GPLL4_OUT_MAIN, 1, 0, 0),
	{ }
};

static struct clk_rcg2 hmss_gpll4_clk_src = {
	.cmd_rcgr = 0x48074,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_5,
	.freq_tbl = ftbl_hmss_gpll4_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "hmss_gpll4_clk_src",
		.parent_names = gcc_parent_names_5,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3_AO(
				LOWER, 400000000,
				LOW, 800000000,
				NOMINAL, 1600000000),
	},
};

static const struct freq_tbl ftbl_hmss_rbcpr_clk_src[] = {
	F(19200000, P_XO, 1, 0, 0),
	{ }
};

static struct clk_rcg2 hmss_rbcpr_clk_src = {
	.cmd_rcgr = 0x48044,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_hmss_rbcpr_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "hmss_rbcpr_clk_src",
		.parent_names = gcc_parent_names_ao_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2_AO(
				LOWER, 19200000,
				NOMINAL, 50000000),
	},
};

static const struct freq_tbl ftbl_pdm2_clk_src[] = {
	F(60000000, P_GPLL0_OUT_MAIN, 10, 0, 0),
	{ }
};

static struct clk_rcg2 pdm2_clk_src = {
	.cmd_rcgr = 0x33010,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_1,
	.freq_tbl = ftbl_pdm2_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "pdm2_clk_src",
		.parent_names = gcc_parent_names_1,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 60000000),
	},
};

static const struct freq_tbl ftbl_qspi_ser_clk_src[] = {
	F(19200000, P_XO, 1, 0, 0),
	F(80200000, P_PLL1_EARLY_DIV_CLK_SRC, 5, 0, 0),
	F(160400000, P_GPLL1_OUT_MAIN, 5, 0, 0),
	F(267333333, P_GPLL1_OUT_MAIN, 3, 0, 0),
	{ }
};

static struct clk_rcg2 qspi_ser_clk_src = {
	.cmd_rcgr = 0x4d00c,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_6,
	.freq_tbl = ftbl_qspi_ser_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "qspi_ser_clk_src",
		.parent_names = gcc_parent_names_6,
		.num_parents = 7,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 80200000,
				LOW, 160400000,
				NOMINAL, 267333333),
	},
};

static const struct freq_tbl ftbl_sdcc1_apps_clk_src[] = {
	F(144000, P_XO, 16, 3, 25),
	F(400000, P_XO, 12, 1, 4),
	F(20000000, P_PLL0_EARLY_DIV_CLK_SRC, 5, 1, 3),
	F(25000000, P_PLL0_EARLY_DIV_CLK_SRC, 6, 1, 2),
	F(50000000, P_PLL0_EARLY_DIV_CLK_SRC, 6, 0, 0),
	F(100000000, P_GPLL0_OUT_MAIN, 6, 0, 0),
	F(192000000, P_GPLL4_OUT_MAIN, 8, 0, 0),
	F(384000000, P_GPLL4_OUT_MAIN, 4, 0, 0),
	{ }
};

static struct clk_rcg2 sdcc1_apps_clk_src = {
	.cmd_rcgr = 0x1602c,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_7,
	.freq_tbl = ftbl_sdcc1_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "sdcc1_apps_clk_src",
		.parent_names = gcc_parent_names_7,
		.num_parents = 5,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 50000000,
				LOW, 100000000,
				NOMINAL, 400000000),
	},
};

static const struct freq_tbl ftbl_sdcc1_ice_core_clk_src[] = {
	F(75000000, P_PLL0_EARLY_DIV_CLK_SRC, 4, 0, 0),
	F(150000000, P_GPLL0_OUT_MAIN, 4, 0, 0),
	F(200000000, P_GPLL0_OUT_MAIN, 3, 0, 0),
	F(300000000, P_GPLL0_OUT_MAIN, 2, 0, 0),
	{ }
};

static struct clk_rcg2 sdcc1_ice_core_clk_src = {
	.cmd_rcgr = 0x16010,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_sdcc1_ice_core_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "sdcc1_ice_core_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 75000000,
				LOW, 150000000,
				NOMINAL, 300000000),
	},
};

static const struct freq_tbl ftbl_sdcc2_apps_clk_src[] = {
	F(144000, P_XO, 16, 3, 25),
	F(400000, P_XO, 12, 1, 4),
	F(20000000, P_PLL0_EARLY_DIV_CLK_SRC, 5, 1, 3),
	F(25000000, P_PLL0_EARLY_DIV_CLK_SRC, 6, 1, 2),
	F(50000000, P_PLL0_EARLY_DIV_CLK_SRC, 6, 0, 0),
	F(100000000, P_GPLL0_OUT_MAIN, 6, 0, 0),
	F(192000000, P_GPLL4_OUT_MAIN, 8, 0, 0),
	F(200000000, P_GPLL0_OUT_MAIN, 3, 0, 0),
	{ }
};

static struct clk_rcg2 sdcc2_apps_clk_src = {
	.cmd_rcgr = 0x14010,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_8,
	.freq_tbl = ftbl_sdcc2_apps_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "sdcc2_apps_clk_src",
		.parent_names = gcc_parent_names_8,
		.num_parents = 5,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 50000000,
				LOW, 100000000,
				NOMINAL, 200000000),
	},
};

static const struct freq_tbl ftbl_ufs_axi_clk_src[] = {
	F(50000000, P_PLL0_EARLY_DIV_CLK_SRC, 6, 0, 0),
	F(100000000, P_GPLL0_OUT_MAIN, 6, 0, 0),
	F(150000000, P_GPLL0_OUT_MAIN, 4, 0, 0),
	F(200000000, P_GPLL0_OUT_MAIN, 3, 0, 0),
	F(240000000, P_GPLL0_OUT_MAIN, 2.5, 0, 0),
	{ }
};

static struct clk_rcg2 ufs_axi_clk_src = {
	.cmd_rcgr = 0x75018,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_ufs_axi_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "ufs_axi_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP5(
				LOWER, 50000000,
				LOW, 100000000,
				LOW_L1, 150000000,
				NOMINAL, 200000000,
				HIGH, 240000000),
	},
};

static const struct freq_tbl ftbl_ufs_ice_core_clk_src[] = {
	F(75000000, P_PLL0_EARLY_DIV_CLK_SRC, 4, 0, 0),
	F(150000000, P_GPLL0_OUT_MAIN, 4, 0, 0),
	F(300000000, P_GPLL0_OUT_MAIN, 2, 0, 0),
	{ }
};

static struct clk_rcg2 ufs_ice_core_clk_src = {
	.cmd_rcgr = 0x76010,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_ufs_ice_core_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "ufs_ice_core_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 75000000,
				LOW, 150000000,
				NOMINAL, 300000000),
	},
};

static struct clk_rcg2 ufs_phy_aux_clk_src = {
	.cmd_rcgr = 0x76044,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_3,
	.freq_tbl = ftbl_hmss_rbcpr_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "ufs_phy_aux_clk_src",
		.parent_names = gcc_parent_names_3,
		.num_parents = 2,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP1(
				LOWER, 19200000),
	},
};

static const struct freq_tbl ftbl_ufs_unipro_core_clk_src[] = {
	F(37500000, P_PLL0_EARLY_DIV_CLK_SRC, 8, 0, 0),
	F(75000000, P_GPLL0_OUT_MAIN, 8, 0, 0),
	F(150000000, P_GPLL0_OUT_MAIN, 4, 0, 0),
	{ }
};

static struct clk_rcg2 ufs_unipro_core_clk_src = {
	.cmd_rcgr = 0x76028,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_ufs_unipro_core_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "ufs_unipro_core_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 37500000,
				LOW, 75000000,
				NOMINAL, 150000000),
	},
};

static const struct freq_tbl ftbl_usb20_master_clk_src[] = {
	F(19200000, P_XO, 1, 0, 0),
	F(60000000, P_GPLL0_OUT_MAIN, 10, 0, 0),
	F(120000000, P_GPLL0_OUT_MAIN, 5, 0, 0),
	{ }
};

static struct clk_rcg2 usb20_master_clk_src = {
	.cmd_rcgr = 0x2f010,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_usb20_master_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "usb20_master_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP3(
				LOWER, 19200000,
				LOW, 60000000,
				NOMINAL, 120000000),
	},
};

static const struct freq_tbl ftbl_usb20_mock_utmi_clk_src[] = {
	F(19200000, P_XO, 1, 0, 0),
	F(60000000, P_GPLL0_OUT_MAIN, 10, 0, 0),
	{ }
};

static struct clk_rcg2 usb20_mock_utmi_clk_src = {
	.cmd_rcgr = 0x2f024,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_usb20_mock_utmi_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "usb20_mock_utmi_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 19200000,
				LOW, 60000000),
	},
};

static const struct freq_tbl ftbl_usb30_master_clk_src[] = {
	F(19200000, P_XO, 1, 0, 0),
	F(66666667, P_PLL0_EARLY_DIV_CLK_SRC, 4.5, 0, 0),
	F(120000000, P_GPLL0_OUT_MAIN, 5, 0, 0),
	F(133333333, P_GPLL0_OUT_MAIN, 4.5, 0, 0),
	F(150000000, P_GPLL0_OUT_MAIN, 4, 0, 0),
	F(200000000, P_GPLL0_OUT_MAIN, 3, 0, 0),
	F(240000000, P_GPLL0_OUT_MAIN, 2.5, 0, 0),
	{ }
};

static struct clk_rcg2 usb30_master_clk_src = {
	.cmd_rcgr = 0xf014,
	.mnd_width = 8,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_usb30_master_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "usb30_master_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP4(
				LOWER, 66666667,
				LOW, 133333333,
				NOMINAL, 200000000,
				HIGH, 240000000),
	},
};

static const struct freq_tbl ftbl_usb30_mock_utmi_clk_src[] = {
	F(19200000, P_XO, 1, 0, 0),
	F(40000000, P_PLL0_EARLY_DIV_CLK_SRC, 7.5, 0, 0),
	F(60000000, P_GPLL0_OUT_MAIN, 10, 0, 0),
	{ }
};

static struct clk_rcg2 usb30_mock_utmi_clk_src = {
	.cmd_rcgr = 0xf028,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_0,
	.freq_tbl = ftbl_usb30_mock_utmi_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "usb30_mock_utmi_clk_src",
		.parent_names = gcc_parent_names_0,
		.num_parents = 4,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP2(
				LOWER, 40000000,
				LOW, 60000000),
	},
};

static const struct freq_tbl ftbl_usb3_phy_aux_clk_src[] = {
	F(1200000, P_XO, 16, 0, 0),
	F(19200000, P_XO, 1, 0, 0),
	{ }
};

static struct clk_rcg2 usb3_phy_aux_clk_src = {
	.cmd_rcgr = 0x5000c,
	.mnd_width = 0,
	.hid_width = 5,
	.parent_map = gcc_parent_map_4,
	.freq_tbl = ftbl_usb3_phy_aux_clk_src,
	.clkr.hw.init = &(struct clk_init_data){
		.name = "usb3_phy_aux_clk_src",
		.parent_names = gcc_parent_names_4,
		.num_parents = 3,
		.ops = &clk_rcg2_ops,
		VDD_DIG_FMAX_MAP1(
				LOWER, 19200000),
	},
};

static struct clk_branch gcc_aggre2_ufs_axi_clk = {
	.halt_reg = 0x75034,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x75034,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_aggre2_ufs_axi_clk",
			.parent_names = (const char *[]){
				"ufs_axi_clk_src",
			},
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_aggre2_usb3_axi_clk = {
	.halt_reg = 0xf03c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0xf03c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_aggre2_usb3_axi_clk",
			.parent_names = (const char *[]){
				"usb30_master_clk_src",
			},
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_bimc_gfx_clk = {
	.halt_reg = 0x7106c,
	.halt_check = BRANCH_VOTED,
	.clkr = {
		.enable_reg = 0x7106c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_bimc_gfx_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_bimc_hmss_axi_clk = {
	.halt_reg = 0x48004,
	.halt_check = BRANCH_HALT_VOTED,
	.clkr = {
		.enable_reg = 0x52004,
		.enable_mask = BIT(22),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_bimc_hmss_axi_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_bimc_mss_q6_axi_clk = {
	.halt_reg = 0x4401c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x4401c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_bimc_mss_q6_axi_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_ahb_clk = {
	.halt_reg = 0x17004,
	.halt_check = BRANCH_HALT_VOTED,
	.clkr = {
		.enable_reg = 0x52004,
		.enable_mask = BIT(17),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_ahb_clk",
			.flags = CLK_ENABLE_HAND_OFF,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_qup1_i2c_apps_clk = {
	.halt_reg = 0x19008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x19008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_qup1_i2c_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_qup1_i2c_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_qup1_spi_apps_clk = {
	.halt_reg = 0x19004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x19004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_qup1_spi_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_qup1_spi_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_qup2_i2c_apps_clk = {
	.halt_reg = 0x1b008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1b008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_qup2_i2c_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_qup2_i2c_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_qup2_spi_apps_clk = {
	.halt_reg = 0x1b004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1b004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_qup2_spi_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_qup2_spi_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_qup3_i2c_apps_clk = {
	.halt_reg = 0x1d008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1d008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_qup3_i2c_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_qup3_i2c_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_qup3_spi_apps_clk = {
	.halt_reg = 0x1d004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1d004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_qup3_spi_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_qup3_spi_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_qup4_i2c_apps_clk = {
	.halt_reg = 0x1f008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1f008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_qup4_i2c_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_qup4_i2c_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_qup4_spi_apps_clk = {
	.halt_reg = 0x1f004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1f004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_qup4_spi_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_qup4_spi_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_uart1_apps_clk = {
	.halt_reg = 0x1a004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1a004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_uart1_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_uart1_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp1_uart2_apps_clk = {
	.halt_reg = 0x1c004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1c004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp1_uart2_apps_clk",
			.parent_names = (const char *[]){
				"blsp1_uart2_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_ahb_clk = {
	.halt_reg = 0x25004,
	.halt_check = BRANCH_HALT_VOTED,
	.clkr = {
		.enable_reg = 0x52004,
		.enable_mask = BIT(15),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_ahb_clk",
			.flags = CLK_ENABLE_HAND_OFF,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_qup1_i2c_apps_clk = {
	.halt_reg = 0x26008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x26008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_qup1_i2c_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_qup1_i2c_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_qup1_spi_apps_clk = {
	.halt_reg = 0x26004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x26004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_qup1_spi_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_qup1_spi_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_qup2_i2c_apps_clk = {
	.halt_reg = 0x28008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x28008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_qup2_i2c_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_qup2_i2c_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_qup2_spi_apps_clk = {
	.halt_reg = 0x28004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x28004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_qup2_spi_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_qup2_spi_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_qup3_i2c_apps_clk = {
	.halt_reg = 0x2a008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x2a008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_qup3_i2c_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_qup3_i2c_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_qup3_spi_apps_clk = {
	.halt_reg = 0x2a004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x2a004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_qup3_spi_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_qup3_spi_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_qup4_i2c_apps_clk = {
	.halt_reg = 0x2c008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x2c008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_qup4_i2c_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_qup4_i2c_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_qup4_spi_apps_clk = {
	.halt_reg = 0x2c004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x2c004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_qup4_spi_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_qup4_spi_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_uart1_apps_clk = {
	.halt_reg = 0x27004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x27004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_uart1_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_uart1_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_blsp2_uart2_apps_clk = {
	.halt_reg = 0x29004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x29004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_blsp2_uart2_apps_clk",
			.parent_names = (const char *[]){
				"blsp2_uart2_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_boot_rom_ahb_clk = {
	.halt_reg = 0x38004,
	.halt_check = BRANCH_HALT_VOTED,
	.clkr = {
		.enable_reg = 0x52004,
		.enable_mask = BIT(10),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_boot_rom_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_cfg_noc_usb2_axi_clk = {
	.halt_reg = 0x5058,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x5058,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_cfg_noc_usb2_axi_clk",
			.parent_names = (const char *[]){
				"usb20_master_clk_src",
			},
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_cfg_noc_usb3_axi_clk = {
	.halt_reg = 0x5018,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x5018,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_cfg_noc_usb3_axi_clk",
			.parent_names = (const char *[]){
				"usb30_master_clk_src",
			},
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_dcc_ahb_clk = {
	.halt_reg = 0x84004,
	.clkr = {
		.enable_reg = 0x84004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_dcc_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_gp1_clk = {
	.halt_reg = 0x64000,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x64000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_gp1_clk",
			.parent_names = (const char *[]){
				"gp1_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_gp2_clk = {
	.halt_reg = 0x65000,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x65000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_gp2_clk",
			.parent_names = (const char *[]){
				"gp2_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_gp3_clk = {
	.halt_reg = 0x66000,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x66000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_gp3_clk",
			.parent_names = (const char *[]){
				"gp3_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_gpu_bimc_gfx_clk = {
	.halt_reg = 0x71010,
	.halt_check = BRANCH_VOTED,
	.clkr = {
		.enable_reg = 0x71010,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_gpu_bimc_gfx_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_gpu_cfg_ahb_clk = {
	.halt_reg = 0x71004,
	.halt_check = BRANCH_VOTED,
	.clkr = {
		.enable_reg = 0x71004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_gpu_cfg_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gpll0_out_msscc = {
	.halt_reg = 0x5200c,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x5200c,
		.enable_mask = BIT(2),
		.hw.init = &(struct clk_init_data){
			.name = "gpll0_out_msscc",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_gpu_gpll0_clk = {
	.halt_reg = 0x5200c,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x5200c,
		.enable_mask = BIT(4),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_gpu_gpll0_clk",
			.parent_names = (const char *[]){
				"gpll0_out_main",
			},
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_gpu_gpll0_div_clk = {
	.halt_reg = 0x5200c,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x5200c,
		.enable_mask = BIT(3),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_gpu_gpll0_div_clk",
			.parent_names = (const char *[]){
				"gpll0_out_early_div",
			},
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_hmss_dvm_bus_clk = {
	.halt_reg = 0x4808c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x4808c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_hmss_dvm_bus_clk",
			.ops = &clk_branch2_ops,
			.flags = CLK_IGNORE_UNUSED,
		},
	},
};

static struct clk_branch gcc_hmss_rbcpr_clk = {
	.halt_reg = 0x48008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x48008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_hmss_rbcpr_clk",
			.parent_names = (const char *[]){
				"hmss_rbcpr_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_mmss_gpll0_clk = {
	.halt_reg = 0x5200c,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x5200c,
		.enable_mask = BIT(1),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_mmss_gpll0_clk",
			.parent_names = (const char *[]){
				"gpll0_out_main",
			},
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_mmss_gpll0_div_clk = {
	.halt_reg = 0x5200c,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x5200c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_mmss_gpll0_div_clk",
			.parent_names = (const char *[]){
				"gpll0_out_early_div",
			},
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_mmss_noc_cfg_ahb_clk = {
	.halt_reg = 0x9004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x9004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_mmss_noc_cfg_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_mmss_sys_noc_axi_clk = {
	.halt_reg = 0x9000,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x9000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_mmss_sys_noc_axi_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_mss_cfg_ahb_clk = {
	.halt_reg = 0x8a000,
	.clkr = {
		.enable_reg = 0x8a000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_mss_cfg_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_mss_mnoc_bimc_axi_clk = {
	.halt_reg = 0x8a004,
<<<<<<< HEAD
=======
	.halt_check = BRANCH_VOTED,
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	.clkr = {
		.enable_reg = 0x8a004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_mss_mnoc_bimc_axi_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_mss_q6_bimc_axi_clk = {
	.halt_reg = 0x8a040,
	.clkr = {
		.enable_reg = 0x8a040,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_mss_q6_bimc_axi_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_mss_snoc_axi_clk = {
	.halt_reg = 0x8a03c,
	.clkr = {
		.enable_reg = 0x8a03c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_mss_snoc_axi_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_pdm2_clk = {
	.halt_reg = 0x3300c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x3300c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_pdm2_clk",
			.parent_names = (const char *[]){
				"pdm2_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_pdm_ahb_clk = {
	.halt_reg = 0x33004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x33004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_pdm_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_prng_ahb_clk = {
	.halt_reg = 0x34004,
	.halt_check = BRANCH_HALT_VOTED,
	.clkr = {
		.enable_reg = 0x52004,
		.enable_mask = BIT(13),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_prng_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_qspi_ahb_clk = {
	.halt_reg = 0x4d004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x4d004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_qspi_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_qspi_ser_clk = {
	.halt_reg = 0x4d008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x4d008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_qspi_ser_clk",
			.parent_names = (const char *[]){
				"qspi_ser_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_rx0_usb2_clkref_clk = {
	.halt_reg = 0x88018,
	.halt_check = BRANCH_HALT_VOTED,
	.clkr = {
		.enable_reg = 0x88018,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_rx0_usb2_clkref_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_rx1_usb2_clkref_clk = {
	.halt_reg = 0x88014,
	.halt_check = BRANCH_HALT_VOTED,
	.clkr = {
		.enable_reg = 0x88014,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_rx1_usb2_clkref_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_sdcc1_ahb_clk = {
	.halt_reg = 0x16008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x16008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_sdcc1_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_sdcc1_apps_clk = {
	.halt_reg = 0x16004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x16004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_sdcc1_apps_clk",
			.parent_names = (const char *[]){
				"sdcc1_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_sdcc1_ice_core_clk = {
	.halt_reg = 0x1600c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x1600c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_sdcc1_ice_core_clk",
			.parent_names = (const char *[]){
				"sdcc1_ice_core_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_sdcc2_ahb_clk = {
	.halt_reg = 0x14008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x14008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_sdcc2_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_sdcc2_apps_clk = {
	.halt_reg = 0x14004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x14004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_sdcc2_apps_clk",
			.parent_names = (const char *[]){
				"sdcc2_apps_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_ahb_clk = {
	.halt_reg = 0x7500c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x7500c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_ahb_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_axi_clk = {
	.halt_reg = 0x75008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x75008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_axi_clk",
			.parent_names = (const char *[]){
				"ufs_axi_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_axi_hw_ctl_clk = {
	.halt_reg = 0x75008,
	.clkr = {
		.enable_reg = 0x75008,
		.enable_mask = BIT(1),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_axi_hw_ctl_clk",
			.parent_names = (const char *[]){
				"gcc_ufs_axi_clk",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_hw_ctl_ops,
		},
	},
};

static struct clk_branch gcc_ufs_clkref_clk = {
	.halt_reg = 0x88008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x88008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_clkref_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_ice_core_clk = {
	.halt_reg = 0x7600c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x7600c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_ice_core_clk",
			.parent_names = (const char *[]){
				"ufs_ice_core_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_ice_core_hw_ctl_clk = {
	.halt_reg = 0x7600c,
	.clkr = {
		.enable_reg = 0x7600c,
		.enable_mask = BIT(1),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_ice_core_hw_ctl_clk",
			.parent_names = (const char *[]){
				"gcc_ufs_ice_core_clk",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_hw_ctl_ops,
		},
	},
};

static struct clk_branch gcc_ufs_phy_aux_clk = {
	.halt_reg = 0x76040,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x76040,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_phy_aux_clk",
			.parent_names = (const char *[]){
				"ufs_phy_aux_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_phy_aux_hw_ctl_clk = {
	.halt_reg = 0x76040,
	.clkr = {
		.enable_reg = 0x76040,
		.enable_mask = BIT(1),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_phy_aux_hw_ctl_clk",
			.parent_names = (const char *[]){
				"gcc_ufs_phy_aux_clk",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_hw_ctl_ops,
		},
	},
};

static struct clk_branch gcc_ufs_rx_symbol_0_clk = {
	.halt_reg = 0x75014,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x75014,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_rx_symbol_0_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_rx_symbol_1_clk = {
	.halt_reg = 0x7605c,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x7605c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_rx_symbol_1_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_tx_symbol_0_clk = {
	.halt_reg = 0x75010,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x75010,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_tx_symbol_0_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_unipro_core_clk = {
	.halt_reg = 0x76008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x76008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_unipro_core_clk",
			.parent_names = (const char *[]){
				"ufs_unipro_core_clk_src",
			},
			.flags = CLK_SET_RATE_PARENT,
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_ufs_unipro_core_hw_ctl_clk = {
	.halt_reg = 0x76008,
	.clkr = {
		.enable_reg = 0x76008,
		.enable_mask = BIT(1),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_ufs_unipro_core_hw_ctl_clk",
			.parent_names = (const char *[]){
				"gcc_ufs_unipro_core_clk",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_hw_ctl_ops,
		},
	},
};

static struct clk_branch gcc_usb20_master_clk = {
	.halt_reg = 0x2f004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x2f004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb20_master_clk",
			.parent_names = (const char *[]){
				"usb20_master_clk_src",
			},
			.flags = CLK_SET_RATE_PARENT,
			.num_parents = 1,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_usb20_mock_utmi_clk = {
	.halt_reg = 0x2f00c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x2f00c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb20_mock_utmi_clk",
			.parent_names = (const char *[]){
				"usb20_mock_utmi_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_usb20_sleep_clk = {
	.halt_reg = 0x2f008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x2f008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb20_sleep_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_usb30_master_clk = {
	.halt_reg = 0xf008,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0xf008,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb30_master_clk",
			.parent_names = (const char *[]){
				"usb30_master_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_usb30_mock_utmi_clk = {
	.halt_reg = 0xf010,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0xf010,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb30_mock_utmi_clk",
			.parent_names = (const char *[]){
				"usb30_mock_utmi_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_usb30_sleep_clk = {
	.halt_reg = 0xf00c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0xf00c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb30_sleep_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_usb3_clkref_clk = {
	.halt_reg = 0x8800c,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x8800c,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb3_clkref_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_usb3_phy_aux_clk = {
	.halt_reg = 0x50000,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x50000,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb3_phy_aux_clk",
			.parent_names = (const char *[]){
				"usb3_phy_aux_clk_src",
			},
			.num_parents = 1,
			.flags = CLK_SET_RATE_PARENT,
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_usb3_phy_pipe_clk = {
	.halt_reg = 0x50004,
	.halt_check = BRANCH_HALT_DELAY,
	.clkr = {
		.enable_reg = 0x50004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb3_phy_pipe_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch gcc_usb_phy_cfg_ahb2phy_clk = {
	.halt_reg = 0x6a004,
	.halt_check = BRANCH_HALT,
	.clkr = {
		.enable_reg = 0x6a004,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "gcc_usb_phy_cfg_ahb2phy_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch hlos1_vote_lpass_adsp_smmu_clk = {
	.halt_reg = 0x7d014,
	.halt_check = BRANCH_VOTED,
	.clkr = {
		.enable_reg = 0x7d014,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "hlos1_vote_lpass_adsp_smmu_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch hlos1_vote_turing_adsp_smmu_clk = {
	.halt_reg = 0x7d048,
	.halt_check = BRANCH_VOTED,
	.clkr = {
		.enable_reg = 0x7d048,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "hlos1_vote_turing_adsp_smmu_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_branch hlos2_vote_turing_adsp_smmu_clk = {
	.halt_reg = 0x7e048,
	.halt_check = BRANCH_VOTED,
	.clkr = {
		.enable_reg = 0x7e048,
		.enable_mask = BIT(0),
		.hw.init = &(struct clk_init_data){
			.name = "hlos2_vote_turing_adsp_smmu_clk",
			.ops = &clk_branch2_ops,
		},
	},
};

static struct clk_fixed_factor gcc_ce1_ahb_m_clk = {
	.hw.init = &(struct clk_init_data){
		.name = "gcc_ce1_ahb_m_clk",
		.ops = &clk_dummy_ops,
		.flags = CLK_IGNORE_UNUSED,
	},
};

static struct clk_fixed_factor gcc_ce1_axi_m_clk = {
	.hw.init = &(struct clk_init_data){
		.name = "gcc_ce1_axi_m_clk",
		.ops = &clk_dummy_ops,
		.flags = CLK_IGNORE_UNUSED,
	},
};

struct clk_hw *gcc_sdm660_hws[] = {
	[GCC_XO] =      &xo.hw,
	[GCC_GPLL0_EARLY_DIV] = &gpll0_out_early_div.hw,
	[GCC_GPLL1_EARLY_DIV] = &gpll1_out_early_div.hw,
	[GCC_CE1_AHB_M_CLK] = &gcc_ce1_ahb_m_clk.hw,
	[GCC_CE1_AXI_M_CLK] = &gcc_ce1_axi_m_clk.hw,
};

static struct clk_regmap *gcc_660_clocks[] = {
	[BLSP1_QUP1_I2C_APPS_CLK_SRC] = &blsp1_qup1_i2c_apps_clk_src.clkr,
	[BLSP1_QUP1_SPI_APPS_CLK_SRC] = &blsp1_qup1_spi_apps_clk_src.clkr,
	[BLSP1_QUP2_I2C_APPS_CLK_SRC] = &blsp1_qup2_i2c_apps_clk_src.clkr,
	[BLSP1_QUP2_SPI_APPS_CLK_SRC] = &blsp1_qup2_spi_apps_clk_src.clkr,
	[BLSP1_QUP3_I2C_APPS_CLK_SRC] = &blsp1_qup3_i2c_apps_clk_src.clkr,
	[BLSP1_QUP3_SPI_APPS_CLK_SRC] = &blsp1_qup3_spi_apps_clk_src.clkr,
	[BLSP1_QUP4_I2C_APPS_CLK_SRC] = &blsp1_qup4_i2c_apps_clk_src.clkr,
	[BLSP1_QUP4_SPI_APPS_CLK_SRC] = &blsp1_qup4_spi_apps_clk_src.clkr,
	[BLSP1_UART1_APPS_CLK_SRC] = &blsp1_uart1_apps_clk_src.clkr,
	[BLSP1_UART2_APPS_CLK_SRC] = &blsp1_uart2_apps_clk_src.clkr,
	[BLSP2_QUP1_I2C_APPS_CLK_SRC] = &blsp2_qup1_i2c_apps_clk_src.clkr,
	[BLSP2_QUP1_SPI_APPS_CLK_SRC] = &blsp2_qup1_spi_apps_clk_src.clkr,
	[BLSP2_QUP2_I2C_APPS_CLK_SRC] = &blsp2_qup2_i2c_apps_clk_src.clkr,
	[BLSP2_QUP2_SPI_APPS_CLK_SRC] = &blsp2_qup2_spi_apps_clk_src.clkr,
	[BLSP2_QUP3_I2C_APPS_CLK_SRC] = &blsp2_qup3_i2c_apps_clk_src.clkr,
	[BLSP2_QUP3_SPI_APPS_CLK_SRC] = &blsp2_qup3_spi_apps_clk_src.clkr,
	[BLSP2_QUP4_I2C_APPS_CLK_SRC] = &blsp2_qup4_i2c_apps_clk_src.clkr,
	[BLSP2_QUP4_SPI_APPS_CLK_SRC] = &blsp2_qup4_spi_apps_clk_src.clkr,
	[BLSP2_UART1_APPS_CLK_SRC] = &blsp2_uart1_apps_clk_src.clkr,
	[BLSP2_UART2_APPS_CLK_SRC] = &blsp2_uart2_apps_clk_src.clkr,
	[GCC_AGGRE2_UFS_AXI_CLK] = &gcc_aggre2_ufs_axi_clk.clkr,
	[GCC_AGGRE2_USB3_AXI_CLK] = &gcc_aggre2_usb3_axi_clk.clkr,
	[GCC_BIMC_GFX_CLK] = &gcc_bimc_gfx_clk.clkr,
	[GCC_BIMC_HMSS_AXI_CLK] = &gcc_bimc_hmss_axi_clk.clkr,
	[GCC_BIMC_MSS_Q6_AXI_CLK] = &gcc_bimc_mss_q6_axi_clk.clkr,
	[GCC_BLSP1_AHB_CLK] = &gcc_blsp1_ahb_clk.clkr,
	[GCC_BLSP1_QUP1_I2C_APPS_CLK] = &gcc_blsp1_qup1_i2c_apps_clk.clkr,
	[GCC_BLSP1_QUP1_SPI_APPS_CLK] = &gcc_blsp1_qup1_spi_apps_clk.clkr,
	[GCC_BLSP1_QUP2_I2C_APPS_CLK] = &gcc_blsp1_qup2_i2c_apps_clk.clkr,
	[GCC_BLSP1_QUP2_SPI_APPS_CLK] = &gcc_blsp1_qup2_spi_apps_clk.clkr,
	[GCC_BLSP1_QUP3_I2C_APPS_CLK] = &gcc_blsp1_qup3_i2c_apps_clk.clkr,
	[GCC_BLSP1_QUP3_SPI_APPS_CLK] = &gcc_blsp1_qup3_spi_apps_clk.clkr,
	[GCC_BLSP1_QUP4_I2C_APPS_CLK] = &gcc_blsp1_qup4_i2c_apps_clk.clkr,
	[GCC_BLSP1_QUP4_SPI_APPS_CLK] = &gcc_blsp1_qup4_spi_apps_clk.clkr,
	[GCC_BLSP1_UART1_APPS_CLK] = &gcc_blsp1_uart1_apps_clk.clkr,
	[GCC_BLSP1_UART2_APPS_CLK] = &gcc_blsp1_uart2_apps_clk.clkr,
	[GCC_BLSP2_AHB_CLK] = &gcc_blsp2_ahb_clk.clkr,
	[GCC_BLSP2_QUP1_I2C_APPS_CLK] = &gcc_blsp2_qup1_i2c_apps_clk.clkr,
	[GCC_BLSP2_QUP1_SPI_APPS_CLK] = &gcc_blsp2_qup1_spi_apps_clk.clkr,
	[GCC_BLSP2_QUP2_I2C_APPS_CLK] = &gcc_blsp2_qup2_i2c_apps_clk.clkr,
	[GCC_BLSP2_QUP2_SPI_APPS_CLK] = &gcc_blsp2_qup2_spi_apps_clk.clkr,
	[GCC_BLSP2_QUP3_I2C_APPS_CLK] = &gcc_blsp2_qup3_i2c_apps_clk.clkr,
	[GCC_BLSP2_QUP3_SPI_APPS_CLK] = &gcc_blsp2_qup3_spi_apps_clk.clkr,
	[GCC_BLSP2_QUP4_I2C_APPS_CLK] = &gcc_blsp2_qup4_i2c_apps_clk.clkr,
	[GCC_BLSP2_QUP4_SPI_APPS_CLK] = &gcc_blsp2_qup4_spi_apps_clk.clkr,
	[GCC_BLSP2_UART1_APPS_CLK] = &gcc_blsp2_uart1_apps_clk.clkr,
	[GCC_BLSP2_UART2_APPS_CLK] = &gcc_blsp2_uart2_apps_clk.clkr,
	[GCC_BOOT_ROM_AHB_CLK] = &gcc_boot_rom_ahb_clk.clkr,
	[GCC_CFG_NOC_USB2_AXI_CLK] = &gcc_cfg_noc_usb2_axi_clk.clkr,
	[GCC_CFG_NOC_USB3_AXI_CLK] = &gcc_cfg_noc_usb3_axi_clk.clkr,
	[GCC_DCC_AHB_CLK] = &gcc_dcc_ahb_clk.clkr,
	[GCC_GP1_CLK] = &gcc_gp1_clk.clkr,
	[GCC_GP2_CLK] = &gcc_gp2_clk.clkr,
	[GCC_GP3_CLK] = &gcc_gp3_clk.clkr,
	[GCC_GPU_BIMC_GFX_CLK] = &gcc_gpu_bimc_gfx_clk.clkr,
	[GCC_GPU_CFG_AHB_CLK] = &gcc_gpu_cfg_ahb_clk.clkr,
	[GCC_GPU_GPLL0_CLK] = &gcc_gpu_gpll0_clk.clkr,
	[GCC_GPU_GPLL0_DIV_CLK] = &gcc_gpu_gpll0_div_clk.clkr,
	[GCC_HMSS_DVM_BUS_CLK] = &gcc_hmss_dvm_bus_clk.clkr,
	[GCC_HMSS_RBCPR_CLK] = &gcc_hmss_rbcpr_clk.clkr,
	[GCC_MMSS_GPLL0_CLK] = &gcc_mmss_gpll0_clk.clkr,
	[GCC_MMSS_GPLL0_DIV_CLK] = &gcc_mmss_gpll0_div_clk.clkr,
	[GCC_MMSS_NOC_CFG_AHB_CLK] = &gcc_mmss_noc_cfg_ahb_clk.clkr,
	[GCC_MMSS_SYS_NOC_AXI_CLK] = &gcc_mmss_sys_noc_axi_clk.clkr,
	[GCC_MSS_CFG_AHB_CLK] = &gcc_mss_cfg_ahb_clk.clkr,
	[GCC_MSS_MNOC_BIMC_AXI_CLK] = &gcc_mss_mnoc_bimc_axi_clk.clkr,
	[GCC_MSS_Q6_BIMC_AXI_CLK] = &gcc_mss_q6_bimc_axi_clk.clkr,
	[GCC_MSS_SNOC_AXI_CLK] = &gcc_mss_snoc_axi_clk.clkr,
	[GCC_PDM2_CLK] = &gcc_pdm2_clk.clkr,
	[GCC_PDM_AHB_CLK] = &gcc_pdm_ahb_clk.clkr,
	[GCC_PRNG_AHB_CLK] = &gcc_prng_ahb_clk.clkr,
	[GCC_QSPI_AHB_CLK] = &gcc_qspi_ahb_clk.clkr,
	[GCC_QSPI_SER_CLK] = &gcc_qspi_ser_clk.clkr,
	[GCC_RX0_USB2_CLKREF_CLK] = &gcc_rx0_usb2_clkref_clk.clkr,
	[GCC_RX1_USB2_CLKREF_CLK] = &gcc_rx1_usb2_clkref_clk.clkr,
	[GCC_SDCC1_AHB_CLK] = &gcc_sdcc1_ahb_clk.clkr,
	[GCC_SDCC1_APPS_CLK] = &gcc_sdcc1_apps_clk.clkr,
	[GCC_SDCC1_ICE_CORE_CLK] = &gcc_sdcc1_ice_core_clk.clkr,
	[GCC_SDCC2_AHB_CLK] = &gcc_sdcc2_ahb_clk.clkr,
	[GCC_SDCC2_APPS_CLK] = &gcc_sdcc2_apps_clk.clkr,
	[GCC_UFS_AHB_CLK] = &gcc_ufs_ahb_clk.clkr,
	[GCC_UFS_AXI_CLK] = &gcc_ufs_axi_clk.clkr,
	[GCC_UFS_CLKREF_CLK] = &gcc_ufs_clkref_clk.clkr,
	[GCC_UFS_ICE_CORE_CLK] = &gcc_ufs_ice_core_clk.clkr,
	[GCC_UFS_PHY_AUX_CLK] = &gcc_ufs_phy_aux_clk.clkr,
	[GCC_UFS_RX_SYMBOL_0_CLK] = &gcc_ufs_rx_symbol_0_clk.clkr,
	[GCC_UFS_RX_SYMBOL_1_CLK] = &gcc_ufs_rx_symbol_1_clk.clkr,
	[GCC_UFS_TX_SYMBOL_0_CLK] = &gcc_ufs_tx_symbol_0_clk.clkr,
	[GCC_UFS_UNIPRO_CORE_CLK] = &gcc_ufs_unipro_core_clk.clkr,
	[GCC_USB20_MASTER_CLK] = &gcc_usb20_master_clk.clkr,
	[GCC_USB20_MOCK_UTMI_CLK] = &gcc_usb20_mock_utmi_clk.clkr,
	[GCC_USB20_SLEEP_CLK] = &gcc_usb20_sleep_clk.clkr,
	[GCC_USB30_MASTER_CLK] = &gcc_usb30_master_clk.clkr,
	[GCC_USB30_MOCK_UTMI_CLK] = &gcc_usb30_mock_utmi_clk.clkr,
	[GCC_USB30_SLEEP_CLK] = &gcc_usb30_sleep_clk.clkr,
	[GCC_USB3_CLKREF_CLK] = &gcc_usb3_clkref_clk.clkr,
	[GCC_USB3_PHY_AUX_CLK] = &gcc_usb3_phy_aux_clk.clkr,
	[GCC_USB3_PHY_PIPE_CLK] = &gcc_usb3_phy_pipe_clk.clkr,
	[GCC_USB_PHY_CFG_AHB2PHY_CLK] = &gcc_usb_phy_cfg_ahb2phy_clk.clkr,
	[GP1_CLK_SRC] = &gp1_clk_src.clkr,
	[GP2_CLK_SRC] = &gp2_clk_src.clkr,
	[GP3_CLK_SRC] = &gp3_clk_src.clkr,
	[GPLL0] = &gpll0_out_main.clkr,
	[GPLL0_AO] = &gpll0_ao_out_main.clkr,
	[GPLL1] = &gpll1_out_main.clkr,
	[GPLL4] = &gpll4_out_main.clkr,
	[HLOS1_VOTE_LPASS_ADSP_SMMU_CLK] = &hlos1_vote_lpass_adsp_smmu_clk.clkr,
	[HMSS_GPLL0_CLK_SRC] = &hmss_gpll0_clk_src.clkr,
	[HMSS_GPLL4_CLK_SRC] = &hmss_gpll4_clk_src.clkr,
	[HMSS_RBCPR_CLK_SRC] = &hmss_rbcpr_clk_src.clkr,
	[PDM2_CLK_SRC] = &pdm2_clk_src.clkr,
	[QSPI_SER_CLK_SRC] = &qspi_ser_clk_src.clkr,
	[SDCC1_APPS_CLK_SRC] = &sdcc1_apps_clk_src.clkr,
	[SDCC1_ICE_CORE_CLK_SRC] = &sdcc1_ice_core_clk_src.clkr,
	[SDCC2_APPS_CLK_SRC] = &sdcc2_apps_clk_src.clkr,
	[UFS_AXI_CLK_SRC] = &ufs_axi_clk_src.clkr,
	[UFS_ICE_CORE_CLK_SRC] = &ufs_ice_core_clk_src.clkr,
	[UFS_PHY_AUX_CLK_SRC] = &ufs_phy_aux_clk_src.clkr,
	[UFS_UNIPRO_CORE_CLK_SRC] = &ufs_unipro_core_clk_src.clkr,
	[USB20_MASTER_CLK_SRC] = &usb20_master_clk_src.clkr,
	[USB20_MOCK_UTMI_CLK_SRC] = &usb20_mock_utmi_clk_src.clkr,
	[USB30_MASTER_CLK_SRC] = &usb30_master_clk_src.clkr,
	[USB30_MOCK_UTMI_CLK_SRC] = &usb30_mock_utmi_clk_src.clkr,
	[USB3_PHY_AUX_CLK_SRC] = &usb3_phy_aux_clk_src.clkr,
	[GPLL0_OUT_MSSCC] = &gpll0_out_msscc.clkr,
	[GCC_UFS_AXI_HW_CTL_CLK] = &gcc_ufs_axi_hw_ctl_clk.clkr,
	[GCC_UFS_ICE_CORE_HW_CTL_CLK] = &gcc_ufs_ice_core_hw_ctl_clk.clkr,
	[GCC_UFS_PHY_AUX_HW_CTL_CLK] = &gcc_ufs_phy_aux_hw_ctl_clk.clkr,
	[GCC_UFS_UNIPRO_CORE_HW_CTL_CLK] = &gcc_ufs_unipro_core_hw_ctl_clk.clkr,
	[HLOS1_VOTE_TURING_ADSP_SMMU_CLK] =
					&hlos1_vote_turing_adsp_smmu_clk.clkr,
	[HLOS2_VOTE_TURING_ADSP_SMMU_CLK] =
					&hlos2_vote_turing_adsp_smmu_clk.clkr,
};

static const struct qcom_reset_map gcc_660_resets[] = {
	[GCC_QUSB2PHY_PRIM_BCR] = { 0x12000 },
	[GCC_QUSB2PHY_SEC_BCR] = { 0x12004 },
<<<<<<< HEAD
=======
	[GCC_SDCC1_BCR] = { 0x16000 },
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	[GCC_UFS_BCR] = { 0x75000 },
	[GCC_USB3_DP_PHY_BCR] = { 0x50028 },
	[GCC_USB3_PHY_BCR] = { 0x50020 },
	[GCC_USB3PHY_PHY_BCR] = { 0x50024 },
	[GCC_USB_20_BCR] = { 0x2f000 },
	[GCC_USB_30_BCR] = { 0xf000 },
	[GCC_USB_PHY_CFG_AHB2PHY_BCR] = { 0x6a000 },
};

static const struct regmap_config gcc_660_regmap_config = {
	.reg_bits	= 32,
	.reg_stride	= 4,
	.val_bits	= 32,
	.max_register	= 0x94000,
	.fast_io	= true,
};

static const struct qcom_cc_desc gcc_660_desc = {
	.config = &gcc_660_regmap_config,
	.clks = gcc_660_clocks,
	.num_clks = ARRAY_SIZE(gcc_660_clocks),
	.hwclks = gcc_sdm660_hws,
	.num_hwclks = ARRAY_SIZE(gcc_sdm660_hws),
	.resets = gcc_660_resets,
	.num_resets = ARRAY_SIZE(gcc_660_resets),
};

static const struct of_device_id gcc_660_match_table[] = {
	{ .compatible = "qcom,gcc-sdm660" },
	{ }
};
MODULE_DEVICE_TABLE(of, gcc_660_match_table);

static int gcc_660_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct regmap *regmap;

	regmap = qcom_cc_map(pdev, &gcc_660_desc);
	if (IS_ERR(regmap))
		return PTR_ERR(regmap);


	vdd_dig.regulator[0] = devm_regulator_get(&pdev->dev, "vdd_dig");
	if (IS_ERR(vdd_dig.regulator[0])) {
		if (!(PTR_ERR(vdd_dig.regulator[0]) == -EPROBE_DEFER))
			dev_err(&pdev->dev,
					"Unable to get vdd_dig regulator\n");
		return PTR_ERR(vdd_dig.regulator[0]);
	}

	vdd_dig_ao.regulator[0] = devm_regulator_get(&pdev->dev, "vdd_dig_ao");
	if (IS_ERR(vdd_dig_ao.regulator[0])) {
		if (!(PTR_ERR(vdd_dig_ao.regulator[0]) == -EPROBE_DEFER))
			dev_err(&pdev->dev,
					"Unable to get vdd_dig_ao regulator\n");
		return PTR_ERR(vdd_dig_ao.regulator[0]);
	}

	ret = qcom_cc_really_probe(pdev, &gcc_660_desc, regmap);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register GCC clocks\n");
		return ret;
	}

	/* Disable the GPLL0 active input to MMSS and GPU via MISC registers */
	regmap_update_bits(regmap, 0x0902c, 0x3, 0x3);
	regmap_update_bits(regmap, 0x71028, 0x3, 0x3);

	/* This clock is used for all MMSSCC register access */
	clk_prepare_enable(gcc_mmss_noc_cfg_ahb_clk.clkr.hw.clk);

	/* This clock is used for all GPUCC register access */
	clk_prepare_enable(gcc_gpu_cfg_ahb_clk.clkr.hw.clk);

	/* Keep bimc gfx clock port on all the time */
	clk_prepare_enable(gcc_bimc_gfx_clk.clkr.hw.clk);

	/* Set the HMSS_GPLL0_SRC for 300MHz to CPU subsystem */
	clk_set_rate(hmss_gpll0_clk_src.clkr.hw.clk, 300000000);

	pr_err("Registered GCC clocks\n");

	return ret;
}

static struct platform_driver gcc_660_driver = {
	.probe		= gcc_660_probe,
	.driver		= {
		.name	= "gcc-sdm660",
		.of_match_table = gcc_660_match_table,
<<<<<<< HEAD
=======
		.probe_type = PROBE_FORCE_SYNCHRONOUS,
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	},
};

static int __init gcc_660_init(void)
{
	return platform_driver_register(&gcc_660_driver);
}
core_initcall_sync(gcc_660_init);

static void __exit gcc_660_exit(void)
{
	platform_driver_unregister(&gcc_660_driver);
}
module_exit(gcc_660_exit);

/* Debug Mux for measure */
static struct measure_clk_data debug_mux_priv = {
	.ctl_reg = 0x62004,
	.status_reg = 0x62008,
	.xo_div4_cbcr = 0x43008,
};

static const char *const gcc_debug_mux_parent_names[] = {
	"measure_only_snoc_clk",
	"measure_only_cnoc_clk",
	"measure_only_cnoc_periph_clk",
	"measure_only_bimc_clk",
	"measure_only_ce1_clk",
	"measure_only_ipa_clk",
	"gcc_aggre2_ufs_axi_clk",
	"gcc_aggre2_usb3_axi_clk",
	"gcc_bimc_gfx_clk",
	"gcc_bimc_hmss_axi_clk",
	"gcc_bimc_mss_q6_axi_clk",
	"gcc_blsp1_ahb_clk",
	"gcc_blsp1_qup1_i2c_apps_clk",
	"gcc_blsp1_qup1_spi_apps_clk",
	"gcc_blsp1_qup2_i2c_apps_clk",
	"gcc_blsp1_qup2_spi_apps_clk",
	"gcc_blsp1_qup3_i2c_apps_clk",
	"gcc_blsp1_qup3_spi_apps_clk",
	"gcc_blsp1_qup4_i2c_apps_clk",
	"gcc_blsp1_qup4_spi_apps_clk",
	"gcc_blsp1_uart1_apps_clk",
	"gcc_blsp1_uart2_apps_clk",
	"gcc_blsp2_ahb_clk",
	"gcc_blsp2_qup1_i2c_apps_clk",
	"gcc_blsp2_qup1_spi_apps_clk",
	"gcc_blsp2_qup2_i2c_apps_clk",
	"gcc_blsp2_qup2_spi_apps_clk",
	"gcc_blsp2_qup3_i2c_apps_clk",
	"gcc_blsp2_qup3_spi_apps_clk",
	"gcc_blsp2_qup4_i2c_apps_clk",
	"gcc_blsp2_qup4_spi_apps_clk",
	"gcc_blsp2_uart1_apps_clk",
	"gcc_blsp2_uart2_apps_clk",
	"gcc_boot_rom_ahb_clk",
	"gcc_ce1_ahb_m_clk",
	"gcc_ce1_axi_m_clk",
	"gcc_cfg_noc_usb2_axi_clk",
	"gcc_cfg_noc_usb3_axi_clk",
	"gcc_dcc_ahb_clk",
	"gcc_gp1_clk",
	"gcc_gp2_clk",
	"gcc_gp3_clk",
	"gcc_gpu_bimc_gfx_clk",
	"gcc_gpu_cfg_ahb_clk",
	"gcc_hmss_dvm_bus_clk",
	"gcc_hmss_rbcpr_clk",
	"gcc_mmss_noc_cfg_ahb_clk",
	"gcc_mmss_sys_noc_axi_clk",
	"gcc_mss_cfg_ahb_clk",
	"gcc_mss_mnoc_bimc_axi_clk",
	"gcc_mss_q6_bimc_axi_clk",
	"gcc_mss_snoc_axi_clk",
	"gcc_pdm2_clk",
	"gcc_pdm_ahb_clk",
	"gcc_prng_ahb_clk",
	"gcc_qspi_ahb_clk",
	"gcc_qspi_ser_clk",
	"gcc_sdcc1_ahb_clk",
	"gcc_sdcc1_apps_clk",
	"gcc_sdcc1_ice_core_clk",
	"gcc_sdcc2_ahb_clk",
	"gcc_sdcc2_apps_clk",
	"gcc_ufs_ahb_clk",
	"gcc_ufs_axi_clk",
	"gcc_ufs_ice_core_clk",
	"gcc_ufs_phy_aux_clk",
	"gcc_ufs_rx_symbol_0_clk",
	"gcc_ufs_rx_symbol_1_clk",
	"gcc_ufs_tx_symbol_0_clk",
	"gcc_ufs_unipro_core_clk",
	"gcc_usb20_master_clk",
	"gcc_usb20_mock_utmi_clk",
	"gcc_usb20_sleep_clk",
	"gcc_usb30_master_clk",
	"gcc_usb30_mock_utmi_clk",
	"gcc_usb30_sleep_clk",
	"gcc_usb3_phy_aux_clk",
	"gcc_usb3_phy_pipe_clk",
	"gcc_usb_phy_cfg_ahb2phy_clk",
	"gpu_cc_debug_mux",
	"mmss_cc_debug_mux",
	"cpu_cc_debug_mux",
};

static int gcc_debug_mux_sels[] = {
	0x0,		/* measure_only_snoc_clk */
	0xE,		/* measure_only_cnoc_clk */
	0x198,		/* measure_only_cnoc_periph_clk */
	0x19D,		/* measure_only_bimc_clk */
	0x97,		/* measure_only_ce1_clk */
	0x11b,		/* measure_only_ipa_clk */
	0x10B,		/* gcc_aggre2_ufs_axi_clk */
	0x10A,		/* gcc_aggre2_usb3_axi_clk */
	0xAC,		/* gcc_bimc_gfx_clk */
	0xBB,		/* gcc_bimc_hmss_axi_clk */
	0xA3,		/* gcc_bimc_mss_q6_axi_clk */
	0x4A,		/* gcc_blsp1_ahb_clk */
	0x4D,		/* gcc_blsp1_qup1_i2c_apps_clk */
	0x4C,		/* gcc_blsp1_qup1_spi_apps_clk */
	0x51,		/* gcc_blsp1_qup2_i2c_apps_clk */
	0x50,		/* gcc_blsp1_qup2_spi_apps_clk */
	0x55,		/* gcc_blsp1_qup3_i2c_apps_clk */
	0x54,		/* gcc_blsp1_qup3_spi_apps_clk */
	0x59,		/* gcc_blsp1_qup4_i2c_apps_clk */
	0x58,		/* gcc_blsp1_qup4_spi_apps_clk */
	0x4E,		/* gcc_blsp1_uart1_apps_clk */
	0x52,		/* gcc_blsp1_uart2_apps_clk */
	0x5E,		/* gcc_blsp2_ahb_clk */
	0x61,		/* gcc_blsp2_qup1_i2c_apps_clk */
	0x60,		/* gcc_blsp2_qup1_spi_apps_clk */
	0x65,		/* gcc_blsp2_qup2_i2c_apps_clk */
	0x64,		/* gcc_blsp2_qup2_spi_apps_clk */
	0x69,		/* gcc_blsp2_qup3_i2c_apps_clk */
	0x68,		/* gcc_blsp2_qup3_spi_apps_clk */
	0x6D,		/* gcc_blsp2_qup4_i2c_apps_clk */
	0x6C,		/* gcc_blsp2_qup4_spi_apps_clk */
	0x62,		/* gcc_blsp2_uart1_apps_clk */
	0x66,		/* gcc_blsp2_uart2_apps_clk */
	0x7A,		/* gcc_boot_rom_ahb_clk */
	0x99,		/* gcc_ce1_ahb_m_clk */
	0x98,		/* gcc_ce1_axi_m_clk */
	0x168,		/* gcc_cfg_noc_usb2_axi_clk */
	0x14,		/* gcc_cfg_noc_usb3_axi_clk */
	0x119,		/* gcc_dcc_ahb_clk */
	0xDF,		/* gcc_gp1_clk */
	0xE0,		/* gcc_gp2_clk */
	0xE1,		/* gcc_gp3_clk */
	0x13F,		/* gcc_gpu_bimc_gfx_clk */
	0x13B,		/* gcc_gpu_cfg_ahb_clk */
	0xBF,		/* gcc_hmss_dvm_bus_clk */
	0xBC,		/* gcc_hmss_rbcpr_clk */
	0x20,		/* gcc_mmss_noc_cfg_ahb_clk */
	0x1F,		/* gcc_mmss_sys_noc_axi_clk */
	0x11F,		/* gcc_mss_cfg_ahb_clk */
	0x120,		/* gcc_mss_mnoc_bimc_axi_clk */
	0x124,		/* gcc_mss_q6_bimc_axi_clk */
	0x123,		/* gcc_mss_snoc_axi_clk */
	0x74,		/* gcc_pdm2_clk */
	0x72,		/* gcc_pdm_ahb_clk */
	0x75,		/* gcc_prng_ahb_clk */
	0x172,		/* gcc_qspi_ahb_clk */
	0x173,		/* gcc_qspi_ser_clk */
	0x16E,		/* gcc_sdcc1_ahb_clk */
	0x16D,		/* gcc_sdcc1_apps_clk */
	0x16F,		/* gcc_sdcc1_ice_core_clk */
	0x47,		/* gcc_sdcc2_ahb_clk */
	0x46,		/* gcc_sdcc2_apps_clk */
	0xEB,		/* gcc_ufs_ahb_clk */
	0xEA,		/* gcc_ufs_axi_clk */
	0xF1,		/* gcc_ufs_ice_core_clk */
	0xF2,		/* gcc_ufs_phy_aux_clk */
	0xED,		/* gcc_ufs_rx_symbol_0_clk */
	0x162,		/* gcc_ufs_rx_symbol_1_clk */
	0xEC,		/* gcc_ufs_tx_symbol_0_clk */
	0xF0,		/* gcc_ufs_unipro_core_clk */
	0x169,		/* gcc_usb20_master_clk */
	0x16B,		/* gcc_usb20_mock_utmi_clk */
	0x16A,		/* gcc_usb20_sleep_clk */
	0x3C,		/* gcc_usb30_master_clk */
	0x3E,		/* gcc_usb30_mock_utmi_clk */
	0x3D,		/* gcc_usb30_sleep_clk */
	0x3F,		/* gcc_usb3_phy_aux_clk */
	0x40,		/* gcc_usb3_phy_pipe_clk */
	0x45,		/* gcc_usb_phy_cfg_ahb2phy_clk */
	0x13D,		/* gpu_cc_debug_mux */
	0x22,		/* mmss_cc_debug_mux */
	0xC0,		/* cpu_cc_debug_mux */
};

static struct clk_debug_mux gcc_debug_mux = {
	.priv = &debug_mux_priv,
	.en_mask = BIT(16),
	.debug_offset = 0x62000,
	.post_div_offset = 0x62000,
	.cbcr_offset = 0x62000,
	.src_sel_mask = 0x3FF,
	.src_sel_shift = 0,
	.post_div_mask = 0xF000,
	.post_div_shift = 12,
	.post_div_val = 1,
	.mux_sels = gcc_debug_mux_sels,
	.hw.init = &(struct clk_init_data){
		.name = "gcc_debug_mux",
		.ops = &clk_debug_mux_ops,
		.parent_names = gcc_debug_mux_parent_names,
		.num_parents = ARRAY_SIZE(gcc_debug_mux_parent_names),
		.flags = CLK_IS_MEASURE,
	},
};

static const char *const gpu_cc_debug_mux_parent_names[] = {
	"gpucc_gfx3d_clk",
	"gpucc_rbbmtimer_clk",
	"gpucc_rbcpr_clk",
};

static int gpu_cc_debug_mux_sels[] = {
	0x8,		/* gpucc_gfx3d_clk */
	0x5,		/* gpucc_rbbmtimer_clk */
	0x3,		/* gpucc_rbcpr_clk */
};

static struct clk_debug_mux gpu_cc_debug_mux = {
	.priv = &debug_mux_priv,
	.en_mask = BIT(16),
	.debug_offset = 0x120,
	.post_div_offset = 0x120,
	.cbcr_offset = 0x120,
	.src_sel_mask = 0xF,
	.src_sel_shift = 0,
	.post_div_mask = 0x60000,
	.post_div_shift = 17,
	.post_div_val = 3,
	.mux_sels = gpu_cc_debug_mux_sels,
	.hw.init = &(struct clk_init_data){
		.name = "gpu_cc_debug_mux",
		.ops = &clk_debug_mux_ops,
		.parent_names = gpu_cc_debug_mux_parent_names,
		.num_parents = ARRAY_SIZE(gpu_cc_debug_mux_parent_names),
		.flags = CLK_IS_MEASURE,
	},
};

static const char *const cpu_cc_debug_mux_parent_names[] = {
	"measure_only_perfcl_clk",
	"measure_only_pwrcl_clk",
};

static int cpu_cc_debug_mux_sels[] = {
	0x1,		/* measure_only_perfcl_clk */
	0x0,		/* measure_only_pwrcl_clk */
};

static int apss_cc_debug_mux_pre_divs[] = {
	0x8,		/* measure_only_perfcl_clk */
	0x8,		/* measure_only_pwrcl_clk */
};

static struct clk_debug_mux cpu_cc_debug_mux = {
	.priv = &debug_mux_priv,
	.debug_offset = 0x0,
	.post_div_offset = 0x0,
	.cbcr_offset = U32_MAX,
	.src_sel_mask = 0x3FF00,
	.src_sel_shift = 8,
	.post_div_mask = 0xF0000000,
	.post_div_shift = 28,
	.post_div_val = 1,
	.mux_sels = cpu_cc_debug_mux_sels,
	.pre_div_vals = apss_cc_debug_mux_pre_divs,
	.hw.init = &(struct clk_init_data){
		.name = "cpu_cc_debug_mux",
		.ops = &clk_debug_mux_ops,
		.parent_names = cpu_cc_debug_mux_parent_names,
		.num_parents = ARRAY_SIZE(cpu_cc_debug_mux_parent_names),
		.flags = CLK_IS_MEASURE,
	},
};

static const char *const mmss_cc_debug_mux_parent_names[] = {
	"measure_only_mmssnoc_axi_clk",
	"mmss_bimc_smmu_ahb_clk",
	"mmss_bimc_smmu_axi_clk",
	"mmss_camss_ahb_clk",
	"mmss_camss_cci_ahb_clk",
	"mmss_camss_cci_clk",
	"mmss_camss_cphy_csid0_clk",
	"mmss_camss_cphy_csid1_clk",
	"mmss_camss_cphy_csid2_clk",
	"mmss_camss_cphy_csid3_clk",
	"mmss_camss_cpp_ahb_clk",
	"mmss_camss_cpp_axi_clk",
	"mmss_camss_cpp_clk",
	"mmss_camss_cpp_vbif_ahb_clk",
	"mmss_camss_csi0_ahb_clk",
	"mmss_camss_csi0_clk",
	"mmss_camss_csi0phytimer_clk",
	"mmss_camss_csi0pix_clk",
	"mmss_camss_csi0rdi_clk",
	"mmss_camss_csi1_ahb_clk",
	"mmss_camss_csi1_clk",
	"mmss_camss_csi1phytimer_clk",
	"mmss_camss_csi1pix_clk",
	"mmss_camss_csi1rdi_clk",
	"mmss_camss_csi2_ahb_clk",
	"mmss_camss_csi2_clk",
	"mmss_camss_csi2phytimer_clk",
	"mmss_camss_csi2pix_clk",
	"mmss_camss_csi2rdi_clk",
	"mmss_camss_csi3_ahb_clk",
	"mmss_camss_csi3_clk",
	"mmss_camss_csi3pix_clk",
	"mmss_camss_csi3rdi_clk",
	"mmss_camss_csi_vfe0_clk",
	"mmss_camss_csi_vfe1_clk",
	"mmss_camss_csiphy0_clk",
	"mmss_camss_csiphy1_clk",
	"mmss_camss_csiphy2_clk",
	"mmss_camss_gp0_clk",
	"mmss_camss_gp1_clk",
	"mmss_camss_ispif_ahb_clk",
	"mmss_camss_jpeg0_clk",
	"mmss_camss_jpeg_ahb_clk",
	"mmss_camss_jpeg_axi_clk",
	"mmss_camss_mclk0_clk",
	"mmss_camss_mclk1_clk",
	"mmss_camss_mclk2_clk",
	"mmss_camss_mclk3_clk",
	"mmss_camss_micro_ahb_clk",
	"mmss_camss_top_ahb_clk",
	"mmss_camss_vfe0_ahb_clk",
	"mmss_camss_vfe0_clk",
	"mmss_camss_vfe0_stream_clk",
	"mmss_camss_vfe1_ahb_clk",
	"mmss_camss_vfe1_clk",
	"mmss_camss_vfe1_stream_clk",
	"mmss_camss_vfe_vbif_ahb_clk",
	"mmss_camss_vfe_vbif_axi_clk",
	"mmss_csiphy_ahb2crif_clk",
	"mmss_mdss_ahb_clk",
	"mmss_mdss_axi_clk",
	"mmss_mdss_byte0_clk",
	"mmss_mdss_byte0_intf_clk",
	"mmss_mdss_byte1_clk",
	"mmss_mdss_byte1_intf_clk",
	"mmss_mdss_dp_aux_clk",
	"mmss_mdss_dp_crypto_clk",
	"mmss_mdss_dp_gtc_clk",
	"mmss_mdss_dp_link_clk",
	"mmss_mdss_dp_link_intf_clk",
	"mmss_mdss_dp_pixel_clk",
	"mmss_mdss_esc0_clk",
	"mmss_mdss_esc1_clk",
	"mmss_mdss_hdmi_dp_ahb_clk",
	"mmss_mdss_mdp_clk",
	"mmss_mdss_pclk0_clk",
	"mmss_mdss_pclk1_clk",
	"mmss_mdss_rot_clk",
	"mmss_mdss_vsync_clk",
	"mmss_misc_ahb_clk",
	"mmss_misc_cxo_clk",
	"mmss_mnoc_ahb_clk",
	"mmss_snoc_dvm_axi_clk",
	"mmss_throttle_camss_axi_clk",
	"mmss_throttle_mdss_axi_clk",
	"mmss_throttle_video_axi_clk",
	"mmss_video_ahb_clk",
	"mmss_video_axi_clk",
	"mmss_video_core_clk",
	"mmss_video_subcore0_clk",
};

static int mmss_cc_debug_mux_sels[] = {
	0x4,		/* measure_only_mmssnoc_axi_clk" */
	0xC,		/* mmss_bimc_smmu_ahb_clk */
	0xD,		/* mmss_bimc_smmu_axi_clk */
	0x37,		/* mmss_camss_ahb_clk" */
	0x2E,		/* mmss_camss_cci_ahb_clk */
	0x2D,		/* mmss_camss_cci_clk" */
	0x8D,		/* mmss_camss_cphy_csid0_clk */
	0x8E,		/* mmss_camss_cphy_csid1_clk */
	0x8F,		/* mmss_camss_cphy_csid2_clk */
	0x90,		/* mmss_camss_cphy_csid3_clk */
	0x3B,		/* mmss_camss_cpp_ahb_clk */
	0x7A,		/* mmss_camss_cpp_axi_clk */
	0x3A,		/* mmss_camss_cpp_clk" */
	0x73,		/* mmss_camss_cpp_vbif_ahb_clk */
	0x42,		/* mmss_camss_csi0_ahb_clk */
	0x41,		/* mmss_camss_csi0_clk */
	0x2F,		/* mmss_camss_csi0phytimer_clk */
	0x45,		/* mmss_camss_csi0pix_clk */
	0x44,		/* mmss_camss_csi0rdi_clk */
	0x47,		/* mmss_camss_csi1_ahb_clk */
	0x46,		/* mmss_camss_csi1_clk */
	0x30,		/* mmss_camss_csi1phytimer_clk */
	0x4A,		/* mmss_camss_csi1pix_clk */
	0x49,		/* mmss_camss_csi1rdi_clk */
	0x4C,		/* mmss_camss_csi2_ahb_clk */
	0x4B,		/* mmss_camss_csi2_clk */
	0x31,		/* mmss_camss_csi2phytimer_clk */
	0x4F,		/* mmss_camss_csi2pix_clk */
	0x4E,		/* mmss_camss_csi2rdi_clk */
	0x51,		/* mmss_camss_csi3_ahb_clk */
	0x50,		/* mmss_camss_csi3_clk */
	0x54,		/* mmss_camss_csi3pix_clk" */
	0x53,		/* mmss_camss_csi3rdi_clk */
	0x3F,		/* mmss_camss_csi_vfe0_clk */
	0x40,		/* mmss_camss_csi_vfe1_clk */
	0x43,		/* mmss_camss_csiphy0_clk */
	0x85,		/* mmss_camss_csiphy1_clk */
	0x88,		/* mmss_camss_csiphy2_clk */
	0x27,		/* mmss_camss_gp0_clk" */
	0x28,		/* mmss_camss_gp1_clk" */
	0x33,		/* mmss_camss_ispif_ahb_clk */
	0x32,		/* mmss_camss_jpeg0_clk */
	0x35,		/* mmss_camss_jpeg_ahb_clk */
	0x36,		/* mmss_camss_jpeg_axi_clk */
	0x29,		/* mmss_camss_mclk0_clk */
	0x2A,		/* mmss_camss_mclk1_clk */
	0x2B,		/* mmss_camss_mclk2_clk */
	0x2C,		/* mmss_camss_mclk3_clk */
	0x26,		/* mmss_camss_micro_ahb_clk */
	0x25,		/* mmss_camss_top_ahb_clk */
	0x86,		/* mmss_camss_vfe0_ahb_clk */
	0x38,		/* mmss_camss_vfe0_clk */
	0x71,		/* mmss_camss_vfe0_stream_clk */
	0x87,		/* mmss_camss_vfe1_ahb_clk */
	0x39,		/* mmss_camss_vfe1_clk */
	0x72,		/* mmss_camss_vfe1_stream_clk */
	0x3C,		/* mmss_camss_vfe_vbif_ahb_clk */
	0x3D,		/* mmss_camss_vfe_vbif_axi_clk */
	0xB8,		/* mmss_csiphy_ahb2crif_clk */
	0x22,		/* mmss_mdss_ahb_clk" */
	0x24,		/* mmss_mdss_axi_clk" */
	0x1E,		/* mmss_mdss_byte0_clk */
	0xAD,		/* mmss_mdss_byte0_intf_clk */
	0x1F,		/* mmss_mdss_byte1_clk */
	0xB6,		/* mmss_mdss_byte1_intf_clk */
	0x9C,		/* mmss_mdss_dp_aux_clk */
	0x9A,		/* mmss_mdss_dp_crypto_clk */
	0x9D,		/* mmss_mdss_dp_gtc_clk */
	0x98,		/* mmss_mdss_dp_link_clk */
	0x99,		/* mmss_mdss_dp_link_intf_clk */
	0x9B,		/* mmss_mdss_dp_pixel_clk */
	0x20,		/* mmss_mdss_esc0_clk" */
	0x21,		/* mmss_mdss_esc1_clk" */
	0x23,		/* mmss_mdss_hdmi_dp_ahb_clk */
	0x14,		/* mmss_mdss_mdp_clk" */
	0x16,		/* mmss_mdss_pclk0_clk */
	0x17,		/* mmss_mdss_pclk1_clk */
	0x12,		/* mmss_mdss_rot_clk" */
	0x1C,		/* mmss_mdss_vsync_clk */
	0x3,		/* mmss_misc_ahb_clk" */
	0x77,		/* mmss_misc_cxo_clk" */
	0x1,		/* mmss_mnoc_ahb_clk" */
	0x13,		/* mmss_snoc_dvm_axi_clk */
	0xAA,		/* mmss_throttle_camss_axi_clk */
	0xAB,		/* mmss_throttle_mdss_axi_clk */
	0xAC,		/* mmss_throttle_video_axi_clk */
	0x11,		/* mmss_video_ahb_clk" */
	0xF,		/* mmss_video_axi_clk" */
	0xE,		/* mmss_video_core_clk */
	0x1A,		/* mmss_video_subcore0_clk */
};

static struct clk_debug_mux mmss_cc_debug_mux = {
	.priv = &debug_mux_priv,
	.en_mask = BIT(12),
	.debug_offset = 0x900,
	.post_div_offset = 0x900,
	.cbcr_offset = 0x900,
	.src_sel_mask = 0x1FF,
	.src_sel_shift = 0,
	.post_div_mask = 0x6000,
	.post_div_shift = 13,
	.post_div_val = 3,
	.mux_sels = mmss_cc_debug_mux_sels,
	.hw.init = &(struct clk_init_data){
		.name = "mmss_cc_debug_mux",
		.ops = &clk_debug_mux_ops,
		.parent_names = mmss_cc_debug_mux_parent_names,
		.num_parents = ARRAY_SIZE(mmss_cc_debug_mux_parent_names),
		.flags = CLK_IS_MEASURE,
	},
};

static struct clk_dummy measure_only_perfcl_clk = {
	.rrate = 1000,
	.hw.init = &(struct clk_init_data){
		.name = "measure_only_perfcl_clk",
		.ops = &clk_dummy_ops,
	},
};

static struct clk_dummy measure_only_pwrcl_clk = {
	.rrate = 1000,
	.hw.init = &(struct clk_init_data){
		.name = "measure_only_pwrcl_clk",
		.ops = &clk_dummy_ops,
	},
};

static struct clk_dummy measure_only_snoc_clk = {
	.rrate = 1000,
	.hw.init = &(struct clk_init_data){
		.name = "measure_only_snoc_clk",
		.ops = &clk_dummy_ops,
	},
};

static struct clk_dummy measure_only_cnoc_clk = {
	.rrate = 1000,
	.hw.init = &(struct clk_init_data){
		.name = "measure_only_cnoc_clk",
		.ops = &clk_dummy_ops,
	},
};

static struct clk_dummy measure_only_cnoc_periph_clk = {
	.rrate = 1000,
	.hw.init = &(struct clk_init_data){
		.name = "measure_only_cnoc_periph_clk",
		.ops = &clk_dummy_ops,
	},
};

static struct clk_dummy measure_only_bimc_clk = {
	.rrate = 1000,
	.hw.init = &(struct clk_init_data){
		.name = "measure_only_bimc_clk",
		.ops = &clk_dummy_ops,
	},
};

static struct clk_dummy measure_only_ce1_clk = {
	.rrate = 1000,
	.hw.init = &(struct clk_init_data){
		.name = "measure_only_ce1_clk",
		.ops = &clk_dummy_ops,
	},
};

static struct clk_dummy measure_only_ipa_clk = {
	.rrate = 1000,
	.hw.init = &(struct clk_init_data){
		.name = "measure_only_ipa_clk",
		.ops = &clk_dummy_ops,
	},
};

static struct clk_dummy measure_only_mmssnoc_axi_clk = {
	.rrate = 1000,
	.hw.init = &(struct clk_init_data){
		.name = "measure_only_mmssnoc_axi_clk",
		.ops = &clk_dummy_ops,
	},
};

struct clk_hw *debugcc_sdm660_hws[] = {
	&measure_only_snoc_clk.hw,
	&measure_only_cnoc_clk.hw,
	&measure_only_cnoc_periph_clk.hw,
	&measure_only_bimc_clk.hw,
	&measure_only_ce1_clk.hw,
	&measure_only_ipa_clk.hw,
	&measure_only_mmssnoc_axi_clk.hw,
	&measure_only_perfcl_clk.hw,
	&measure_only_pwrcl_clk.hw,
};

static struct mux_regmap_names mux_list[] = {
	{ .mux = &gcc_debug_mux, .regmap_name = "qcom,gcc" },
	{ .mux = &gpu_cc_debug_mux, .regmap_name = "qcom,gpu" },
	{ .mux = &cpu_cc_debug_mux, .regmap_name = "qcom,cpu" },
	{ .mux = &mmss_cc_debug_mux, .regmap_name = "qcom,mmss" },

};

static const struct of_device_id clk_debug_match_table[] = {
	{ .compatible = "qcom,sdm660-debugcc" },
	{}
};

static int clk_debug_sdm660_probe(struct platform_device *pdev)
{
	struct clk *clk;
	int ret = 0, i;

	BUILD_BUG_ON(ARRAY_SIZE(gcc_debug_mux_parent_names) !=
		     ARRAY_SIZE(gcc_debug_mux_sels));
	BUILD_BUG_ON(ARRAY_SIZE(gpu_cc_debug_mux_parent_names) !=
		ARRAY_SIZE(gpu_cc_debug_mux_sels));
	BUILD_BUG_ON(ARRAY_SIZE(mmss_cc_debug_mux_parent_names) !=
		ARRAY_SIZE(mmss_cc_debug_mux_sels));

	clk = devm_clk_get(&pdev->dev, "xo_clk_src");
	if (IS_ERR(clk)) {
		if (PTR_ERR(clk) != -EPROBE_DEFER)
			dev_err(&pdev->dev, "Unable to get xo clock\n");
		return PTR_ERR(clk);
	}

	debug_mux_priv.cxo = clk;

	for (i = 0; i < ARRAY_SIZE(mux_list); i++) {
		ret = map_debug_bases(pdev, mux_list[i].regmap_name,
				      mux_list[i].mux);
		if (ret == -EBADR)
			continue;
		else if (ret)
			return ret;

		clk = devm_clk_register(&pdev->dev, &mux_list[i].mux->hw);
		if (IS_ERR(clk)) {
			dev_err(&pdev->dev, "Unable to register %s, err:(%d)\n",
				mux_list[i].mux->hw.init->name, PTR_ERR(clk));
			return PTR_ERR(clk);
		}
	}

	for (i = 0; i < ARRAY_SIZE(debugcc_sdm660_hws); i++) {
		clk = devm_clk_register(&pdev->dev, debugcc_sdm660_hws[i]);
		if (IS_ERR(clk)) {
			dev_err(&pdev->dev, "Unable to register %s, err:(%d)\n",
			debugcc_sdm660_hws[i]->init->name, PTR_ERR(clk));
			return PTR_ERR(clk);
		}
	}

	ret = clk_debug_measure_register(&gcc_debug_mux.hw);
	if (ret)
		dev_err(&pdev->dev, "Could not register Measure clock\n");

	return ret;
}

static struct platform_driver clk_debug_driver = {
	.probe = clk_debug_sdm660_probe,
	.driver = {
		.name = "debugcc-sdm660",
		.of_match_table = clk_debug_match_table,
	},
};

int __init clk_debug_sdm660_init(void)
{
	return platform_driver_register(&clk_debug_driver);
}
fs_initcall(clk_debug_sdm660_init);
