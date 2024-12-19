// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2011, 2014-2016, 2018, The Linux Foundation. All rights reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

<<<<<<< HEAD
#if !defined(OPLUS_FEATURE_POWERINFO_STANDBY_DEBUG) || !defined(CONFIG_OPLUS_POWERINFO_STANDBY_DEBUG)
/* add for wakelock profiler */
int msm_show_resume_irq_mask;
#else
int msm_show_resume_irq_mask = 1;
#endif
=======
int msm_show_resume_irq_mask;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

module_param_named(
	debug_mask, msm_show_resume_irq_mask, int, 0664);
