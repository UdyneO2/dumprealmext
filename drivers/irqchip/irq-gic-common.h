/*
 * Copyright (C) 2002 ARM Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _IRQ_GIC_COMMON_H
#define _IRQ_GIC_COMMON_H

#include <linux/of.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/arm-gic-common.h>

struct gic_quirk {
	const char *desc;
	bool (*init)(void *data);
	u32 iidr;
	u32 mask;
};
extern bool from_suspend;

<<<<<<< HEAD
#ifdef CONFIG_QCOM_SHOW_RESUME_IRQ
extern int msm_show_resume_irq_mask;
#else
#define msm_show_resume_irq_mask 0
#endif

=======
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
int gic_configure_irq(unsigned int irq, unsigned int type,
                       void __iomem *base, void (*sync_access)(void));
void gic_dist_config(void __iomem *base, int gic_irqs,
		     void (*sync_access)(void));
void gic_cpu_config(void __iomem *base, void (*sync_access)(void));
void gic_enable_quirks(u32 iidr, const struct gic_quirk *quirks,
		void *data);

void gic_set_kvm_info(const struct gic_kvm_info *info);

#endif /* _IRQ_GIC_COMMON_H */
