/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2018-2019, The Linux Foundation. All rights reserved.
 */

#ifndef _ION_KERNEL_H
#define _ION_KERNEL_H

#include <linux/dma-buf.h>
#include <linux/bitmap.h>
<<<<<<< HEAD
#include "../uapi/ion.h"
#include "../uapi/msm_ion.h"
=======
#include <uapi/linux/ion.h>
#include <uapi/linux/msm_ion.h>
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

#ifdef CONFIG_ION

/*
 * Allocates an ion buffer.
 * Use IS_ERR on returned pointer to check for success.
 */
<<<<<<< HEAD
struct dma_buf *ion_alloc(size_t len, unsigned int heap_id_mask,
			  unsigned int flags);
=======
struct dma_buf *ion_alloc_dmabuf(size_t len, unsigned int heap_id_mask,
				 unsigned int flags);
static inline struct dma_buf *ion_alloc(size_t len, unsigned int heap_id_mask,
					unsigned int flags)
{
	return ion_alloc_dmabuf(len, heap_id_mask, flags);
}
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

static inline unsigned int ion_get_flags_num_vm_elems(unsigned int flags)
{
	unsigned long vm_flags = flags & ION_FLAGS_CP_MASK;

	return ((unsigned int)bitmap_weight(&vm_flags, BITS_PER_LONG));
}

int ion_populate_vm_list(unsigned long flags, unsigned int *vm_list,
			 int nelems);

#else

static inline struct dma_buf *ion_alloc(size_t len, unsigned int heap_id_mask,
					unsigned int flags)
{
	return -ENOMEM;
}

static inline unsigned int ion_get_flags_num_vm_elems(unsigned int flags)
{
	return 0;
}

static inline int ion_populate_vm_list(unsigned long flags,
				       unsigned int *vm_list, int nelems)
{
	return -EINVAL;
}

#endif /* CONFIG_ION */
#endif /* _ION_KERNEL_H */
