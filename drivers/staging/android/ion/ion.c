// SPDX-License-Identifier: GPL-2.0
/*
<<<<<<< HEAD
 * drivers/staging/android/ion/ion.c
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2020, The Linux Foundation. All rights reserved.
 *
 */

#include <linux/anon_inodes.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/memblock.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/rbtree.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/bitops.h>
#include <linux/msm_dma_iommu_mapping.h>
#define CREATE_TRACE_POINTS
#include <trace/events/ion.h>
#include <soc/qcom/secure_buffer.h>

#include "ion.h"
#include "ion_secure_util.h"

#if defined(OPLUS_FEATURE_HEALTHINFO) && defined(CONFIG_OPPO_HEALTHINFO) && defined (CONFIG_OPPO_MEM_MONITOR)
#include <linux/oppo_healthinfo/memory_monitor.h>
#endif /*OPLUS_FEATURE_HEALTHINFO*/

#if defined(OPLUS_FEATURE_HEALTHINFO) && defined(CONFIG_OPPO_HEALTHINFO)
#include <linux/oppo_healthinfo/oppo_ion.h>
#endif

static struct ion_device *internal_dev;
static atomic_long_t total_heap_bytes;

int ion_walk_heaps(int heap_id, enum ion_heap_type type, void *data,
		   int (*f)(struct ion_heap *heap, void *data))
{
	int ret_val = 0;
	struct ion_heap *heap;
	struct ion_device *dev = internal_dev;
	/*
	 * traverse the list of heaps available in this system
	 * and find the heap that is specified.
	 */
	down_write(&dev->lock);
	plist_for_each_entry(heap, &dev->heaps, node) {
		if (ION_HEAP(heap->id) != heap_id ||
		    type != heap->type)
			continue;
		ret_val = f(heap, data);
		break;
	}
	up_write(&dev->lock);
	return ret_val;
}
EXPORT_SYMBOL(ion_walk_heaps);

bool ion_buffer_cached(struct ion_buffer *buffer)
{
	return !!(buffer->flags & ION_FLAG_CACHED);
}

/* this function should only be called while dev->lock is held */
static void ion_buffer_add(struct ion_device *dev,
			   struct ion_buffer *buffer)
{
	struct rb_node **p = &dev->buffers.rb_node;
	struct rb_node *parent = NULL;
	struct ion_buffer *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct ion_buffer, node);

		if (buffer < entry) {
			p = &(*p)->rb_left;
		} else if (buffer > entry) {
			p = &(*p)->rb_right;
		} else {
			pr_err("%s: buffer already found.", __func__);
			BUG();
		}
	}

	rb_link_node(&buffer->node, parent, p);
	rb_insert_color(&buffer->node, &dev->buffers);
}

/* this function should only be called while dev->lock is held */
static struct ion_buffer *ion_buffer_create(struct ion_heap *heap,
					    struct ion_device *dev,
					    unsigned long len,
					    unsigned long flags)
{
	struct ion_buffer *buffer;
	struct sg_table *table;
	int ret;

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	buffer->heap = heap;
	buffer->flags = flags;
	buffer->dev = dev;
	buffer->size = len;

	ret = heap->ops->allocate(heap, buffer, len, flags);

	if (ret) {
		if (!(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto err2;

		if (ret == -EINTR)
			goto err2;

		ion_heap_freelist_drain(heap, 0);
		ret = heap->ops->allocate(heap, buffer, len, flags);
		if (ret)
			goto err2;
	}

	if (!buffer->sg_table) {
		WARN_ONCE(1, "This heap needs to set the sgtable");
		ret = -EINVAL;
		goto err1;
	}

	table = buffer->sg_table;
	INIT_LIST_HEAD(&buffer->attachments);
	INIT_LIST_HEAD(&buffer->vmas);
	mutex_init(&buffer->lock);

	if (IS_ENABLED(CONFIG_ION_FORCE_DMA_SYNC)) {
		int i;
		struct scatterlist *sg;

		/*
		 * this will set up dma addresses for the sglist -- it is not
		 * technically correct as per the dma api -- a specific
		 * device isn't really taking ownership here.  However, in
		 * practice on our systems the only dma_address space is
		 * physical addresses.
		 */
		for_each_sg(table->sgl, sg, table->nents, i) {
			sg_dma_address(sg) = sg_phys(sg);
			sg_dma_len(sg) = sg->length;
		}
	}

#if defined(OPLUS_FEATURE_MEMLEAK_DETECT) && defined(CONFIG_DUMP_TASKS_MEM)
	/* record creator before
	 * the buffer inster to heap.
	 */
	buffer->tsk = current->group_leader;
	get_task_struct(buffer->tsk);
	atomic64_add(buffer->size, &buffer->tsk->ions);
#endif
#if defined(OPLUS_FEATURE_MEMLEAK_DETECT) && defined(CONFIG_MEMLEAK_DETECT_THREAD) && defined(CONFIG_SVELTE)
	/* add record the buffer
	 * create time and calc the buffer age on dump.
	 */
	buffer->jiffies = jiffies;
#endif
	mutex_lock(&dev->buffer_lock);
	ion_buffer_add(dev, buffer);
	mutex_unlock(&dev->buffer_lock);
	atomic_long_add(len, &heap->total_allocated);
	atomic_long_add(len, &total_heap_bytes);
#ifdef OPLUS_FEATURE_HEALTHINFO
	if (ion_cnt_enable)
		atomic_long_add(buffer->size, &ion_total_size);
#endif /*OPLUS_FEATURE_HEALTHINFO*/
	return buffer;

err1:
	heap->ops->free(buffer);
err2:
	kfree(buffer);
	return ERR_PTR(ret);
}

void ion_buffer_destroy(struct ion_buffer *buffer)
{
	if (buffer->kmap_cnt > 0) {
		pr_warn_ratelimited("ION client likely missing a call to dma_buf_kunmap or dma_buf_vunmap\n");
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
	}
#ifdef OPLUS_FEATURE_HEALTHINFO
	if (ion_cnt_enable)
		atomic_long_sub(buffer->size, &ion_total_size);
#endif /*OPLUS_FEATURE_HEALTHINFO*/
#ifdef CONFIG_DUMP_TASKS_MEM
	/* accounts process-real-phymem*/
	if (buffer->tsk) {
		atomic64_sub(buffer->size, &buffer->tsk->ions);
		put_task_struct(buffer->tsk);
		buffer->tsk = NULL;
	}
#endif /* CONFIG_DUMP_TASKS_MEM */
	buffer->heap->ops->free(buffer);
	kfree(buffer);
}

static void _ion_buffer_destroy(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct ion_device *dev = buffer->dev;

	msm_dma_buf_freed(buffer);

	mutex_lock(&dev->buffer_lock);
	rb_erase(&buffer->node, &dev->buffers);
	mutex_unlock(&dev->buffer_lock);
	atomic_long_sub(buffer->size, &total_heap_bytes);

	atomic_long_sub(buffer->size, &buffer->heap->total_allocated);
	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_freelist_add(heap, buffer);
	else
		ion_buffer_destroy(buffer);
}

static void *ion_buffer_kmap_get(struct ion_buffer *buffer)
{
	void *vaddr;

	if (buffer->kmap_cnt) {
		buffer->kmap_cnt++;
		return buffer->vaddr;
	}
	vaddr = buffer->heap->ops->map_kernel(buffer->heap, buffer);
	if (WARN_ONCE(!vaddr,
		      "heap->ops->map_kernel should return ERR_PTR on error"))
		return ERR_PTR(-EINVAL);
	if (IS_ERR(vaddr))
		return vaddr;
	buffer->vaddr = vaddr;
	buffer->kmap_cnt++;
	return vaddr;
}

static void ion_buffer_kmap_put(struct ion_buffer *buffer)
{
	if (buffer->kmap_cnt == 0) {
		pr_warn_ratelimited("ION client likely missing a call to dma_buf_kmap or dma_buf_vmap, pid:%d\n",
				    current->pid);
		return;
	}

	buffer->kmap_cnt--;
	if (!buffer->kmap_cnt) {
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
		buffer->vaddr = NULL;
	}
}

static struct sg_table *dup_sg_table(struct sg_table *table)
{
	struct sg_table *new_table;
	int ret, i;
	struct scatterlist *sg, *new_sg;

	new_table = kzalloc(sizeof(*new_table), GFP_KERNEL);
	if (!new_table)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(new_table, table->nents, GFP_KERNEL);
	if (ret) {
		kfree(new_table);
		return ERR_PTR(-ENOMEM);
	}

	new_sg = new_table->sgl;
	for_each_sg(table->sgl, sg, table->nents, i) {
		memcpy(new_sg, sg, sizeof(*sg));
		sg_dma_address(new_sg) = 0;
		sg_dma_len(new_sg) = 0;
		new_sg = sg_next(new_sg);
	}

	return new_table;
}

static void free_duped_table(struct sg_table *table)
{
	sg_free_table(table);
	kfree(table);
}

struct ion_dma_buf_attachment {
	struct device *dev;
	struct sg_table *table;
=======
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019-2021 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "ion_secure_util.h"
#include "ion_system_secure_heap.h"
#include "compat_ion.h"

#ifdef CONFIG_ION_LEGACY
#include "ion_legacy.h"
#endif

struct ion_dma_buf_attachment {
	struct ion_dma_buf_attachment *next;
	struct device *dev;
	struct sg_table table;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	struct list_head list;
	bool dma_mapped;
};

<<<<<<< HEAD
static int ion_dma_buf_attach(struct dma_buf *dmabuf,
			      struct dma_buf_attachment *attachment)
{
	struct ion_dma_buf_attachment *a;
	struct sg_table *table;
	struct ion_buffer *buffer = dmabuf->priv;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	table = dup_sg_table(buffer->sg_table);
	if (IS_ERR(table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->table = table;
	a->dev = attachment->dev;
	a->dma_mapped = false;
	INIT_LIST_HEAD(&a->list);

	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void ion_dma_buf_detatch(struct dma_buf *dmabuf,
				struct dma_buf_attachment *attachment)
{
	struct ion_dma_buf_attachment *a = attachment->priv;
	struct ion_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);
	free_duped_table(a->table);

	kfree(a);
}

static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction direction)
{
	struct ion_dma_buf_attachment *a = attachment->priv;
	struct sg_table *table;
	int count, map_attrs;
	struct ion_buffer *buffer = attachment->dmabuf->priv;

	table = a->table;

	map_attrs = attachment->dma_map_attrs;
=======
static long ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static const struct file_operations ion_fops = {
	.unlocked_ioctl = ion_ioctl,
#ifdef CONFIG_COMPAT
#ifdef CONFIG_ION_LEGACY
	.compat_ioctl = compat_ion_ioctl
#else
	.compat_ioctl = ion_ioctl
#endif
#endif
};

static struct ion_device ion_dev = {
	.heaps = PLIST_HEAD_INIT(ion_dev.heaps),
	.dev = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = "ion",
		.fops = &ion_fops
	}
};

static void ion_buffer_free_work(struct work_struct *work)
{
	struct ion_buffer *buffer = container_of(work, typeof(*buffer), free);
	struct ion_dma_buf_attachment *a, *next;
	struct ion_heap *heap = buffer->heap;

	msm_dma_buf_freed(&buffer->iommu_data);
	for (a = buffer->attachments; a; a = next) {
		next = a->next;
		sg_free_table(&a->table);
		kfree(a);
	}
	if (buffer->kmap_refcount)
		heap->ops->unmap_kernel(heap, buffer);
	heap->ops->free(buffer);
	kfree(buffer);
}

static struct ion_buffer *ion_buffer_create(struct ion_heap *heap, size_t len,
					    unsigned int flags)
{
	struct ion_buffer *buffer;
	int ret;

	buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	*buffer = (typeof(*buffer)){
		.flags = flags,
		.heap = heap,
		.size = len,
		.kmap_lock = __MUTEX_INITIALIZER(buffer->kmap_lock),
		.free = __WORK_INITIALIZER(buffer->free, ion_buffer_free_work),
		.map_freelist = LIST_HEAD_INIT(buffer->map_freelist),
		.freelist_lock = __SPIN_LOCK_INITIALIZER(buffer->freelist_lock),
		.iommu_data = {
			.map_list = LIST_HEAD_INIT(buffer->iommu_data.map_list),
			.lock = __MUTEX_INITIALIZER(buffer->iommu_data.lock)
		}
	};

	ret = heap->ops->allocate(heap, buffer, len, flags);
	if (ret) {
		if (ret == -EINTR || !(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto free_buffer;

		drain_workqueue(heap->wq);
		if (heap->ops->allocate(heap, buffer, len, flags))
			goto free_buffer;
	}

	return buffer;

free_buffer:
	kfree(buffer);
	return ERR_PTR(ret);
}

static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction dir)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a = attachment->priv;
	int count, map_attrs = attachment->dma_map_attrs;

>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (!(buffer->flags & ION_FLAG_CACHED) ||
	    !hlos_accessible_buffer(buffer))
		map_attrs |= DMA_ATTR_SKIP_CPU_SYNC;

<<<<<<< HEAD
	mutex_lock(&buffer->lock);
	if (map_attrs & DMA_ATTR_SKIP_CPU_SYNC)
		trace_ion_dma_map_cmo_skip(attachment->dev,
					   attachment->dmabuf->buf_name,
					   ion_buffer_cached(buffer),
					   hlos_accessible_buffer(buffer),
					   attachment->dma_map_attrs,
					   direction);
	else
		trace_ion_dma_map_cmo_apply(attachment->dev,
					    attachment->dmabuf->buf_name,
					    ion_buffer_cached(buffer),
					    hlos_accessible_buffer(buffer),
					    attachment->dma_map_attrs,
					    direction);

	if (map_attrs & DMA_ATTR_DELAYED_UNMAP) {
		count = msm_dma_map_sg_attrs(attachment->dev, table->sgl,
					     table->nents, direction,
					     attachment->dmabuf, map_attrs);
	} else {
		count = dma_map_sg_attrs(attachment->dev, table->sgl,
					 table->nents, direction,
					 map_attrs);
	}

	if (count <= 0) {
		mutex_unlock(&buffer->lock);
		return ERR_PTR(-ENOMEM);
	}

	a->dma_mapped = true;
	mutex_unlock(&buffer->lock);
	return table;
=======
	if (map_attrs & DMA_ATTR_DELAYED_UNMAP)
		count = msm_dma_map_sg_attrs(attachment->dev, a->table.sgl,
					     a->table.nents, dir, dmabuf,
					     map_attrs);
	else
		count = dma_map_sg_attrs(attachment->dev, a->table.sgl,
					 a->table.nents, dir, map_attrs);
	if (!count)
		return ERR_PTR(-ENOMEM);

	a->dma_mapped = true;
	return &a->table;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
}

static void ion_unmap_dma_buf(struct dma_buf_attachment *attachment,
			      struct sg_table *table,
<<<<<<< HEAD
			      enum dma_data_direction direction)
{
	int map_attrs;
	struct ion_buffer *buffer = attachment->dmabuf->priv;
	struct ion_dma_buf_attachment *a = attachment->priv;

	map_attrs = attachment->dma_map_attrs;
=======
			      enum dma_data_direction dir)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a = attachment->priv;
	int map_attrs = attachment->dma_map_attrs;

>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (!(buffer->flags & ION_FLAG_CACHED) ||
	    !hlos_accessible_buffer(buffer))
		map_attrs |= DMA_ATTR_SKIP_CPU_SYNC;

<<<<<<< HEAD
	mutex_lock(&buffer->lock);
	if (map_attrs & DMA_ATTR_SKIP_CPU_SYNC)
		trace_ion_dma_unmap_cmo_skip(attachment->dev,
					     attachment->dmabuf->buf_name,
					     ion_buffer_cached(buffer),
					     hlos_accessible_buffer(buffer),
					     attachment->dma_map_attrs,
					     direction);
	else
		trace_ion_dma_unmap_cmo_apply(attachment->dev,
					      attachment->dmabuf->buf_name,
					      ion_buffer_cached(buffer),
					      hlos_accessible_buffer(buffer),
					      attachment->dma_map_attrs,
					      direction);

	if (map_attrs & DMA_ATTR_DELAYED_UNMAP)
		msm_dma_unmap_sg_attrs(attachment->dev, table->sgl,
				       table->nents, direction,
				       attachment->dmabuf,
				       map_attrs);
	else
		dma_unmap_sg_attrs(attachment->dev, table->sgl, table->nents,
				   direction, map_attrs);
	a->dma_mapped = false;
	mutex_unlock(&buffer->lock);
}

void ion_pages_sync_for_device(struct device *dev, struct page *page,
			       size_t size, enum dma_data_direction dir)
{
	struct scatterlist sg;

	sg_init_table(&sg, 1);
	sg_set_page(&sg, page, size, 0);
	/*
	 * This is not correct - sg_dma_address needs a dma_addr_t that is valid
	 * for the targeted device, but this works on the currently targeted
	 * hardware.
	 */
	sg_dma_address(&sg) = page_to_phys(page);
	dma_sync_sg_for_device(dev, &sg, 1, dir);
}

static void ion_vm_open(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list;

	vma_list = kmalloc(sizeof(*vma_list), GFP_KERNEL);
	if (!vma_list)
		return;
	vma_list->vma = vma;
	mutex_lock(&buffer->lock);
	list_add(&vma_list->list, &buffer->vmas);
	mutex_unlock(&buffer->lock);
}

static void ion_vm_close(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list, *tmp;

	mutex_lock(&buffer->lock);
	list_for_each_entry_safe(vma_list, tmp, &buffer->vmas, list) {
		if (vma_list->vma != vma)
			continue;
		list_del(&vma_list->list);
		kfree(vma_list);
		break;
	}
	mutex_unlock(&buffer->lock);
}

static const struct vm_operations_struct ion_vma_ops = {
	.open = ion_vm_open,
	.close = ion_vm_close,
};

static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = dmabuf->priv;
	int ret = 0;

	if (!buffer->heap->ops->map_user) {
		pr_err("%s: this heap does not define a method for mapping to userspace\n",
		       __func__);
		return -EINVAL;
	}
=======
	if (map_attrs & DMA_ATTR_DELAYED_UNMAP)
		msm_dma_unmap_sg_attrs(attachment->dev, table->sgl,
				       table->nents, dir, dmabuf, map_attrs);
	else
		dma_unmap_sg_attrs(attachment->dev, table->sgl, table->nents,
				   dir, map_attrs);
	a->dma_mapped = false;
}

static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;

	if (!buffer->heap->ops->map_user)
		return -EINVAL;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	if (!(buffer->flags & ION_FLAG_CACHED))
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

<<<<<<< HEAD
	vma->vm_private_data = buffer;
	vma->vm_ops = &ion_vma_ops;
	ion_vm_open(vma);

	mutex_lock(&buffer->lock);
	/* now map it to userspace */
	ret = buffer->heap->ops->map_user(buffer->heap, buffer, vma);
	mutex_unlock(&buffer->lock);

	if (ret)
		pr_err("%s: failure mapping buffer to userspace\n",
		       __func__);

	return ret;
=======
	return heap->ops->map_user(heap, buffer, vma);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
}

static void ion_dma_buf_release(struct dma_buf *dmabuf)
{
<<<<<<< HEAD
	struct ion_buffer *buffer = dmabuf->priv;

	_ion_buffer_destroy(buffer);
	kfree(dmabuf->exp_name);
=======
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		queue_work(heap->wq, &buffer->free);
	else
		ion_buffer_free_work(&buffer->free);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
}

static void *ion_dma_buf_vmap(struct dma_buf *dmabuf)
{
<<<<<<< HEAD
	struct ion_buffer *buffer = dmabuf->priv;
	void *vaddr = ERR_PTR(-EINVAL);

	if (buffer->heap->ops->map_kernel) {
		mutex_lock(&buffer->lock);
		vaddr = ion_buffer_kmap_get(buffer);
		mutex_unlock(&buffer->lock);
	} else {
		pr_warn_ratelimited("heap %s doesn't support map_kernel\n",
				    buffer->heap->name);
	}
=======
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;
	void *vaddr;

	if (!heap->ops->map_kernel)
		return ERR_PTR(-ENODEV);

	mutex_lock(&buffer->kmap_lock);
	if (buffer->kmap_refcount) {
		vaddr = buffer->vaddr;
		buffer->kmap_refcount++;
	} else {
		vaddr = heap->ops->map_kernel(heap, buffer);
		if (IS_ERR_OR_NULL(vaddr)) {
			vaddr = ERR_PTR(-EINVAL);
		} else {
			buffer->vaddr = vaddr;
			buffer->kmap_refcount++;
		}
	}
	mutex_unlock(&buffer->kmap_lock);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	return vaddr;
}

static void ion_dma_buf_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
<<<<<<< HEAD
	struct ion_buffer *buffer = dmabuf->priv;

	if (buffer->heap->ops->map_kernel) {
		mutex_lock(&buffer->lock);
		ion_buffer_kmap_put(buffer);
		mutex_unlock(&buffer->lock);
	}
=======
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;

	mutex_lock(&buffer->kmap_lock);
	if (!--buffer->kmap_refcount)
		heap->ops->unmap_kernel(heap, buffer);
	mutex_unlock(&buffer->kmap_lock);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
}

static void *ion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
<<<<<<< HEAD
	/*
	 * TODO: Once clients remove their hacks where they assume kmap(ed)
	 * addresses are virtually contiguous implement this properly
	 */
	void *vaddr = ion_dma_buf_vmap(dmabuf);

=======
	void *vaddr;

	vaddr = ion_dma_buf_vmap(dmabuf);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (IS_ERR(vaddr))
		return vaddr;

	return vaddr + offset * PAGE_SIZE;
}

static void ion_dma_buf_kunmap(struct dma_buf *dmabuf, unsigned long offset,
			       void *ptr)
{
<<<<<<< HEAD
	/*
	 * TODO: Once clients remove their hacks where they assume kmap(ed)
	 * addresses are virtually contiguous implement this properly
	 */
	ion_dma_buf_vunmap(dmabuf, ptr);
}

static int ion_sgl_sync_range(struct device *dev, struct scatterlist *sgl,
			      unsigned int nents, unsigned long offset,
			      unsigned long length,
			      enum dma_data_direction dir, bool for_cpu)
{
	int i;
	struct scatterlist *sg;
	unsigned int len = 0;
	dma_addr_t sg_dma_addr;

	for_each_sg(sgl, sg, nents, i) {
		if (sg_dma_len(sg) == 0)
			break;

		if (i > 0) {
			pr_warn_ratelimited("Partial cmo only supported with 1 segment\n"
				"is dma_set_max_seg_size being set on dev:%s\n",
				dev_name(dev));
			return -EINVAL;
		}
	}

	for_each_sg(sgl, sg, nents, i) {
		unsigned int sg_offset, sg_left, size = 0;

		if (i == 0)
			sg_dma_addr = sg_dma_address(sg);

		len += sg->length;
		if (len <= offset) {
=======
	ion_dma_buf_vunmap(dmabuf, NULL);
}

static int ion_dup_sg_table(struct sg_table *dst, struct sg_table *src)
{
	unsigned int nents = src->nents;
	struct scatterlist *d, *s;

	if (sg_alloc_table(dst, nents, GFP_KERNEL))
		return -ENOMEM;

	for (d = dst->sgl, s = src->sgl;
	     nents > SG_MAX_SINGLE_ALLOC; nents -= SG_MAX_SINGLE_ALLOC - 1,
	     d = sg_chain_ptr(&d[SG_MAX_SINGLE_ALLOC - 1]),
	     s = sg_chain_ptr(&s[SG_MAX_SINGLE_ALLOC - 1]))
		memcpy(d, s, (SG_MAX_SINGLE_ALLOC - 1) * sizeof(*d));

	if (nents)
		memcpy(d, s, nents * sizeof(*d));

	return 0;
}

static int ion_dma_buf_attach(struct dma_buf *dmabuf,
			      struct dma_buf_attachment *attachment)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;

	spin_lock(&buffer->freelist_lock);
	list_for_each_entry(a, &buffer->map_freelist, list) {
		if (a->dev == attachment->dev) {
			list_del(&a->list);
			spin_unlock(&buffer->freelist_lock);
			attachment->priv = a;
			return 0;
		}
	}
	spin_unlock(&buffer->freelist_lock);

	a = kmalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	if (ion_dup_sg_table(&a->table, buffer->sg_table)) {
		kfree(a);
		return -ENOMEM;
	}

	a->dev = attachment->dev;
	a->dma_mapped = false;
	attachment->priv = a;
	a->next = buffer->attachments;
	buffer->attachments = a;

	return 0;
}

static void ion_dma_buf_detach(struct dma_buf *dmabuf,
			       struct dma_buf_attachment *attachment)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a = attachment->priv;

	spin_lock(&buffer->freelist_lock);
	list_add(&a->list, &buffer->map_freelist);
	spin_unlock(&buffer->freelist_lock);
}

static int ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					enum dma_data_direction dir)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (a->dma_mapped)
			dma_sync_sg_for_cpu(a->dev, a->table.sgl,
					    a->table.nents, dir);
	}

	return 0;
}

static int ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
				      enum dma_data_direction dir)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (a->dma_mapped)
			dma_sync_sg_for_device(a->dev, a->table.sgl,
					       a->table.nents, dir);
	}

	return 0;
}

static void ion_sgl_sync_range(struct device *dev, struct scatterlist *sgl,
			       unsigned int nents, unsigned long offset,
			       unsigned long len, enum dma_data_direction dir,
			       bool for_cpu)
{
	dma_addr_t sg_dma_addr = sg_dma_address(sgl);
	unsigned long total = 0;
	struct scatterlist *sg;
	int i;

	for_each_sg(sgl, sg, nents, i) {
		unsigned long sg_offset, sg_left, size;

		total += sg->length;
		if (total <= offset) {
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
			sg_dma_addr += sg->length;
			continue;
		}

<<<<<<< HEAD
		sg_left = len - offset;
		sg_offset = sg->length - sg_left;

		size = (length < sg_left) ? length : sg_left;
=======
		sg_left = total - offset;
		sg_offset = sg->length - sg_left;
		size = min(len, sg_left);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
		if (for_cpu)
			dma_sync_single_range_for_cpu(dev, sg_dma_addr,
						      sg_offset, size, dir);
		else
			dma_sync_single_range_for_device(dev, sg_dma_addr,
							 sg_offset, size, dir);
<<<<<<< HEAD

		offset += size;
		length -= size;
		sg_dma_addr += sg->length;

		if (length == 0)
			break;
	}

	return 0;
}

static int ion_sgl_sync_mapped(struct device *dev, struct scatterlist *sgl,
			       unsigned int nents, struct list_head *vmas,
			       enum dma_data_direction dir, bool for_cpu)
{
	struct ion_vma_list *vma_list;
	int ret = 0;

	list_for_each_entry(vma_list, vmas, list) {
		struct vm_area_struct *vma = vma_list->vma;

		ret = ion_sgl_sync_range(dev, sgl, nents,
					 vma->vm_pgoff * PAGE_SIZE,
					 vma->vm_end - vma->vm_start, dir,
					 for_cpu);
		if (ret)
			break;
	}

	return ret;
}

static int __ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					  enum dma_data_direction direction,
					  bool sync_only_mapped)
{
	struct ion_buffer *buffer = dmabuf->priv;
	struct ion_dma_buf_attachment *a;
	int ret = 0;

	if (!hlos_accessible_buffer(buffer)) {
		trace_ion_begin_cpu_access_cmo_skip(NULL, dmabuf->buf_name,
						    ion_buffer_cached(buffer),
						    false, direction,
						    sync_only_mapped);
		ret = -EPERM;
		goto out;
	}

	if (!(buffer->flags & ION_FLAG_CACHED)) {
		trace_ion_begin_cpu_access_cmo_skip(NULL, dmabuf->buf_name,
						    false, true, direction,
						    sync_only_mapped);
		goto out;
	}

	mutex_lock(&buffer->lock);

	if (IS_ENABLED(CONFIG_ION_FORCE_DMA_SYNC)) {
		struct device *dev = buffer->heap->priv;
		struct sg_table *table = buffer->sg_table;

		if (sync_only_mapped)
			ret = ion_sgl_sync_mapped(dev, table->sgl,
						  table->nents, &buffer->vmas,
						  direction, true);
		else
			dma_sync_sg_for_cpu(dev, table->sgl,
					    table->nents, direction);

		if (!ret)
			trace_ion_begin_cpu_access_cmo_apply(dev,
							     dmabuf->buf_name,
							     true, true,
							     direction,
							     sync_only_mapped);
		else
			trace_ion_begin_cpu_access_cmo_skip(dev,
							    dmabuf->buf_name,
							    true, true,
							    direction,
							    sync_only_mapped);
		mutex_unlock(&buffer->lock);
		goto out;
	}

	list_for_each_entry(a, &buffer->attachments, list) {
		int tmp = 0;

		if (!a->dma_mapped) {
			trace_ion_begin_cpu_access_notmapped(a->dev,
							     dmabuf->buf_name,
							     true, true,
							     direction,
							     sync_only_mapped);
			continue;
		}

		if (sync_only_mapped)
			tmp = ion_sgl_sync_mapped(a->dev, a->table->sgl,
						  a->table->nents,
						  &buffer->vmas,
						  direction, true);
		else
			dma_sync_sg_for_cpu(a->dev, a->table->sgl,
					    a->table->nents, direction);

		if (!tmp) {
			trace_ion_begin_cpu_access_cmo_apply(a->dev,
							     dmabuf->buf_name,
							     true, true,
							     direction,
							     sync_only_mapped);
		} else {
			trace_ion_begin_cpu_access_cmo_skip(a->dev,
							    dmabuf->buf_name,
							    true, true,
							    direction,
							    sync_only_mapped);
			ret = tmp;
		}

	}
	mutex_unlock(&buffer->lock);
out:
	return ret;
}

static int __ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
					enum dma_data_direction direction,
					bool sync_only_mapped)
{
	struct ion_buffer *buffer = dmabuf->priv;
	struct ion_dma_buf_attachment *a;
	int ret = 0;

	if (!hlos_accessible_buffer(buffer)) {
		trace_ion_end_cpu_access_cmo_skip(NULL, dmabuf->buf_name,
						  ion_buffer_cached(buffer),
						  false, direction,
						  sync_only_mapped);
		ret = -EPERM;
		goto out;
	}

	if (!(buffer->flags & ION_FLAG_CACHED)) {
		trace_ion_end_cpu_access_cmo_skip(NULL, dmabuf->buf_name, false,
						  true, direction,
						  sync_only_mapped);
		goto out;
	}

	mutex_lock(&buffer->lock);
	if (IS_ENABLED(CONFIG_ION_FORCE_DMA_SYNC)) {
		struct device *dev = buffer->heap->priv;
		struct sg_table *table = buffer->sg_table;

		if (sync_only_mapped)
			ret = ion_sgl_sync_mapped(dev, table->sgl,
						  table->nents, &buffer->vmas,
						  direction, false);
		else
			dma_sync_sg_for_device(dev, table->sgl,
					       table->nents, direction);

		if (!ret)
			trace_ion_end_cpu_access_cmo_apply(dev,
							   dmabuf->buf_name,
							   true, true,
							   direction,
							   sync_only_mapped);
		else
			trace_ion_end_cpu_access_cmo_skip(dev, dmabuf->buf_name,
							  true, true, direction,
							  sync_only_mapped);
		mutex_unlock(&buffer->lock);
		goto out;
	}

	list_for_each_entry(a, &buffer->attachments, list) {
		int tmp = 0;

		if (!a->dma_mapped) {
			trace_ion_end_cpu_access_notmapped(a->dev,
							   dmabuf->buf_name,
							   true, true,
							   direction,
							   sync_only_mapped);
			continue;
		}

		if (sync_only_mapped)
			tmp = ion_sgl_sync_mapped(a->dev, a->table->sgl,
						  a->table->nents,
						  &buffer->vmas, direction,
						  false);
		else
			dma_sync_sg_for_device(a->dev, a->table->sgl,
					       a->table->nents, direction);

		if (!tmp) {
			trace_ion_end_cpu_access_cmo_apply(a->dev,
							   dmabuf->buf_name,
							   true, true,
							   direction,
							   sync_only_mapped);
		} else {
			trace_ion_end_cpu_access_cmo_skip(a->dev,
							  dmabuf->buf_name,
							  true, true, direction,
							  sync_only_mapped);
			ret = tmp;
		}
	}
	mutex_unlock(&buffer->lock);

out:
	return ret;
}

static int ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf,
					enum dma_data_direction direction)
{
	return __ion_dma_buf_begin_cpu_access(dmabuf, direction, false);
}

static int ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
				      enum dma_data_direction direction)
{
	return __ion_dma_buf_end_cpu_access(dmabuf, direction, false);
}

static int ion_dma_buf_begin_cpu_access_umapped(struct dma_buf *dmabuf,
						enum dma_data_direction dir)
{
	return __ion_dma_buf_begin_cpu_access(dmabuf, dir, true);
}

static int ion_dma_buf_end_cpu_access_umapped(struct dma_buf *dmabuf,
					      enum dma_data_direction dir)
{
	return __ion_dma_buf_end_cpu_access(dmabuf, dir, true);
}

=======
		len -= size;
		if (!len)
			break;

		offset += size;
		sg_dma_addr += sg->length;
	}
}

static int ion_dma_buf_cpu_access_partial(struct dma_buf *dmabuf,
					  enum dma_data_direction dir,
					  unsigned int offset, unsigned int len,
					  bool start)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;
	int ret = 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (!a->dma_mapped)
			continue;

		if (a->table.nents > 1 && sg_next(a->table.sgl)->dma_length) {
			ret = -EINVAL;
			continue;
		}

		ion_sgl_sync_range(a->dev, a->table.sgl, a->table.nents, offset,
				   len, dir, start);
	}

	return ret;
}

>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
static int ion_dma_buf_begin_cpu_access_partial(struct dma_buf *dmabuf,
						enum dma_data_direction dir,
						unsigned int offset,
						unsigned int len)
{
<<<<<<< HEAD
	struct ion_buffer *buffer = dmabuf->priv;
	struct ion_dma_buf_attachment *a;
	int ret = 0;

	if (!hlos_accessible_buffer(buffer)) {
		trace_ion_begin_cpu_access_cmo_skip(NULL, dmabuf->buf_name,
						    ion_buffer_cached(buffer),
						    false, dir,
						    false);
		ret = -EPERM;
		goto out;
	}

	if (!(buffer->flags & ION_FLAG_CACHED)) {
		trace_ion_begin_cpu_access_cmo_skip(NULL, dmabuf->buf_name,
						    false, true, dir,
						    false);
		goto out;
	}

	mutex_lock(&buffer->lock);
	if (IS_ENABLED(CONFIG_ION_FORCE_DMA_SYNC)) {
		struct device *dev = buffer->heap->priv;
		struct sg_table *table = buffer->sg_table;

		ret = ion_sgl_sync_range(dev, table->sgl, table->nents,
					 offset, len, dir, true);

		if (!ret)
			trace_ion_begin_cpu_access_cmo_apply(dev,
							     dmabuf->buf_name,
							     true, true, dir,
							     false);
		else
			trace_ion_begin_cpu_access_cmo_skip(dev,
							    dmabuf->buf_name,
							    true, true, dir,
							    false);
		mutex_unlock(&buffer->lock);
		goto out;
	}

	list_for_each_entry(a, &buffer->attachments, list) {
		int tmp = 0;

		if (!a->dma_mapped) {
			trace_ion_begin_cpu_access_notmapped(a->dev,
							     dmabuf->buf_name,
							     true, true,
							     dir,
							     false);
			continue;
		}

		tmp = ion_sgl_sync_range(a->dev, a->table->sgl, a->table->nents,
					 offset, len, dir, true);

		if (!tmp) {
			trace_ion_begin_cpu_access_cmo_apply(a->dev,
							     dmabuf->buf_name,
							     true, true, dir,
							     false);
		} else {
			trace_ion_begin_cpu_access_cmo_skip(a->dev,
							    dmabuf->buf_name,
							    true, true, dir,
							    false);
			ret = tmp;
		}
	}
	mutex_unlock(&buffer->lock);

out:
	return ret;
}

static int ion_dma_buf_end_cpu_access_partial(struct dma_buf *dmabuf,
					      enum dma_data_direction direction,
					      unsigned int offset,
					      unsigned int len)
{
	struct ion_buffer *buffer = dmabuf->priv;
	struct ion_dma_buf_attachment *a;
	int ret = 0;

	if (!hlos_accessible_buffer(buffer)) {
		trace_ion_end_cpu_access_cmo_skip(NULL, dmabuf->buf_name,
						  ion_buffer_cached(buffer),
						  false, direction,
						  false);
		ret = -EPERM;
		goto out;
	}

	if (!(buffer->flags & ION_FLAG_CACHED)) {
		trace_ion_end_cpu_access_cmo_skip(NULL, dmabuf->buf_name, false,
						  true, direction,
						  false);
		goto out;
	}

	mutex_lock(&buffer->lock);
	if (IS_ENABLED(CONFIG_ION_FORCE_DMA_SYNC)) {
		struct device *dev = buffer->heap->priv;
		struct sg_table *table = buffer->sg_table;

		ret = ion_sgl_sync_range(dev, table->sgl, table->nents,
					 offset, len, direction, false);

		if (!ret)
			trace_ion_end_cpu_access_cmo_apply(dev,
							   dmabuf->buf_name,
							   true, true,
							   direction, false);
		else
			trace_ion_end_cpu_access_cmo_skip(dev, dmabuf->buf_name,
							  true, true,
							  direction, false);

		mutex_unlock(&buffer->lock);
		goto out;
	}

	list_for_each_entry(a, &buffer->attachments, list) {
		int tmp = 0;

		if (!a->dma_mapped) {
			trace_ion_end_cpu_access_notmapped(a->dev,
							   dmabuf->buf_name,
							   true, true,
							   direction,
							   false);
			continue;
		}

		tmp = ion_sgl_sync_range(a->dev, a->table->sgl, a->table->nents,
					 offset, len, direction, false);

		if (!tmp) {
			trace_ion_end_cpu_access_cmo_apply(a->dev,
							   dmabuf->buf_name,
							   true, true,
							   direction, false);

		} else {
			trace_ion_end_cpu_access_cmo_skip(a->dev,
							  dmabuf->buf_name,
							  true, true, direction,
							  false);
			ret = tmp;
		}
	}
	mutex_unlock(&buffer->lock);

out:
	return ret;
}

static int ion_dma_buf_get_flags(struct dma_buf *dmabuf,
				 unsigned long *flags)
{
	struct ion_buffer *buffer = dmabuf->priv;
	*flags = buffer->flags;

	return 0;
}

static const struct dma_buf_ops dma_buf_ops = {
=======
	return ion_dma_buf_cpu_access_partial(dmabuf, dir, offset, len, true);
}

static int ion_dma_buf_end_cpu_access_partial(struct dma_buf *dmabuf,
					      enum dma_data_direction dir,
					      unsigned int offset,
					      unsigned int len)
{
	return ion_dma_buf_cpu_access_partial(dmabuf, dir, offset, len, false);
}

static int ion_dma_buf_get_flags(struct dma_buf *dmabuf, unsigned long *flags)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);

	*flags = buffer->flags;
	return 0;
}

static const struct dma_buf_ops ion_dma_buf_ops = {
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	.map_dma_buf = ion_map_dma_buf,
	.unmap_dma_buf = ion_unmap_dma_buf,
	.mmap = ion_mmap,
	.release = ion_dma_buf_release,
	.attach = ion_dma_buf_attach,
<<<<<<< HEAD
	.detach = ion_dma_buf_detatch,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
	.begin_cpu_access_umapped = ion_dma_buf_begin_cpu_access_umapped,
	.end_cpu_access_umapped = ion_dma_buf_end_cpu_access_umapped,
=======
	.detach = ion_dma_buf_detach,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	.begin_cpu_access_partial = ion_dma_buf_begin_cpu_access_partial,
	.end_cpu_access_partial = ion_dma_buf_end_cpu_access_partial,
	.map = ion_dma_buf_kmap,
	.unmap = ion_dma_buf_kunmap,
	.vmap = ion_dma_buf_vmap,
	.vunmap = ion_dma_buf_vunmap,
<<<<<<< HEAD
	.get_flags = ion_dma_buf_get_flags,
};

#ifdef CONFIG_OPLUS_ION_BOOSTPOOL
static inline unsigned int boost_pool_extra_flags(unsigned int heap_id_mask)
{
	unsigned int extra_flags = 0;

	if (heap_id_mask & (1 << ION_CAMERA_HEAP_ID)) {
		extra_flags |= ION_FLAG_CAMERA_BUFFER;
	}
	return extra_flags;
}
#endif /* CONFIG_OPLUS_ION_BOOSTPOOL */

struct dma_buf *ion_alloc_dmabuf(size_t len, unsigned int heap_id_mask,
				 unsigned int flags)
{
	struct ion_device *dev = internal_dev;
	struct ion_buffer *buffer = NULL;
	struct ion_heap *heap;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct dma_buf *dmabuf;
	char task_comm[TASK_COMM_LEN];
#ifdef CONFIG_OPLUS_ION_BOOSTPOOL
	unsigned int extra_flags = boost_pool_extra_flags(heap_id_mask);
#endif /* CONFIG_OPLUS_ION_BOOSTPOOL */
#if defined(OPLUS_FEATURE_HEALTHINFO) && defined(CONFIG_OPPO_HEALTHINFO) && defined (CONFIG_OPPO_MEM_MONITOR)
	unsigned long oppo_ionwait_start = jiffies;
#endif /*OPLUS_FEATURE_HEALTHINFO*/

	pr_debug("%s: len %zu heap_id_mask %u flags %x\n", __func__,
		 len, heap_id_mask, flags);
	/*
	 * traverse the list of heaps available in this system in priority
	 * order.  If the heap type is supported by the client, and matches the
	 * request of the caller allocate from it.  Repeat until allocate has
	 * succeeded or all heaps have been tried
	 */
	len = PAGE_ALIGN(len);

	if (!len)
		return ERR_PTR(-EINVAL);

#ifdef CONFIG_OPLUS_ION_BOOSTPOOL
	trace_ion_alloc_start(len, heap_id_mask, flags,
			      extra_flags ? "true" : "false");
#endif /* CONFIG_OPLUS_ION_BOOSTPOOL */

	down_read(&dev->lock);
	plist_for_each_entry(heap, &dev->heaps, node) {
		/* if the caller didn't specify this heap id */
		if (!((1 << heap->id) & heap_id_mask))
			continue;
#ifdef CONFIG_OPLUS_ION_BOOSTPOOL
		if (heap->id == ION_SYSTEM_HEAP_ID) {
			buffer = ion_buffer_create(heap, dev, len,
						   flags | extra_flags);
		} else
#endif
			buffer = ion_buffer_create(heap, dev, len, flags);
		if (!IS_ERR(buffer) || PTR_ERR(buffer) == -EINTR)
			break;
	}
	up_read(&dev->lock);

#ifdef CONFIG_OPLUS_ION_BOOSTPOOL
	trace_ion_alloc_end(len, heap_id_mask, flags, "");
#endif /* CONFIG_OPLUS_ION_BOOSTPOOL */
=======
	.get_flags = ion_dma_buf_get_flags
};

struct dma_buf *ion_alloc_dmabuf(size_t len, unsigned int heap_id_mask,
				 unsigned int flags)
{
	struct ion_device *idev = &ion_dev;
	struct dma_buf_export_info exp_info;
	struct ion_buffer *buffer = NULL;
	struct dma_buf *dmabuf;
	struct ion_heap *heap;

	len = PAGE_ALIGN(len);
	if (!len)
		return ERR_PTR(-EINVAL);

	plist_for_each_entry(heap, &idev->heaps, node) {
		if (BIT(heap->id) & heap_id_mask) {
			buffer = ion_buffer_create(heap, len, flags);
			if (!IS_ERR(buffer) || PTR_ERR(buffer) == -EINTR)
				break;
		}
	}
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	if (!buffer)
		return ERR_PTR(-ENODEV);

	if (IS_ERR(buffer))
		return ERR_CAST(buffer);

<<<<<<< HEAD
	get_task_comm(task_comm, current->group_leader);

	exp_info.ops = &dma_buf_ops;
	exp_info.size = buffer->size;
	exp_info.flags = O_RDWR;
	exp_info.priv = buffer;
	exp_info.exp_name = kasprintf(GFP_KERNEL, "%s-%s-%d-%s", KBUILD_MODNAME,
				      heap->name, current->tgid, task_comm);

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		_ion_buffer_destroy(buffer);
		kfree(exp_info.exp_name);
	}
#if defined(OPLUS_FEATURE_HEALTHINFO) && defined(CONFIG_OPPO_HEALTHINFO) && defined (CONFIG_OPPO_MEM_MONITOR)
	oppo_ionwait_monitor(jiffies_to_msecs(jiffies - oppo_ionwait_start));
#endif /*OPLUS_FEATURE_HEALTHINFO*/
	return dmabuf;
}

struct dma_buf *ion_alloc(size_t len, unsigned int heap_id_mask,
			  unsigned int flags)
{
	struct ion_device *dev = internal_dev;
	struct ion_heap *heap;
	bool type_valid = false;

	pr_debug("%s: len %zu heap_id_mask %u flags %x\n", __func__,
		 len, heap_id_mask, flags);
	/*
	 * traverse the list of heaps available in this system in priority
	 * order.  Check the heap type is supported.
	 */

	down_read(&dev->lock);
	plist_for_each_entry(heap, &dev->heaps, node) {
		/* if the caller didn't specify this heap id */
		if (!((1 << heap->id) & heap_id_mask))
			continue;
		if (heap->type == ION_HEAP_TYPE_SYSTEM ||
		    heap->type == (enum ion_heap_type)ION_HEAP_TYPE_HYP_CMA ||
		    heap->type ==
			(enum ion_heap_type)ION_HEAP_TYPE_SYSTEM_SECURE) {
			type_valid = true;
		} else {
			pr_warn("%s: heap type not supported, type:%d\n",
				__func__, heap->type);
		}
		break;
	}
	up_read(&dev->lock);

	if (!type_valid)
		return ERR_PTR(-EINVAL);

	return ion_alloc_dmabuf(len, heap_id_mask, flags);
}
EXPORT_SYMBOL(ion_alloc);

int ion_alloc_fd(size_t len, unsigned int heap_id_mask, unsigned int flags)
{
	int fd;
	struct dma_buf *dmabuf;

	dmabuf = ion_alloc_dmabuf(len, heap_id_mask, flags);
=======
	exp_info = (typeof(exp_info)){
		.ops = &ion_dma_buf_ops,
		.size = buffer->size,
		.flags = O_RDWR,
		.priv = &buffer->iommu_data
	};

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf))
		ion_buffer_free_work(&buffer->free);

	return dmabuf;
}

static int ion_alloc_fd(struct ion_allocation_data *a)
{
	struct dma_buf *dmabuf;
	int fd;

	dmabuf = ion_alloc_dmabuf(a->len, a->heap_id_mask, a->flags);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	return fd;
}

<<<<<<< HEAD
int ion_query_heaps(struct ion_heap_query *query)
{
	struct ion_device *dev = internal_dev;
	struct ion_heap_data __user *buffer = u64_to_user_ptr(query->heaps);
	int ret = -EINVAL, cnt = 0, max_cnt;
	struct ion_heap *heap;
	struct ion_heap_data hdata;

	memset(&hdata, 0, sizeof(hdata));

	down_read(&dev->lock);
	if (!buffer) {
		query->cnt = dev->heap_cnt;
		ret = 0;
		goto out;
	}

	if (query->cnt <= 0)
		goto out;

	max_cnt = query->cnt;

	plist_for_each_entry(heap, &dev->heaps, node) {
		strlcpy(hdata.name, heap->name, sizeof(hdata.name));
		hdata.name[sizeof(hdata.name) - 1] = '\0';
		hdata.type = heap->type;
		hdata.heap_id = heap->id;

		if (copy_to_user(&buffer[cnt], &hdata, sizeof(hdata))) {
			ret = -EFAULT;
			goto out;
		}

		cnt++;
		if (cnt >= max_cnt)
			break;
	}

	query->cnt = cnt;
	ret = 0;
out:
	up_read(&dev->lock);
	return ret;
}

static const struct file_operations ion_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = ion_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ion_ioctl,
#endif
};

static int ion_debug_heap_show(struct seq_file *s, void *unused)
{
	struct ion_heap *heap = s->private;

	if (heap->debug_show)
		heap->debug_show(heap, s, unused);

	return 0;
}

static int ion_debug_heap_open(struct inode *inode, struct file *file)
{
	return single_open(file, ion_debug_heap_show, inode->i_private);
}

static const struct file_operations debug_heap_fops = {
	.open = ion_debug_heap_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int debug_shrink_set(void *data, u64 val)
{
	struct ion_heap *heap = data;
	struct shrink_control sc;
	int objs;

	sc.gfp_mask = GFP_HIGHUSER;
	sc.nr_to_scan = val;

	if (!val) {
		objs = heap->shrinker.count_objects(&heap->shrinker, &sc);
		sc.nr_to_scan = objs;
	}

	heap->shrinker.scan_objects(&heap->shrinker, &sc);
	return 0;
}

static int debug_shrink_get(void *data, u64 *val)
{
	struct ion_heap *heap = data;
	struct shrink_control sc;
	int objs;

	sc.gfp_mask = GFP_HIGHUSER;
	sc.nr_to_scan = 0;

	objs = heap->shrinker.count_objects(&heap->shrinker, &sc);
	*val = objs;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(debug_shrink_fops, debug_shrink_get,
			debug_shrink_set, "%llu\n");

void ion_device_add_heap(struct ion_device *dev, struct ion_heap *heap)
{
	char debug_name[64], buf[256];
	int ret;

	if (!heap->ops->allocate || !heap->ops->free)
		pr_err("%s: can not add heap with invalid ops struct.\n",
		       __func__);

	spin_lock_init(&heap->free_lock);
	heap->free_list_size = 0;

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_init_deferred_free(heap);

	if ((heap->flags & ION_HEAP_FLAG_DEFER_FREE) || heap->ops->shrink) {
		ret = ion_heap_init_shrinker(heap);
		if (ret)
			pr_err("%s: Failed to register shrinker\n", __func__);
	}

	heap->dev = dev;
	down_write(&dev->lock);
	/*
	 * use negative heap->id to reverse the priority -- when traversing
	 * the list later attempt higher id numbers first
	 */
	plist_node_init(&heap->node, -heap->id);
	plist_add(&heap->node, &dev->heaps);

	if (heap->debug_show) {
		snprintf(debug_name, 64, "%s_stats", heap->name);
		if (!debugfs_create_file(debug_name, 0664, dev->debug_root,
					 heap, &debug_heap_fops))
			pr_err("Failed to create heap debugfs at %s/%s\n",
			       dentry_path(dev->debug_root, buf, 256),
			       debug_name);
	}

	if (heap->shrinker.count_objects && heap->shrinker.scan_objects) {
		snprintf(debug_name, 64, "%s_shrink", heap->name);
		if (!debugfs_create_file(debug_name, 0644, dev->debug_root,
					 heap, &debug_shrink_fops))
			pr_err("Failed to create heap debugfs at %s/%s\n",
			       dentry_path(dev->debug_root, buf, 256),
			       debug_name);
	}

	dev->heap_cnt++;
	up_write(&dev->lock);
}
EXPORT_SYMBOL(ion_device_add_heap);

static ssize_t
total_heaps_kb_show(struct kobject *kobj, struct kobj_attribute *attr,
		    char *buf)
{
	u64 size_in_bytes = atomic_long_read(&total_heap_bytes);

	return sprintf(buf, "%llu\n", div_u64(size_in_bytes, 1024));
}

static ssize_t
total_pools_kb_show(struct kobject *kobj, struct kobj_attribute *attr,
		    char *buf)
{
	u64 size_in_bytes = ion_page_pool_nr_pages() * PAGE_SIZE;

	return sprintf(buf, "%llu\n", div_u64(size_in_bytes, 1024));
}

static struct kobj_attribute total_heaps_kb_attr =
	__ATTR_RO(total_heaps_kb);

static struct kobj_attribute total_pools_kb_attr =
	__ATTR_RO(total_pools_kb);

static struct attribute *ion_device_attrs[] = {
	&total_heaps_kb_attr.attr,
	&total_pools_kb_attr.attr,
	NULL,
};

ATTRIBUTE_GROUPS(ion_device);

static int ion_init_sysfs(void)
{
	struct kobject *ion_kobj;
	int ret;

	ion_kobj = kobject_create_and_add("ion", kernel_kobj);
	if (!ion_kobj)
		return -ENOMEM;

	ret = sysfs_create_groups(ion_kobj, ion_device_groups);
	if (ret) {
		kobject_put(ion_kobj);
		return ret;
	}

	return 0;
}

struct ion_device *ion_device_create(void)
{
	struct ion_device *idev;
	int ret;

	idev = kzalloc(sizeof(*idev), GFP_KERNEL);
	if (!idev)
		return ERR_PTR(-ENOMEM);

	idev->dev.minor = MISC_DYNAMIC_MINOR;
	idev->dev.name = "ion";
	idev->dev.fops = &ion_fops;
	idev->dev.parent = NULL;
	ret = misc_register(&idev->dev);
	if (ret) {
		pr_err("ion: failed to register misc device.\n");
		goto err_reg;
	}

	ret = ion_init_sysfs();
	if (ret) {
		pr_err("ion: failed to add sysfs attributes.\n");
		goto err_sysfs;
	}

	idev->debug_root = debugfs_create_dir("ion", NULL);
	idev->buffers = RB_ROOT;
	mutex_init(&idev->buffer_lock);
	init_rwsem(&idev->lock);
	plist_head_init(&idev->heaps);
	internal_dev = idev;
	return idev;

err_sysfs:
	misc_deregister(&idev->dev);
err_reg:
	kfree(idev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(ion_device_create);
#if defined(OPLUS_FEATURE_MEMLEAK_DETECT) && defined(CONFIG_MEMLEAK_DETECT_THREAD) && defined(CONFIG_SVELTE)
/* add ion memleak detect dameon,
 * need CONFIG_DUMP_TASKS_MEM first.
 */
#include "ion_track/ion_track.c"
#endif
=======
static int ion_old_alloc_fd(struct ion_old_allocation_data *a)
{
	struct dma_buf *dmabuf;
	int fd;

	dmabuf = ion_alloc_dmabuf(a->len, a->heap_id_mask, a->flags);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	return fd;
}

void ion_add_heap(struct ion_device *idev, struct ion_heap *heap)
{
	struct ion_heap_data *hdata = &idev->heap_data[idev->heap_count];

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE) {
		heap->wq = alloc_workqueue("%s", WQ_UNBOUND | WQ_MEM_RECLAIM |
					   WQ_CPU_INTENSIVE, 0, heap->name);
		BUG_ON(!heap->wq);
	}

	if (heap->ops->shrink)
		ion_heap_init_shrinker(heap);

	plist_node_init(&heap->node, -heap->id);
	plist_add(&heap->node, &idev->heaps);

	strlcpy(hdata->name, heap->name, sizeof(hdata->name));
	hdata->type = heap->type;
	hdata->heap_id = heap->id;
	idev->heap_count++;
}

static int ion_walk_heaps(int heap_id, int type, void *data,
			  int (*f)(struct ion_heap *heap, void *data))
{
	struct ion_device *idev = &ion_dev;
	struct ion_heap *heap;
	int ret = 0;

	plist_for_each_entry(heap, &idev->heaps, node) {
		if (heap->type == type && ION_HEAP(heap->id) == heap_id) {
			ret = f(heap, data);
			break;
		}
	}

	return ret;
}

static int ion_query_heaps(struct ion_heap_query *query)
{
	struct ion_device *idev = &ion_dev;

	if (!query->cnt)
		return -EINVAL;

	if (copy_to_user(u64_to_user_ptr(query->heaps), idev->heap_data,
			 min(query->cnt, idev->heap_count) *
			 sizeof(*idev->heap_data)))
		return -EFAULT;

	return 0;
}

static long ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ion_device *idev = &ion_dev;
	union {
		struct ion_allocation_data allocation;
		struct ion_prefetch_data prefetch;
		struct ion_heap_query query;
#ifdef CONFIG_ION_LEGACY
		struct ion_fd_data fd;
		struct ion_old_allocation_data old_allocation;
		struct ion_handle_data handle;
#endif
	} data;
	int fd, *output;

	switch (cmd) {
	case ION_IOC_ALLOC:
		if (copy_from_user(&data, (void __user *)arg,
				   sizeof(struct ion_allocation_data)))
			return -EFAULT;

		fd = ion_alloc_fd(&data.allocation);
		if (fd < 0)
			return fd;

		output = &fd;
		arg += offsetof(struct ion_allocation_data, fd);
		break;
	case ION_IOC_HEAP_QUERY:
		/* The data used in ion_heap_query ends at `heaps` */
		if (copy_from_user(&data, (void __user *)arg,
				   offsetof(struct ion_heap_query, heaps) +
				   sizeof(data.query.heaps)))
			return -EFAULT;

		if (data.query.heaps)
			return ion_query_heaps(&data.query);

		output = &idev->heap_count;
		/* `arg` already points to the ion_heap_query member we want */
		break;
	case ION_IOC_PREFETCH:
		/* The data used in ion_prefetch_data begins at `regions` */
		if (copy_from_user(&data.prefetch.regions,
				   (void __user *)arg +
				   offsetof(struct ion_prefetch_data, regions),
				   sizeof(struct ion_prefetch_data) -
				   offsetof(struct ion_prefetch_data, regions)))
			return -EFAULT;

		return ion_walk_heaps(data.prefetch.heap_id,
				      ION_HEAP_TYPE_SYSTEM_SECURE,
				      &data.prefetch,
				      ion_system_secure_heap_prefetch);
	case ION_IOC_DRAIN:
		/* The data used in ion_prefetch_data begins at `regions` */
		if (copy_from_user(&data.prefetch.regions,
				   (void __user *)arg +
				   offsetof(struct ion_prefetch_data, regions),
				   sizeof(struct ion_prefetch_data) -
				   offsetof(struct ion_prefetch_data, regions)))
			return -EFAULT;

		return ion_walk_heaps(data.prefetch.heap_id,
				      ION_HEAP_TYPE_SYSTEM_SECURE,
				      &data.prefetch,
				      ion_system_secure_heap_drain);
#ifdef CONFIG_ION_LEGACY
	case ION_OLD_IOC_ALLOC:
		/* The data used in ion_old_allocation_data ends at `flags` */
		if (copy_from_user(&data, (void __user *)arg,
				   offsetof(struct ion_old_allocation_data, flags) +
				   sizeof(data.old_allocation.flags)))
			return -EFAULT;

		fd = ion_old_alloc_fd(&data.old_allocation);
		if (fd < 0)
			return fd;

		output = &fd;
		arg += offsetof(struct ion_old_allocation_data, handle);
		break;
	case ION_IOC_FREE:
		/* Only copy the `handle` field */
		if (copy_from_user(&data.handle.handle,
				   (void __user *)arg +
				   offsetof(struct ion_handle_data, handle),
				   sizeof(data.handle.handle)))
			return -EFAULT;

		/*
		 * libion passes 0 as the handle to check for this ioctl's
		 * existence and expects -ENOTTY on kernel 4.12+ as an indicator
		 * of having a new ION ABI. We want to use new ION as much as
		 * possible, so pretend that this ioctl doesn't exist when
		 * libion checks for it.
		 */
		if (!data.handle.handle)
			return -ENOTTY;

		return 0;
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
		/* Only copy the `handle` field */
		if (copy_from_user(&data.fd.handle,
				   (void __user *)arg +
				   offsetof(struct ion_fd_data, handle),
				   sizeof(data.fd.handle)))
			return -EFAULT;

		output = &data.fd.handle;
		arg += offsetof(struct ion_fd_data, fd);
		break;
	case ION_IOC_IMPORT:
		/* Only copy the `fd` field */
		if (copy_from_user(&data.fd.fd,
				   (void __user *)arg +
				   offsetof(struct ion_fd_data, fd),
				   sizeof(data.fd.fd)))
			return -EFAULT;

		output = &data.fd.fd;
		arg += offsetof(struct ion_fd_data, handle);
		break;
#endif
	default:
		return -ENOTTY;
	}

	if (copy_to_user((void __user *)arg, output, sizeof(*output)))
		return -EFAULT;

	return 0;
}

struct ion_device *ion_device_create(struct ion_heap_data *heap_data)
{
	struct ion_device *idev = &ion_dev;
	int ret;

	ret = misc_register(&idev->dev);
	if (ret)
		return ERR_PTR(ret);

	idev->heap_data = heap_data;
	return idev;
}
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
