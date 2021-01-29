// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019-2021 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
<<<<<<< HEAD
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include <linux/dma-buf.h>
#include <linux/idr.h>
#include <linux/sched/task.h>
#include <linux/bitops.h>
#include <linux/msm_dma_iommu_mapping.h>
#define CREATE_TRACE_POINTS
#include <trace/events/ion.h>
#include <soc/qcom/secure_buffer.h>

#include "ion.h"
=======
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)
#include "ion_secure_util.h"
#include "ion_system_secure_heap.h"

<<<<<<< HEAD
static struct ion_device *internal_dev;
=======
struct ion_dma_buf_attachment {
	struct ion_dma_buf_attachment *next;
	struct device *dev;
	struct sg_table table;
	struct list_head list;
	struct rw_semaphore map_rwsem;
	bool dma_mapped;
};
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)

static long ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static const struct file_operations ion_fops = {
	.unlocked_ioctl = ion_ioctl,
	.compat_ioctl = ion_ioctl
};

static struct ion_device ion_dev = {
	.heaps = PLIST_HEAD_INIT(ion_dev.heaps),
	.heap_rwsem = __RWSEM_INITIALIZER(ion_dev.heap_rwsem),
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

<<<<<<< HEAD
	buffer->heap = heap;
	buffer->flags = flags;
=======
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
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)

	ret = heap->ops->allocate(heap, buffer, len, flags);
	if (ret) {
		if (ret == -EINTR || !(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto free_buffer;

<<<<<<< HEAD
	if (buffer->sg_table == NULL) {
		WARN_ONCE(1, "This heap needs to set the sgtable");
		ret = -EINVAL;
		goto err1;
	}

	table = buffer->sg_table;
	buffer->dev = dev;
	buffer->size = len;

	buffer->dev = dev;
	buffer->size = len;
	INIT_LIST_HEAD(&buffer->attachments);
	INIT_LIST_HEAD(&buffer->vmas);
	mutex_init(&buffer->lock);

	buffer->pid = task_pid_nr(current->group_leader);
	buffer->client_pids[buffer->ref_cnt++] = buffer->pid;

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

	mutex_lock(&dev->buffer_lock);
	ion_buffer_add(dev, buffer);
	mutex_unlock(&dev->buffer_lock);
	atomic_long_add(len, &heap->total_allocated);
=======
		drain_workqueue(heap->wq);
		if (heap->ops->allocate(heap, buffer, len, flags))
			goto free_buffer;
	}

>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)
	return buffer;

free_buffer:
	kfree(buffer);
	return ERR_PTR(ret);
}

<<<<<<< HEAD
void ion_buffer_destroy(struct ion_buffer *buffer)
{
	if (buffer->kmap_cnt > 0) {
		pr_warn_ratelimited("ION client likely missing a call to dma_buf_kunmap or dma_buf_vunmap\n");
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
	}
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
	if (WARN_ONCE(vaddr == NULL,
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
	struct list_head list;
	bool dma_mapped;
};

static int ion_dma_buf_attach(struct dma_buf *dmabuf, struct device *dev,
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
	a->dev = dev;
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
=======
static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction dir)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a = attachment->priv;
	int count, map_attrs = attachment->dma_map_attrs;
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)

	if (!(buffer->flags & ION_FLAG_CACHED) ||
	    !hlos_accessible_buffer(buffer))
		map_attrs |= DMA_ATTR_SKIP_CPU_SYNC;

	down_write(&a->map_rwsem);
	if (map_attrs & DMA_ATTR_DELAYED_UNMAP)
		count = msm_dma_map_sg_attrs(attachment->dev, a->table.sgl,
					     a->table.nents, dir, dmabuf,
					     map_attrs);
	else
		count = dma_map_sg_attrs(attachment->dev, a->table.sgl,
					 a->table.nents, dir, map_attrs);
	if (count)
		a->dma_mapped = true;
	up_write(&a->map_rwsem);

	return count ? &a->table : ERR_PTR(-ENOMEM);
}

static void ion_unmap_dma_buf(struct dma_buf_attachment *attachment,
			      struct sg_table *table,
			      enum dma_data_direction dir)
{
<<<<<<< HEAD
	int map_attrs;
	struct ion_buffer *buffer = attachment->dmabuf->priv;
=======
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)
	struct ion_dma_buf_attachment *a = attachment->priv;
	int map_attrs = attachment->dma_map_attrs;

	if (!(buffer->flags & ION_FLAG_CACHED) ||
	    !hlos_accessible_buffer(buffer))
		map_attrs |= DMA_ATTR_SKIP_CPU_SYNC;

	down_write(&a->map_rwsem);
	if (map_attrs & DMA_ATTR_DELAYED_UNMAP)
		msm_dma_unmap_sg_attrs(attachment->dev, table->sgl,
				       table->nents, dir, dmabuf, map_attrs);
	else
		dma_unmap_sg_attrs(attachment->dev, table->sgl, table->nents,
				   dir, map_attrs);
	a->dma_mapped = false;
	up_write(&a->map_rwsem);
}

<<<<<<< HEAD
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


static int ion_dma_buf_import_buf_add_by_moto(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = dmabuf->priv;
	int i;
	int found_pid = 0;
	pid_t task_pid = task_pid_nr(current->group_leader);

	mutex_lock(&buffer->lock);
	for (i = 0; i < buffer->ref_cnt && i < MAX_CLIENTS_NUM; i++) {
		if (buffer->client_pids[i] == task_pid) {
			found_pid = 1;
			break;
		}
	}
	if (!found_pid && buffer->ref_cnt < MAX_CLIENTS_NUM)
		buffer->client_pids[buffer->ref_cnt++] = task_pid;

	mutex_unlock(&buffer->lock);

	return 0;
}
static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = dmabuf->priv;
	int ret = 0;
=======
static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)

	if (!buffer->heap->ops->map_user)
		return -EINVAL;

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

	ion_dma_buf_import_buf_add_by_moto(dmabuf);

	if (ret)
		pr_err("%s: failure mapping buffer to userspace\n",
		       __func__);

	return ret;
=======
	return heap->ops->map_user(heap, buffer, vma);
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)
}

static void ion_dma_buf_release(struct dma_buf *dmabuf)
{
<<<<<<< HEAD
	struct ion_buffer *buffer = dmabuf->priv;
=======
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		queue_work(heap->wq, &buffer->free);
	else
		ion_buffer_free_work(&buffer->free);
}

static void *ion_dma_buf_vmap(struct dma_buf *dmabuf)
{
<<<<<<< HEAD
	struct ion_buffer *buffer = dmabuf->priv;
	void *vaddr = ERR_PTR(-EINVAL);
=======
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;
	void *vaddr;
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)

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

	return vaddr;
}

static void ion_dma_buf_vunmap(struct dma_buf *dmabuf, void *vaddr)
{
<<<<<<< HEAD
	struct ion_buffer *buffer = dmabuf->priv;
=======
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_heap *heap = buffer->heap;
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)

	mutex_lock(&buffer->kmap_lock);
	if (!--buffer->kmap_refcount)
		heap->ops->unmap_kernel(heap, buffer);
	mutex_unlock(&buffer->kmap_lock);
}

static void *ion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	void *vaddr;

	vaddr = ion_dma_buf_vmap(dmabuf);
	if (IS_ERR(vaddr))
		return vaddr;

	return vaddr + offset * PAGE_SIZE;
}

static void ion_dma_buf_kunmap(struct dma_buf *dmabuf, unsigned long offset,
			       void *ptr)
{
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

static int ion_dma_buf_attach(struct dma_buf *dmabuf, struct device *dev,
			      struct dma_buf_attachment *attachment)
{
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
	struct ion_dma_buf_attachment *a;

	spin_lock(&buffer->freelist_lock);
	list_for_each_entry(a, &buffer->map_freelist, list) {
		if (a->dev == dev) {
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

	a->dev = dev;
	a->dma_mapped = false;
	a->map_rwsem = (struct rw_semaphore)__RWSEM_INITIALIZER(a->map_rwsem);
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
	struct ion_buffer *buffer = dmabuf->priv;
	struct ion_dma_buf_attachment *a;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (down_read_trylock(&a->map_rwsem)) {
			if (a->dma_mapped)
				dma_sync_sg_for_cpu(a->dev, a->table.sgl,
						    a->table.nents, dir);
			up_read(&a->map_rwsem);
		}
	}

	return 0;
}

static int ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf,
				      enum dma_data_direction dir)
{
	struct ion_buffer *buffer = dmabuf->priv;
	struct ion_dma_buf_attachment *a;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (down_read_trylock(&a->map_rwsem)) {
			if (a->dma_mapped)
				dma_sync_sg_for_device(a->dev, a->table.sgl,
						       a->table.nents, dir);
			up_read(&a->map_rwsem);
		}
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
			sg_dma_addr += sg->length;
			continue;
		}

		sg_left = total - offset;
		sg_offset = sg->length - sg_left;
		size = min(len, sg_left);
		if (for_cpu)
			dma_sync_single_range_for_cpu(dev, sg_dma_addr,
						      sg_offset, size, dir);
		else
			dma_sync_single_range_for_device(dev, sg_dma_addr,
							 sg_offset, size, dir);
		len -= size;
		if (!len)
			break;

		offset += size;
		sg_dma_addr += sg->length;
	}
}

static int ion_dma_buf_begin_cpu_access_partial(struct dma_buf *dmabuf,
						enum dma_data_direction dir,
						unsigned int offset,
						unsigned int len)
{
	struct ion_buffer *buffer = dmabuf->priv;
	struct ion_dma_buf_attachment *a;
	int ret = 0;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (a->table.nents > 1 && sg_next(a->table.sgl)->dma_length) {
			ret = -EINVAL;
			continue;
		}

		if (down_read_trylock(&a->map_rwsem)) {
			if (a->dma_mapped)
				ion_sgl_sync_range(a->dev, a->table.sgl,
						   a->table.nents, offset, len,
						   dir, true);
			up_read(&a->map_rwsem);
		}
	}

	return ret;
}

static int ion_dma_buf_end_cpu_access_partial(struct dma_buf *dmabuf,
					      enum dma_data_direction dir,
					      unsigned int offset,
					      unsigned int len)
{
	struct ion_buffer *buffer = dmabuf->priv;
	struct ion_dma_buf_attachment *a;
	int ret = 0;

	if (!hlos_accessible_buffer(buffer))
		return -EPERM;

	if (!(buffer->flags & ION_FLAG_CACHED))
		return 0;

	for (a = buffer->attachments; a; a = a->next) {
		if (a->table.nents > 1 && sg_next(a->table.sgl)->dma_length) {
			ret = -EINVAL;
			continue;
		}

		if (down_read_trylock(&a->map_rwsem)) {
			if (a->dma_mapped)
				ion_sgl_sync_range(a->dev, a->table.sgl,
						   a->table.nents, offset, len,
						   dir, false);
			up_read(&a->map_rwsem);
		}
	}

	return ret;
}

static int ion_dma_buf_get_flags(struct dma_buf *dmabuf, unsigned long *flags)
{
<<<<<<< HEAD
	struct ion_buffer *buffer = dmabuf->priv;
	*flags = buffer->flags;
=======
	struct ion_buffer *buffer = container_of(dmabuf->priv, typeof(*buffer),
						 iommu_data);
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)

	*flags = buffer->flags;
	return 0;
}

static const struct dma_buf_ops ion_dma_buf_ops = {
	.map_dma_buf = ion_map_dma_buf,
	.unmap_dma_buf = ion_unmap_dma_buf,
	.mmap = ion_mmap,
	.release = ion_dma_buf_release,
	.attach = ion_dma_buf_attach,
	.detach = ion_dma_buf_detach,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
	.begin_cpu_access_partial = ion_dma_buf_begin_cpu_access_partial,
	.end_cpu_access_partial = ion_dma_buf_end_cpu_access_partial,
	.map_atomic = ion_dma_buf_kmap,
	.unmap_atomic = ion_dma_buf_kunmap,
	.map = ion_dma_buf_kmap,
	.unmap = ion_dma_buf_kunmap,
	.vmap = ion_dma_buf_vmap,
	.vunmap = ion_dma_buf_vunmap,
<<<<<<< HEAD
	.get_flags = ion_dma_buf_get_flags,
	.import_buf_add_by_moto = ion_dma_buf_import_buf_add_by_moto,
=======
	.get_flags = ion_dma_buf_get_flags
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)
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

	down_read(&idev->heap_rwsem);
	plist_for_each_entry(heap, &idev->heaps, node) {
		if (BIT(heap->id) & heap_id_mask) {
			buffer = ion_buffer_create(heap, len, flags);
			if (!IS_ERR(buffer) || PTR_ERR(buffer) == -EINTR)
				break;
		}
	}
	up_read(&idev->heap_rwsem);

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
=======
	exp_info = (typeof(exp_info)){
		.ops = &ion_dma_buf_ops,
		.size = buffer->size,
		.flags = O_RDWR,
		.priv = &buffer->iommu_data
	};
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)

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
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	return fd;
}

void ion_device_add_heap(struct ion_device *idev, struct ion_heap *heap)
{
	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE) {
		heap->wq = alloc_workqueue("%s", WQ_UNBOUND,
					   WQ_UNBOUND_MAX_ACTIVE, heap->name);
		BUG_ON(!heap->wq);
	}

	if (heap->ops->shrink)
		ion_heap_init_shrinker(heap);

	plist_node_init(&heap->node, -heap->id);

	down_write(&idev->heap_rwsem);
	plist_add(&heap->node, &idev->heaps);
	up_write(&idev->heap_rwsem);
}

static int ion_walk_heaps(int heap_id, int type, void *data,
			  int (*f)(struct ion_heap *heap, void *data))
{
	struct ion_device *idev = &ion_dev;
	struct ion_heap *heap;
	int ret = 0;

	down_write(&idev->heap_rwsem);
	plist_for_each_entry(heap, &idev->heaps, node) {
		if (heap->type == type && ION_HEAP(heap->id) == heap_id) {
			ret = f(heap, data);
			break;
		}
	}
	up_write(&idev->heap_rwsem);

<<<<<<< HEAD
	dev->heap_cnt++;
	up_write(&dev->lock);
}
EXPORT_SYMBOL(ion_device_add_heap);

static int ion_debug_allbufs_show(struct seq_file *s, void *unused)
{
	struct ion_device *dev = s->private;
	struct rb_node *n;
	int i;

	seq_printf(s, "%16.s %16.s %12.s %12.s %20.s    %s\n", "heap",
		"buffer", "size", "ref cnt", "allocator", "references");

	down_read(&dev->lock);
	mutex_lock(&dev->buffer_lock);
	for (n = rb_first(&dev->buffers); n; n = rb_next(n)) {
		struct ion_buffer *buf = rb_entry(n, struct ion_buffer, node);
		int buf_refcount = buf->ref_cnt;
		seq_printf(s, "%16.s %16pK %12.x %12.d %20.d    %s",
			buf->heap->name, buf, (int)buf->size,
			buf_refcount, buf->pid, "");

		for(i = 0; i < buf->ref_cnt && i < MAX_CLIENTS_NUM; i++)
			seq_printf(s, "%u, ", buf->client_pids[i]);

		seq_puts(s, "\n");
	}
	mutex_unlock(&dev->buffer_lock);
	up_read(&dev->lock);
	return 0;
}

static int ion_debug_allbufs_open(struct inode *inode, struct file *file)
{
	return single_open(file, ion_debug_allbufs_show, inode->i_private);
}

static const struct file_operations debug_allbufs_fops = {
	.open = ion_debug_allbufs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
=======
	return ret;
}

static long ion_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	union {
		struct ion_allocation_data allocation;
		struct ion_prefetch_data prefetch_data;
	} data;
	int fd, *output;

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	switch (cmd) {
	case ION_IOC_ALLOC:
		fd = ion_alloc_fd(&data.allocation);
		if (fd < 0)
			return fd;

		output = &fd;
		arg += offsetof(struct ion_allocation_data, fd);
		break;
	case ION_IOC_PREFETCH:
		return ion_walk_heaps(data.prefetch_data.heap_id,
				      ION_HEAP_TYPE_SYSTEM_SECURE,
				      &data.prefetch_data,
				      ion_system_secure_heap_prefetch);
	case ION_IOC_DRAIN:
		return ion_walk_heaps(data.prefetch_data.heap_id,
				      ION_HEAP_TYPE_SYSTEM_SECURE,
				      &data.prefetch_data,
				      ion_system_secure_heap_drain);
	default:
		return -ENOTTY;
	}

	if (copy_to_user((void __user *)arg, output, sizeof(*output)))
		return -EFAULT;
>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)


struct ion_device *ion_device_create(void)
{
	struct ion_device *idev = &ion_dev;
	int ret;

	ret = misc_register(&idev->dev);
<<<<<<< HEAD
	if (ret) {
		pr_err("ion: failed to register misc device.\n");
		kfree(idev);
		return ERR_PTR(ret);
	}

	idev->debug_root = debugfs_create_dir("ion", NULL);
	if (!idev->debug_root) {
		pr_err("ion: failed to create debugfs root directory.\n");
		goto debugfs_done;
	}

debugfs_done:

	idev->buffers = RB_ROOT;
	mutex_init(&idev->buffer_lock);
	init_rwsem(&idev->lock);
	plist_head_init(&idev->heaps);
	internal_dev = idev;
	debugfs_create_file("check_all_bufs", 0664, idev->debug_root, idev,
		&debug_allbufs_fops);
=======
	if (ret)
		return ERR_PTR(ret);

>>>>>>> e0e9347ad336f (ion: Rewrite to improve clarity and performance)
	return idev;
}
