/*
 * allocator interface
 *
 * This software program is licensed subject to the GNU General Public License
 * (GPL).Version 2,June 1991, available at http://www.fsf.org/copyleft/gpl.html

 * (C) Copyright 2015 Marvell International Ltd.
 * All Rights Reserved
 */
#include <linux/kernel.h>
#include <linux/genalloc.h>
#include <linux/bug.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include "allocator.h"

struct tmem_allocator {
	struct gen_pool *pool;
	unsigned long addr;
	unsigned long addr_aligned;
	size_t size;
	size_t min_align;
};

struct tmem_allocator *tmem_create(void *base, size_t size,
	size_t min_align)
{
	struct tmem_allocator *allocator;
	unsigned long addr = (unsigned long)base;
	unsigned long addr_aligned;

	BUG_ON(!is_power_of_2(min_align));

	allocator = kzalloc(sizeof(*allocator), GFP_KERNEL);
	if (!allocator) {
		pr_err("%s: create allocator failed\n", __func__);
		return NULL;
	}

	addr_aligned = roundup(addr, min_align);

	allocator->addr = addr;
	allocator->addr_aligned = addr_aligned;
	allocator->size = size - (addr_aligned - addr);
	allocator->min_align = min_align;

	allocator->pool = gen_pool_create(ilog2(min_align), -1);

	if (!allocator->pool) {
		pr_err("%s: create pool failed\n", __func__);
		kfree(allocator);
		return NULL;
	}

	if (gen_pool_add(allocator->pool,
			addr_aligned, allocator->size, -1) < 0) {
		pr_err("%s: add memory to pool failed\n", __func__);
		gen_pool_destroy(allocator->pool);
		kfree(allocator);
		return NULL;
	}

	return allocator;
}
EXPORT_SYMBOL(tmem_create);

void *tmem_alloc(struct tmem_allocator *allocator, size_t size, int flag)
{
	(void)flag;
	return (void *)gen_pool_alloc(allocator->pool, size);
}
EXPORT_SYMBOL(tmem_alloc);

void tmem_free(struct tmem_allocator *allocator, void *ptr, size_t size)
{
	gen_pool_free(allocator->pool, (unsigned long)ptr, size);
}
EXPORT_SYMBOL(tmem_free);

void tmem_free_all(struct tmem_allocator *allocator)
{
	/*
	 * a workaround to free all the memory
	 * 1. allocate all the remained memory
	 * 2. free it in one statement
	 */
	while (gen_pool_alloc(allocator->pool,
				allocator->min_align))
		;

	gen_pool_free(allocator->pool,
		allocator->addr_aligned, allocator->size);
}
EXPORT_SYMBOL(tmem_free_all);

void tmem_destroy(struct tmem_allocator *allocator)
{
	gen_pool_destroy(allocator->pool);
	kfree(allocator);
}
EXPORT_SYMBOL(tmem_destroy);
