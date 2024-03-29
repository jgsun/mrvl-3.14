/*
 * drivers/staging/android/uapi/ion.h
 *
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _UAPI_LINUX_ION_H
#define _UAPI_LINUX_ION_H

#include <linux/ioctl.h>
#include <linux/types.h>

typedef int ion_user_handle_t;

/**
 * enum ion_heap_types - list of all possible types of heaps
 * @ION_HEAP_TYPE_SYSTEM:	 memory allocated via vmalloc
 * @ION_HEAP_TYPE_SYSTEM_CONTIG: memory allocated via kmalloc
 * @ION_HEAP_TYPE_CARVEOUT:	 memory allocated from a prereserved
 * 				 carveout heap, allocations are physically
 * 				 contiguous
 * @ION_HEAP_TYPE_DMA:		 memory allocated via DMA API
 * @ION_NUM_HEAPS:		 helper for iterating over heaps, a bit mask
 * 				 is used to identify the heaps, so only 32
 * 				 total heap types are supported
 */
enum ion_heap_type {
	ION_HEAP_TYPE_SYSTEM,
	ION_HEAP_TYPE_SYSTEM_CONTIG,
	ION_HEAP_TYPE_CARVEOUT,
	ION_HEAP_TYPE_CHUNK,
	ION_HEAP_TYPE_DMA,
	ION_HEAP_TYPE_CUSTOM, /* must be last so device specific heaps always
				 are at the end of this enum */
	ION_NUM_HEAPS = 16,
};

#define ION_HEAP_SYSTEM_MASK		(1 << ION_HEAP_TYPE_SYSTEM)
#define ION_HEAP_SYSTEM_CONTIG_MASK	(1 << ION_HEAP_TYPE_SYSTEM_CONTIG)
#define ION_HEAP_CARVEOUT_MASK		(1 << ION_HEAP_TYPE_CARVEOUT)
#define ION_HEAP_TYPE_DMA_MASK		(1 << ION_HEAP_TYPE_DMA)

#define ION_NUM_HEAP_IDS		sizeof(unsigned int) * 8

/**
 * allocation flags - the lower 16 bits are used by core ion, the upper 16
 * bits are reserved for use by the heaps themselves.
 */
#define ION_FLAG_CACHED 1		/* mappings of this buffer should be
					   cached, ion will do cache
					   maintenance when the buffer is
					   mapped for dma */
#define ION_FLAG_CACHED_NEEDS_SYNC 2	/* mappings of this buffer will created
					   at mmap time, if this is set
					   caches must be managed manually */

/**
 * DOC: Ion Userspace API
 *
 * create a client by opening /dev/ion
 * most operations handled via following ioctls
 *
 */

/**
 * struct ion_allocation_data - metadata passed from userspace for allocations
 * @len:		size of the allocation
 * @align:		required alignment of the allocation
 * @heap_id_mask:	mask of heap ids to allocate from
 * @flags:		flags passed to heap
 * @handle:		pointer that will be populated with a cookie to use to 
 *			refer to this allocation
 *
 * Provided by userspace as an argument to the ioctl
 */
struct ion_allocation_data {
	size_t len;
	size_t align;
	unsigned int heap_id_mask;
	unsigned int flags;
	ion_user_handle_t handle;
};

/**
 * struct ion_fd_data - metadata passed to/from userspace for a handle/fd pair
 * @handle:	a handle
 * @fd:		a file descriptor representing that handle
 *
 * For ION_IOC_SHARE or ION_IOC_MAP userspace populates the handle field with
 * the handle returned from ion alloc, and the kernel returns the file
 * descriptor to share or map in the fd field.  For ION_IOC_IMPORT, userspace
 * provides the file descriptor and the kernel returns the handle.
 */
struct ion_fd_data {
	ion_user_handle_t handle;
	int fd;
};

/**
 * struct ion_handle_data - a handle passed to/from the kernel
 * @handle:	a handle
 */
struct ion_handle_data {
	ion_user_handle_t handle;
};

#define ION_BUFFER_UNKOWN	0
#define ION_BUFFER_DMA_VALID	(1 << 0)
#define ION_BUFFER_CPU_VALID	(1 << 1)

#define ION_BUFFER_NOTIFY_QUERY		0
#define ION_BUFFER_NOTIFY_DMA_READ	1
#define ION_BUFFER_NOTIFY_DMA_WRITE	2
#define ION_BUFFER_NOTIFY_CPU_READ	4
#define ION_BUFFER_NOTIFY_CPU_WRITE	8
#define ION_BUFFER_NOTIFY_VARIED	0xF

struct ion_notify_data {
	int fd;
	unsigned int note;
};

struct ion_sync_range_data {
	int fd;
	unsigned int offset;
	unsigned int size;
	unsigned int note;
};

/**
 * struct ion_custom_data - metadata passed to/from userspace for a custom ioctl
 * @cmd:	the custom ioctl function to call
 * @arg:	additional data to pass to the custom ioctl, typically a user
 *		pointer to a predefined structure
 *
 * This works just like the regular cmd and arg fields of an ioctl.
 */
struct ion_custom_data {
	unsigned int cmd;
	unsigned long arg;
};

/**
 * struct ion_buffer_name_data - passed to/from userspace for a name/fd pair
 * @fd:		a file descriptor of the buffer exported
 * @name:	optional name of the buffer
 */
#define ION_BUFFER_NAME_LEN	16
struct ion_buffer_name_data {
	int fd;
	char name[ION_BUFFER_NAME_LEN];
};

#define ION_BUFFER_TYPE_PHYS	(1 << 0)
#define ION_BUFFER_TYPE_DMA	(1 << 1)
/**
 * struct ion_phys_data - passed to/from userspace for a fd/addr pair
 * @fd:		a file descriptor of the buffer exported
 * @addr:	phys or dma address of the buffer
 */
struct ion_phys_data {
	int fd;
	unsigned int addr;
	unsigned int flags;
};

/**
 * struct user_map_data - passed to/from userspace for a cpu virt/phys addr and DMA addr pair
 * @start:	 a physical or virtual address of the buffer exported
 * @dma_address: dma address of the buffer
 * @flags:	 indicates the start is a physical address or virtual address, 1 for phys
 * @size:	 buffer size
 */
struct user_map_data {
	unsigned int start;
	unsigned int dma_address;
	unsigned int flags;
	unsigned int size;
};

#define PXA_USER_BUFFER_TYPE_PHYS	(1 << 0)
#define PXA_USER_BUFFER_TYPE_VIRT	(1 << 1)

/**
 * DOC: ION_PXA_IOC_DMA - get the DMA address of the buffer
 *
 * Takes an user_map_data returns the DMA address.
 */
#define ION_PXA_IOC_MAP_DMA	1
#define ION_PXA_IOC_UNMAP_DMA	2


#define ION_IOC_MAGIC		'I'

/**
 * DOC: ION_IOC_ALLOC - allocate memory
 *
 * Takes an ion_allocation_data struct and returns it with the handle field
 * populated with the opaque handle for the allocation.
 */
#define ION_IOC_ALLOC		_IOWR(ION_IOC_MAGIC, 0, \
				      struct ion_allocation_data)

/**
 * DOC: ION_IOC_FREE - free memory
 *
 * Takes an ion_handle_data struct and frees the handle.
 */
#define ION_IOC_FREE		_IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)

/**
 * DOC: ION_IOC_MAP - get a file descriptor to mmap
 *
 * Takes an ion_fd_data struct with the handle field populated with a valid
 * opaque handle.  Returns the struct with the fd field set to a file
 * descriptor open in the current address space.  This file descriptor
 * can then be used as an argument to mmap.
 */
#define ION_IOC_MAP		_IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)

/**
 * DOC: ION_IOC_SHARE - creates a file descriptor to use to share an allocation
 *
 * Takes an ion_fd_data struct with the handle field populated with a valid
 * opaque handle.  Returns the struct with the fd field set to a file
 * descriptor open in the current address space.  This file descriptor
 * can then be passed to another process.  The corresponding opaque handle can
 * be retrieved via ION_IOC_IMPORT.
 */
#define ION_IOC_SHARE		_IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

/**
 * DOC: ION_IOC_IMPORT - imports a shared file descriptor
 *
 * Takes an ion_fd_data struct with the fd field populated with a valid file
 * descriptor obtained from ION_IOC_SHARE and returns the struct with the handle
 * filed set to the corresponding opaque handle.
 */
#define ION_IOC_IMPORT		_IOWR(ION_IOC_MAGIC, 5, struct ion_fd_data)

/**
 * DOC: ION_IOC_SYNC - syncs a shared file descriptors to memory
 *
 * Deprecated in favor of using the dma_buf api's correctly (syncing
 * will happend automatically when the buffer is mapped to a device).
 * If necessary should be used after touching a cached buffer from the cpu,
 * this will make the buffer in memory coherent.
 */
#define ION_IOC_SYNC		_IOWR(ION_IOC_MAGIC, 7, struct ion_fd_data)

/**
 * DOC: ION_IOC_CUSTOM - call architecture specific ion ioctl
 *
 * Takes the argument of the architecture specific ioctl to call and
 * passes appropriate userdata for that ioctl
 */
#define ION_IOC_CUSTOM		_IOWR(ION_IOC_MAGIC, 6, struct ion_custom_data)

/**
 * DOC: ION_IOC_NAME - assign a name to the buffer
 *
 * Takes an ion_buffer_name_data with share_fd and a string name.
 */
#define ION_IOC_NAME	_IOWR(ION_IOC_MAGIC, 8, struct ion_buffer_name_data)

/**
 * DOC: ION_IOC_PHYS - get the physical address or iova of the buffer
 *
 * Takes an ion_phys_data with share_fd and returns the address.
 */
#define ION_IOC_PHYS		_IOWR(ION_IOC_MAGIC, 9, struct ion_phys_data)

/**
 * DOC: ION_IOC_NOTIFY - notify the buffer usage type of next operation
 *
 * Takes an ion_notify_data with share_fd and the notification.
 */
#define ION_IOC_NOTIFY		_IOWR(ION_IOC_MAGIC, 10, struct ion_notify_data)

/**
 * DOC: ION_IOC_SYNC_RANGE - syncs a shared file descriptors to memory by range
 *
 * Takes an ion_sync_range_data with share_fd, buffer offset and size
 */
#define ION_IOC_SYNC_RANGE _IOWR(ION_IOC_MAGIC, 11, struct ion_sync_range_data)

#endif /* _UAPI_LINUX_ION_H */
