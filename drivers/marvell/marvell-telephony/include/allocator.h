/*
 * allocator interface
 *
 * This software program is licensed subject to the GNU General Public License
 * (GPL).Version 2,June 1991, available at http://www.fsf.org/copyleft/gpl.html

 * (C) Copyright 2015 Marvell International Ltd.
 * All Rights Reserved
 */
#ifndef TEL_ALLOCATOR_H_
#define TEL_ALLOCATOR_H_

struct tmem_allocator;
struct tmem_allocator *tmem_create(void *base, size_t size,
	size_t min_align);
void *tmem_alloc(struct tmem_allocator *allocator, size_t size, int flag);
void tmem_free(struct tmem_allocator *allocator, void *ptr, size_t size);
void tmem_free_all(struct tmem_allocator *allocator);
void tmem_destroy(struct tmem_allocator *allocator);

#endif /* TEL_ALLOCATOR_H_ */
