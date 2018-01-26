// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp.  */

/* Wrappers for malloc, et. al. */
#include <mem_region.h>
#include <lock.h>
#include <string.h>
#include <mem_region-malloc.h>

#define DEFAULT_ALIGN __alignof__(long)

void *__memalign(size_t blocksize, size_t bytes, const char *location)
{
	void *p;

	lock(&ultra_heap.free_list_lock);
	p = mem_alloc(&ultra_heap, bytes, blocksize, location);
	unlock(&ultra_heap.free_list_lock);

	return p;
}

void *__malloc(size_t bytes, const char *location)
{
	return __memalign(DEFAULT_ALIGN, bytes, location);
}

void __free(void *p, const char *location)
{
	lock(&ultra_heap.free_list_lock);
	mem_free(&ultra_heap, p, location);
	unlock(&ultra_heap.free_list_lock);
}

void *__realloc(void *ptr, size_t size, const char *location)
{
	void *newptr;

	/* Two classic malloc corner cases. */
	if (!size) {
		__free(ptr, location);
		return NULL;
	}
	if (!ptr)
		return __malloc(size, location);

	lock(&ultra_heap.free_list_lock);
	if (mem_resize(&ultra_heap, ptr, size, location)) {
		newptr = ptr;
	} else {
		newptr = mem_alloc(&ultra_heap, size, DEFAULT_ALIGN,
				   location);
		if (newptr) {
			size_t copy = mem_allocated_size(ptr);
			if (copy > size)
				copy = size;
			memcpy(newptr, ptr, copy);
			mem_free(&ultra_heap, ptr, location);
		}
	}
	unlock(&ultra_heap.free_list_lock);
	return newptr;
}

void *__zalloc(size_t bytes, const char *location)
{
	void *p = __malloc(bytes, location);

	if (p)
		memset(p, 0, bytes);
	return p;
}
