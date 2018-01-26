// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Non Dump alloc
 *
 * Copyright 2019 IBM Corp.
 *
 */

#include <include/mem_region-malloc.h>

/*
 * @todo: allocator that allocates and frees memory
 * from a non-dumpabale area. This is needed to save sensitive
 * information which will not be able to anyone who dumps the
 * ultravisor memory.
 */
static inline void free_non_dumpable(void *ptr)
{
	free(ptr);
}
static inline void *malloc_non_dumpable(size_t size)
{
	return malloc(size);
}
