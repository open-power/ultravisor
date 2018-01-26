// SPDX-License-Identifier: GPL-2.0
#include <stdlib.h>
#include <ccan/list/list.h>

#ifdef USERSPACE
#include "stubs.h"
#endif

#ifndef PAGE_ALLOC_H
#define PAGE_ALLOC_H

#define MAX_ORDER 10

#define MB		(1UL << 20)
#define UV_PAGE_SHIFT	21
#define UV_PAGE_SIZE	(1UL << UV_PAGE_SHIFT)
#define UV_PAGE_MASK	(~(UV_PAGE_SIZE-1))
#define UV_PAGE_OFFSET_MASK	(UV_PAGE_SIZE-1)

#define U_INVAL 1

/*
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	const typeof(x) _x = (x);	\
	const typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

/* Bit vectors */

#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))

#define change_bit(bit, ptr) __change_bit(bit, ptr)

static inline void __change_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p ^= mask;
}

static inline int __test_and_change_bit(int nr,
					volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old = *p;

	*p = old ^ mask;
	return (old & mask) != 0;
}

/**
 * test_bit - Determine whether a bit is set
 * @nr: bit number to test
 * @addr: Address to start counting from
 */
static inline int test_bit(int nr, const volatile unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

/*
 * Multiple processes may "see" the same page. E.g. for untouched
 * mappings of /dev/null, all processes see the same page full of
 * zeroes, and text pages of executables and shared libraries have
 * only one copy in memory, at most, normally.
 *
 * For the non-reserved pages, page->count denotes a reference count.
 *   page->count == 0 means the page is free.
 *   page->count == 1 means the page is used for exactly one purpose
 *   (e.g. a private data page of one process).
 *
 * A page may be used for kmalloc() or anyone else who does a
 * __get_free_page(). In this case the page->count is at least 1, and
 * all other fields are unused but should be 0 or NULL. The
 * management of this page is the responsibility of the one who uses
 * it.
 */

#define put_page_testzero(p) 	(--(p)->count == 0)
#define set_page_count(p,v) 	((p)->count = (v))

typedef struct page {
	union {
		unsigned int order;		/* When allocated: order */
		struct list_node list;		/* When free: free list */
	};
	unsigned long count;			/* Usage count */
} mem_map_t;

extern mem_map_t * mem_map;

int _free_pages(void *p);

#ifndef __TEST__
bool __make_reservation(size_t n);
void __release_reservation(size_t n);
#else
static inline bool  __make_reservation(size_t UNUSED(n))
{
	return true;
}
static void __release_reservation(size_t UNUSED(n))
{
}

#endif

void *__alloc_n_pages(size_t n, size_t *n_alloc);
static inline void *alloc_n_pages(size_t n, size_t *n_alloc, size_t page_size)
{
	assert(page_size == UV_PAGE_SIZE);
	if (n == 0)
		return NULL;

	return __alloc_n_pages(n, n_alloc);
}

static inline int free_pages(void *p, size_t page_size)
{
	assert(page_size == UV_PAGE_SIZE);
	return _free_pages(p);
}

int init_numa(u32 n);
void add_numa_node(int32_t node_id, void *start, size_t totalpages);

static inline bool acquire_page_reservation(size_t n)
{
	return __make_reservation(n);
}
static inline void release_page_reservation(size_t n)
{
	__release_reservation(n);
}

int32_t get_numa_node_id_of_page(void *p);
#endif
