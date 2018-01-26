#ifndef SVM_PAGE_ALLOC_H
#define SVM_PAGE_ALLOC_H

#include <include/logging.h>
#include <page_alloc.h>


/**
 * allocate 'n' physically contiguous pages of size UV_PAGE_SIZE On success
 * return the address of the first page.  If 'n' physically contiguous pages
 * cannot be satisfied, return the number of allocated physically contiguous
 * pages in '*n_allocated' and return the address of the first page. Returning
 * fewer pages than requested is legal.
 */
static inline void *alloc_uv_page(size_t n, size_t *n_allocated)
{
	return alloc_n_pages(n, n_allocated, UV_PAGE_SIZE);
}

static inline void *alloc_reserved_uv_page(void)
{
	if (!acquire_page_reservation(1)) {
		pr_error("%s:  Page Reservation failed\n", __func__);
		return NULL;
	}
	return alloc_uv_page(1, NULL);
}

/**
 * free all the physically contiguous pages starting at address 'page'. 'page'
 * has to be a address returned by alloc_svm_page(). Any other addresses are
 * considered invalid. return U_INVAL;
 */
static inline int free_uv_page(void *page)
{
	return free_pages(page, UV_PAGE_SIZE);
}

static inline int free_reserved_uv_page(void *page)
{
	int ret = free_uv_page(page);
	if (!ret)
		release_page_reservation(1);
	return ret;
}

static inline size_t get_uv_page_sz(void)
{
	return UV_PAGE_SIZE;
}
#endif
