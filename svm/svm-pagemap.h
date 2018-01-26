#include <config.h>
#include <ccan/intmap/intmap.h>

#ifndef SVM_PAGEMAP_H
#define SVM_PAGEMAP_H

struct svm_page_info {
	uint64_t flags;
};

/*
 * svm_pagemap_t is essentially an array of svm_page_info pointers but
 * very space efficient since we expect the array to be very sparse.
 * Like with an array, svm_pagemap_t allows following operations:
 *
 * 	- Initialize the array
 * 	- Store a value at an index
 * 	- Load (retrieve) the value stored at an index.
 *
 * Unlike an array:
 * 	- Store operation allocates memory if necessary, and can fail.
 * 	- Array must be "cleared" when done to free resources.
 *
 * NOTE: Locking should be provided by the higher level interfaces!
 *
 * NOTE: svm_pagemap_t could very well use a void* and we could call it
 * 	 uv_intmap_t. But a specific type allows better error checking.
 * 	 If we need to create a map for another type, its just a few
 * 	 lines of code to duplicate.
 */
typedef UINTMAP(struct svm_page_info *) svm_pagemap_t;

extern void svm_pagemap_init(svm_pagemap_t *svm_pagemap);

extern int svm_pagemap_store(svm_pagemap_t *svm_pagemap, u64 index,
					struct svm_page_info *pginfo);

extern struct svm_page_info *svm_pagemap_load(svm_pagemap_t *svm_pagemap,
					uint64_t index);

extern void svm_pagemap_clear(svm_pagemap_t *svm_pagemap);

#ifdef SVM_PAGEMAP_TEST
extern void svm_pagemap_test(void);
#else
#define svm_pagemap_test(void)  do { } while (0)
#endif

#define svm_pagemap_iterate(svm_pagemap, fn, handle) \
	uintmap_iterate(svm_pagemap, fn, handle)
#define svm_pagemap_del(svm_pagemap, index) uintmap_del(svm_pagemap, index)

#define svm_pagemap_iterate_safe(svm_pagemap, fn, handle)		\
	({								\
		u64  next=0;						\
		bool  ret=true;						\
		while ((uintmap_after(svm_pagemap, &next))) {		\
			ret = fn(next,					\
				 svm_pagemap_load(svm_pagemap, next),	\
				 handle);				\
			if (!ret)					\
				break;					\
		}							\
		ret;							\
	})

#endif /* SVM_PAGEMAP_H */
