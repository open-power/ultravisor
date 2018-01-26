#include <svm/svm-pagemap.h>
#include <logging.h>
#include <errno.h>

/*
 * Create/initialize the svm_pagemap tree.
 */
void svm_pagemap_init(svm_pagemap_t *svm_pagemap)
{
	uintmap_init(svm_pagemap);
}

/*
 * Store the given @pointer at @index. Return 0 on success or if
 * its already there. Return -ENOMEM otherwise.
 */
int svm_pagemap_store(svm_pagemap_t *svm_pagemap, u64 index,
					struct svm_page_info *pointer)
{
	if (uintmap_add(svm_pagemap, index, pointer) || errno == EEXIST)
		return 0;

	return -ENOMEM;
}

/*
 * Return the pointer stored at @index (or NULL if nothing was stored
 * there).
 */
struct svm_page_info *svm_pagemap_load(svm_pagemap_t *svm_pagemap, u64 index)
{
	return uintmap_get(svm_pagemap, index);
}

/*
 * Clear/destroy the svm_pagemap tree.
 */
void svm_pagemap_clear(svm_pagemap_t *svm_pagemap)
{
	uintmap_clear(svm_pagemap);
}
