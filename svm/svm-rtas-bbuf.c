// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 IBM Corp.
 */

#undef DEBUG
#define pr_fmt(fmt) "SVM-RTAS-BBUF: " fmt

#include <ccan/bitops/bitops.h>
#include <compiler.h>
#include <context.h>
#include <errno.h>
#include <exceptions.h>
#include <inttypes.h>
#include <logging.h>
#include <stack.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <svm_host.h>
#include <svm/svm-internal.h>
#include <svm/svm-rtas-bbuf.h>
#include <unistd.h>
#include <utils.h>

#undef DEBUG
#ifdef DEBUG
#define svm_rtas_dprintf(fmt...)                                               \
	do {                                                                   \
		printf(fmt);                                                   \
	} while (0)
#else
#define svm_rtas_dprintf(fmt...)                                               \
	do {                                                                   \
	} while (0)
#endif

/**
 * @brief Copy contents between gpa buffers.
 *
 * @param mm a memory context.
 * @param dest Gpa to copy to.
 * @param src Gpa to copy from.
 * @param length Length of copy.
 */

size_t svm_rtas_bbuf_memcpy(struct mm_struct *mm, gpa_t dest, gpa_t src,
			    size_t length)
{
	size_t ret = 0;
	hpa_t dest_hpa;
	hpa_t src_hpa;

	assert(length <= RTAS_BUF_BBUF_SZ);

	while (length) {
		uint32_t chunk;

		dest_hpa = (hpa_t)gpa_to_addr(mm, dest, NULL);
		if (!dest_hpa)
			return ret;
		src_hpa = (hpa_t)gpa_to_addr(mm, src, NULL);
		if (!src_hpa)
			return ret;
		chunk = (RTAS_BUF_BBUF_SZ - (src % RTAS_BUF_BBUF_SZ));

		if (chunk > length) {
			chunk = length;
		}

		/* Avoid crossing page boundaries */
		chunk = min(chunk,
			    (uint32_t)(PAGE_SIZE - (dest_hpa & ~PAGE_MASK)));
		chunk = min(chunk,
			    (uint32_t)(PAGE_SIZE - (src_hpa & ~PAGE_MASK)));

		svm_rtas_dprintf("%s: dest_hpa 0x%016" PRIx64 ","
				 " src_hpa 0x%016" PRIx64 ","
				 " chunk 0x%x\n",
				 __func__, dest_hpa, src_hpa, chunk);

		memcpy((void *)NO_RMOR(dest_hpa), (void *)NO_RMOR(src_hpa),
		       chunk);

		dest += chunk;
		src += chunk;
		length -= chunk;
		ret += chunk;
	}

	return ret;
}

gpa_t svm_rtas_bbuf_alloc(struct mm_struct *mm, struct svm_rtas *rtas)
{
	uint32_t free_bit;
	gpa_t bbuf_gpa = (gpa_t) NULL;
	hpa_t bbuf_hpa = (hpa_t) NULL;

	_Static_assert(8 * sizeof(rtas->bbuf_alloc_map) >= MAX_BBUF_CNT,
		       "Invalid number of RTAS buffers");

	assert(rtas->rtas_buf_bbuf);
	if (!rtas->rtas_buf_bbuf)
		return (gpa_t) NULL;

	lock(&(rtas->rtas_bitmap_lock));

	free_bit = bitops_lc64(rtas->bbuf_alloc_map);
	svm_rtas_dprintf("%s: free_bit %u\n", __func__, free_bit);

	if (free_bit >= WARN_BBUF_USE_CNT)
		pr_warn("%s: Using %u RTAS buffers (max %lu)\n", __func__,
			free_bit, MAX_BBUF_CNT);

	if (free_bit >= MAX_BBUF_CNT)
		goto unlock_exit;

	bbuf_gpa = rtas->rtas_buf_bbuf + (RTAS_BUF_BBUF_SZ * free_bit);

	bbuf_hpa = (hpa_t)gpa_to_addr(mm, bbuf_gpa, NULL);
	if (bbuf_hpa)
		rtas->bbuf_alloc_map |= (1 << free_bit);
	else
		bbuf_gpa = (gpa_t) NULL;

unlock_exit:
	unlock(&(rtas->rtas_bitmap_lock));

	if (bbuf_hpa)
		memset((void *)NO_RMOR(bbuf_hpa), 0, RTAS_BUF_BBUF_SZ);

	return bbuf_gpa;
}

void svm_rtas_bbuf_free(struct svm_rtas *rtas, gpa_t bbuf_addr)
{
	uint32_t used_bit;

	lock(&(rtas->rtas_bitmap_lock));

	used_bit = (bbuf_addr - rtas->rtas_buf_bbuf) / RTAS_BUF_BBUF_SZ;

	svm_rtas_dprintf("%s: used_bit %u\n", __func__, used_bit);

	rtas->bbuf_alloc_map &= ~(1 << used_bit);

	unlock(&(rtas->rtas_bitmap_lock));
}

void svm_rtas_bbuf_init(struct svm_rtas *rtas)
{
	init_lock(&rtas->rtas_bitmap_lock);
}
