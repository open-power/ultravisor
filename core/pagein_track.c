// SPDX-License-Identifier: GPL-2.0
/*
 * Pagein Track
 *
 * Copyright 2020 IBM Corp.
 *
 */
#include <svm_host.h>
#include <stdio.h>
#include <utils.h>
#include <stdlib.h>
#include <context.h>
#include <logging.h>
#include <svm_page_alloc.h>
#include <mmu.h>
#include <utils.h>
#include <pagein_track.h>
#include <include/hvcall.h>

#define BITSHIFT	6	/* log2(u64) */
#define BITMASK		((0x1ULL << BITSHIFT) - 1)
#define LOC(num)	((u64)num >> BITSHIFT)
#define BITNUM(num)	((u64)num & BITMASK)
#define BIT(num)	(0x1ULL << num)
#define MAXGFN	(UV_PAGE_SIZE*8)

static void set_bit(u64 *bitmap, int bitnum)
{
	bitmap[LOC(bitnum)] |= BIT(BITNUM(bitnum));
}

static bool is_bit_set(u64 *bitmap, int bitnum)
{
	return (bitmap[LOC(bitnum)] & BIT(BITNUM(bitnum)));
}

int init_pagein_tracking(struct svm *svm)
{
	if (svm->pagein_bitmap)
		return 0;

	if (!acquire_page_reservation(1))
		return -1;

	svm->pagein_bitmap = alloc_uv_page(1, NULL);
	if (!svm->pagein_bitmap) {
		pr_warn("%s INTERNAL INCONSISTENCY, page allocation "
			"failed inspite of successful reservation\n", __func__);
		return -1;
	}
	memset(svm->pagein_bitmap, 0, UV_PAGE_SIZE);
	return 0;
}

void destroy_pagein_tracking(struct svm *svm)
{
	if (!svm->pagein_bitmap)
		return;

	free_uv_page(svm->pagein_bitmap);
	svm->pagein_bitmap = NULL;

	release_page_reservation(1);

	/*
	 * @todo WARNING: Zero the bytes in the pages that got paged-in; the
	 * page-range that was not requested in any get_page_range() call. The
	 * hypervisor could implant malicious code in those bytes to attack the
	 * guest.
	 *
	 * Ex: lets say the first get_page_range() requested from gpa range
	 * 10-30. But get_page_range will copy from 0-64K.  The next page
	 * request is from 20 to 50bytes.  And now destroy_pagein_tracking()
	 * got called.  Before returning, destroy_pagein_tracking() must zero
	 * bytes 0-9 and 51-64K. Otherwise Hypervisor can take advantage of any
	 * code that got copied in those ranges.
	 */
}

static bool is_page_paged_in(struct svm *svm, gfn_t gfn)
{
	if (gfn >= MAXGFN) {
		pr_error("%s GFN 0x%llx number out of bound\n", __func__, gfn);
		return false;
	}

	return	is_bit_set(svm->pagein_bitmap, gfn);
}

static void set_page_paged_in(struct svm *svm, gfn_t gfn)
{
	return set_bit(svm->pagein_bitmap, gfn);
}

/** @brief return the physical address mapped to the GPA at @gpa
 *
 * If @gpa is not paged-in from the Hypervisor, page it in.
 *
 * @rstate reflection state of the caller.  @gpa the Guest Physical Address.
 * @len number of bytes.
 *
 * WARNING: Must be called only before the VM has gone secure; before
 * H_SVM_INIT_DONE is called.
 *
 * Keeps track of requests; using a bitmap, for the same page, and skips paging
 * in the page from the Hypevisor. The bitmap is discarded once he VM goes
 * secure.
 *
 * It is tempting to consider the intmap infrastructure to track duplicate
 * requests. But that infrastructure is built for tracking GFN states, not to
 * track duplicate GFN page-in requests.
 */
void *get_page_range(struct refl_state *rstate, gpa_t gpa, u64 len)
{
	struct svm *svm = rstate->svm;
	int rc;
	gfn_t gfn;
	gfn_t start_gfn = SVM_GPA_TO_GFN(gpa);
	gfn_t end_gfn = SVM_GPA_TO_GFN((gpa + len - 1));
	enum gpf_state state;

	if (!len)
		return NULL;

	if (IS_SVM_SECURE(svm)) {
		pr_warn("%s called after the VM has turned secure. Ignored.\n",
			__func__);
		return NULL;
	}

	if (!svm_valid_gfn_range(svm, start_gfn, (end_gfn - start_gfn + 1) )) {
		pr_debug("%s Nonexistent Page gpa=0x%llx is request. Ignored.\n",
			 __func__, gpa);
		return NULL;
	}

	for (gfn = start_gfn; gfn <= end_gfn; gfn++) {

		if(is_page_paged_in(svm, gfn))
			continue;

		svm_gfn_lock(svm, (gfn));
		state = svm_get_gfn_state(svm, gfn);
		svm_gfn_unlock(svm, (gfn));

		if (state != GPF_SECURE)
			continue;

		rc = h_svm_page_in(rstate, SVM_GFN_TO_GPA(gfn),
				   H_PAGE_IN_NONSHARED);
		if (rc) {
			pr_error("%s: page-in 0x%llx page from HV[%d]\n",
				 __func__, SVM_GFN_TO_GPA(gfn), rc);
			return NULL;
		}

		set_page_paged_in(svm, gfn);
	}

	return gpa_to_addr(&svm->mm, gpa, NULL);
}
