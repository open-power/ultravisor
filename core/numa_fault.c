// SPDX-License-Identifier: GPL-2.0
/*
 * NUMA faults
 *
 * Copyright 2019 IBM Corp.
 */
#include <errno.h>
#include <inttypes.h>
#include <types.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <logging.h>
#include <processor.h>
#include <mmu.h>
#include <cpu.h>
#include <timebase.h>
#include <pgtable.h>
#include <svm_host.h>
#include <tlbflush.h>
#include <numa.h>
#include <numa_fault.h>

#ifdef NUMA_STATISTIC
#define PAGES_PER_PMD (1 << (RADIX_PTE_INDEX_SIZE + RADIX_PMD_INDEX_SIZE))

/* Maximum number of secured pages to invalidate each time */
#define MAX_PAGE_RATIO (PAGES_PER_PMD * 10)

#define atomic_add atomic_add_return_relaxed

/**
 * compute_fault_rate - compute and display numa faults rate
 *
 * Called every @NUMA_FAULT_DELAY seconds.
 * @svm : the svm descriptor
 * @tb  : the current timebase register value.
 */
static void compute_fault_rate(struct svm *svm, u64 tb)
{
	struct svm_numa_fault *nf = &svm->numa_fault;
	u64 elapsed;
	unsigned int distant, local;

	/* time elapsed in seconds */
	elapsed = tb_to_secs(tb - nf->last_tb);

	distant = nf->last_distant;
	local = nf->last_local;

	nf->last_distant = atomic_read(&nf->distant);
	nf->last_local = atomic_read(&nf->local);

	/* Compute number of numa faults during the elapsed time */
	distant = nf->last_distant - distant;
	local = nf->last_local - local;

	pr_debug("NUMA fault in %llus local: %u distant: %u "\
		 "total local: %u distant: %u\n",
		 elapsed, local, distant, nf->last_local, nf->last_distant);
}

static bool distant_access(struct svm *svm, gpa_t gpa)
{
	int32_t page_node_id = NUMA_NO_NODE;
	void *uv_page = gpa_to_addr(&svm->mm, gpa, NULL);

	if (uv_page)
		page_node_id = get_numa_node_id_of_page(uv_page);

	return page_node_id != this_cpu()->numa_node_id;
}

/**
 * numa_fault - called when a non accessible page is faulted.
 * @svm : the svm descriptor
 * @gpa : the faulted address
 * Return 0 on success, !=0 if the page is not present in the PTE.
 */
int numa_fault(struct svm *svm, gpa_t gpa)
{
	int npages;

	npages = set_normal_page(&svm->mm, svm->lpid, gpa);
	if (npages < 0) {
		pr_error("Can't set normal page at 0x%llx\n", gpa);
		return -1;
	}

	/* Record the fault in the SVM descriptor. */
	if (distant_access(svm, gpa))
		atomic_add(npages, &svm->numa_fault.distant);
	else
		atomic_add(npages, &svm->numa_fault.local);

	return 0;
}

/*
 * Goto the next non empty slot, wrapping back to the beginning if needed.
 */
static void next_non_empty_slot(struct svm *svm)
{
	struct svm_numa_fault *nf = &svm->numa_fault;
	struct svm_memory_slot *slot = nf->slot;
	bool looped = false;

	if (!slot)
		slot = &svm->memslots.memslots[0];
	else
		slot++;

again:
	for (; slot < svm->memslots.memslots + SVM_MEM_SLOTS_NUM; slot++)
		if (slot->npages) {
			nf->slot = slot;
			nf->next_gpa = SVM_GFN_TO_GPA(slot->base_gfn);
			nf->slot_end = nf->next_gpa;
			nf->slot_end += slot->npages << PAGE_SHIFT;
			return;
		}

	assert(!looped); /* don't loop for ever */

	slot =  &svm->memslots.memslots[0];
	looped = true;
	goto again;
}

static void compute_defaults(struct svm *svm)
{
	unsigned int npages = 0;
	struct svm_memory_slot *slot;

	svm->numa_fault.delay = secs_to_tb(NUMA_FAULT_DELAY);

	next_non_empty_slot(svm);

	/*
	 * Compute the number of pages to reset each time.
	 * Try using 10% of the total number of pages of the SVM.
	 * @todo: we might ignore the shared pages here.
	 */
	svm_for_each_memslot(slot, svm->memslots)
		npages += slot->npages;

	svm->numa_fault.page_ratio = npages * 10 / 100;

	if (!svm->numa_fault.page_ratio)
		svm->numa_fault.page_ratio = 1;
	else if (svm->numa_fault.page_ratio > MAX_PAGE_RATIO)
		svm->numa_fault.page_ratio = MAX_PAGE_RATIO;

	pr_info("NUMA page ratio:%u npages:%u.\n",
		svm->numa_fault.page_ratio, npages);
}

/**
 * do_numa_fault_reset - invalidate access to a set of secure pages of a SVM
 * @svm : the SVM descriptor
 *
 * This function is intended to be called on a timer regular basis only once at
 * a time per SVM
 */
static void do_numa_task(struct svm *svm)
{
	struct svm_numa_fault *nf = &svm->numa_fault;
	int npages;
	struct svm_memory_slot *first_slot = NULL;

	npages = nf->page_ratio;

	while (npages > 0) {
		int done;
		u64 next;

		if (nf->next_gpa >= nf->slot_end) {
			next_non_empty_slot(svm);
			if (nf->slot == first_slot) {
				pr_numa_debug("No more page to invalidate (%d)\n",
					      npages);
				return;
			}
			first_slot = nf->slot;
		}

		done = set_noaccess_range(&svm->mm, svm->lpid, npages,
					  nf->next_gpa,  nf->slot_end, &next);

		pr_numa_debug("NUMA invalidated %d pages in 0x%llx - 0x%llx\n",
			      done, nf->next_gpa, next);

		nf->next_gpa = next;
		npages -= done;
	}
}

/**
 * Called by multiple hooks, this function checks the time elapsed since the
 * last invalidation of a bunch of pages.  If the time elapsed is greater than a
 * specific time, it calls the worker function but only one CPU is allowed to do
 * so.
 * @svm : the SVM descriptor
 */
void numa_task(struct svm *svm)
{
	u64 tb;

	if (!try_lock(&svm->numa_fault.lock))
		return;

	tb = mftb();
	if (tb - svm->numa_fault.last_tb < svm->numa_fault.delay)
		goto out_unlock;

	/* First call, set the default values for this SVM */
	if (!svm->numa_fault.page_ratio)
		compute_defaults(svm);
	else
		compute_fault_rate(svm, tb);

	do_numa_task(svm);
	/*
	 * Read the timebase value to not take in account the time elapsed while
	 * invalidating the pages.
	 */
	svm->numa_fault.last_tb = mftb();

out_unlock:
	unlock(&svm->numa_fault.lock);
}
#endif /* NUMA_STATISTIC */
