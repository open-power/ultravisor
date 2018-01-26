// SPDX-License-Identifier: GPL-2.0
/*
 * SVM Hosts
 *
 * Copyright 2018 IBM Corp.
 *
 */

#define pr_fmt(fmt) "SVM: " fmt

#include <svm_host.h>
#include <stdio.h>
#include <utils.h>
#include <uvcall.h>
#include <inttypes.h>
#include <stdlib.h>
#include <logging.h>
#include <context.h>
#include <page_alloc.h>
#include <hvcall.h>
#include <mmu.h>
#include <tlbflush.h>
#include <exceptions.h>
#include <nondump_alloc.h>
#include <page_encrypt.h>
#include <numa_fault.h>
#include <svm/svm-rtas.h>
#include <mem_region.h>
#include <pagein_track.h>
#include <uv/uv-crypto.h>

static LIST_HEAD(uv_svms);
static struct lock svm_lock = LOCK_UNLOCKED;

struct svm * __get_svm(u64 lpid);

bool hv_is_LE;			/* True if HV is LE */

static void __del_reflect_states(struct list_head *refl_states)
{
	struct refl_state *_s, *_n;

	list_for_each_safe(refl_states, _s, _n, link) {
		list_del(&_s->link);
		free(_s);
	}
}

static void __del_reflect_states_svm(struct svm *sh_svm)
{
	 __del_reflect_states(&sh_svm->refl_states);
}

struct refl_state *find_reflect_state(u64 lpid, u64 magic)
{
	struct svm *sh_svm;
	struct refl_state *_s;
	struct refl_state *_state = NULL;

	sh_svm = get_svm(lpid);

	if(!sh_svm)
		return NULL;

	lock(&sh_svm->lock);

	list_for_each(&sh_svm->refl_states, _s, link) {
		if (_s->active && _s->magic == magic) {
			_state = _s;
			break;
		}
	}

	unlock(&sh_svm->lock);
	return _state;
}

static struct refl_state *setup_reflect_state(struct list_head *refl_states)
{
	struct refl_state *_s;
	struct refl_state *_state = NULL;

	list_for_each(refl_states, _s, link) {
		if (!_s->active) {
			_s->active = true;
			_state = _s;
			break;
		}
	}

	if (!_state) {
		_state = zalloc(sizeof(*_state));
		if (!_state)
			return NULL;
		_state->active = true;
		list_add_tail(refl_states, &_state->link);
	}
	return _state;
}

struct refl_state *get_reflect_state_svm(u64 lpid)
{
	struct svm *sh_svm;
	struct refl_state *state;

	sh_svm = get_svm(lpid);
	if(!sh_svm)
		return NULL;

	lock(&sh_svm->lock);

	state = setup_reflect_state(&sh_svm->refl_states);
	if (!state)
		goto out;

	if (state->svm) {
		assert(state->svm == sh_svm);
	} else {
		state->svm = sh_svm;
		state->id = ++sh_svm->next_state_id;
	}

out:
	unlock(&sh_svm->lock);
	return state;
}

void put_reflect_state(struct refl_state *state)
{
	/*
	 * @todo we don't need this lock since all we are doing is marking
	 * 	 the state inactive. Only impact of not taking the lock is
	 * 	 that get_reflect_state() may skip over this r_state when
	 * 	 looking for an inactive reflect state, but this will get
	 * 	 reused on the next get_reflect_state().
	 */
	lock(&state->svm->lock);

	state->active = false;

	unlock(&state->svm->lock);
}

static void del_esmb_file_ctx(struct svm *sh_svm)
{
	struct esmb_file_ctx *_c, *_n;

	list_for_each_safe(&sh_svm->esmb_file_ctx, _c, _n, link) {
		list_del(&_c->link);
		free(_c);
	}
}

struct esmb_file_ctx *find_esmb_file_ctx(struct svm *svm, char *name)
{
	struct esmb_file_ctx *tmp;
	struct esmb_file_ctx *ctx = NULL;

	list_for_each(&svm->esmb_file_ctx, tmp, link) {
		if (strcmp(tmp->filename, name) == 0) {
			ctx = tmp;
			break;
		}
	}

	return ctx;
}

static int populate_memslot_secure_pages(struct svm *svm,
				struct svm_memory_slot *slot)
{
       u64 total_pages;

       total_pages = get_reservation_size(SVM_GFN_TO_GPA(slot->base_gfn),
				SVM_PAGES_TO_BYTES(slot->npages));

       if (!acquire_page_reservation(total_pages))
		goto out;

       if (setup_page_range(&svm->mm, SVM_GFN_TO_GPA(slot->base_gfn),
				SVM_PAGES_TO_BYTES(slot->npages)))
		goto free_page;

       svm->reserved_pages += total_pages;
       return 0;

free_page:
       release_page_reservation(total_pages);
out:
       return U_BUSY;
}

/*
 * Insert/Delete memslot and re-sort memslots based on their GFN,
 * so binary search could be used to lookup GFN.
 * Sorting algorithm takes advantage of having initially
 * sorted array and known changed memslot position.
 */
static void update_memslots(struct svm_memslots *slots,
			    struct svm_memory_slot *new)
{
	int id = new->id;
	int i = slots->id_to_index[id];
	struct svm_memory_slot *mslots = slots->memslots;

	if (mslots[i].id != id) {
		pr_warn("memslot %d has a incorrect id=%d. "
			"Memslots in inconsistent state\n",
			i, id);
		return;
	}

	if (!new->npages) {
		if (mslots[i].npages)
			slots->used_slots--;
	} else {
		if (!mslots[i].npages)
			slots->used_slots++;
	}

	while (i < SVM_MEM_SLOTS_NUM - 1 &&
	       new->base_gfn <= mslots[i + 1].base_gfn) {
		if (!mslots[i + 1].npages)
			break;
		mslots[i] = mslots[i + 1];
		slots->id_to_index[mslots[i].id] = i;
		i++;
	}

	/*
	 * The ">=" is needed when creating a slot with base_gfn == 0,
	 * so that it moves before all those with base_gfn == nbytes == 0.
	 *
	 * On the other hand, if new->nbytes is zero, the above loop has
	 * already left i pointing to the beginning of the empty part of
	 * mslots, and the ">=" would move the hole backwards in this
	 * case---which is wrong.  So skip the loop when deleting a slot.
	 */
	if (new->npages) {
		while (i > 0 &&
		       new->base_gfn >= mslots[i - 1].base_gfn) {
			mslots[i] = mslots[i - 1];
			slots->id_to_index[mslots[i].id] = i;
			i--;
		}
	} else if (i != slots->used_slots)  {
		pr_error("memslots is in a inconsistent state\n");
		return;
	}

	mslots[i] = *new;
	slots->id_to_index[mslots[i].id] = i;
}

static bool memslot_overlap(struct svm *svm, u64 start_gpa, u64 nbytes,
					u16 slotid)
{
	u64 base_gfn = SVM_GPA_TO_GFN(start_gpa);
	u64 npages = SVM_BYTES_TO_PAGES(nbytes);
	struct svm_memory_slot *slot;

	/* @todo: change this linear search to binary */
	svm_for_each_memslot(slot, svm->memslots) {
		if (slot->id == slotid)
			continue;
		if (!((base_gfn + npages <= slot->base_gfn) ||
			(base_gfn >= slot->base_gfn + slot->npages)))
			return true;
	}
	return false;
}

int create_memslot(struct svm *svm, gpa_t start_gpa,
			u64 nbytes, u64 flags, u16 slotid)
{
	struct svm_memory_slot new;
	int rc;

	/* General sanity checks */
	if (start_gpa & (SVM_PAGESIZE - 1))
		goto out;
	if (start_gpa + nbytes < start_gpa)
		goto out;
	if (slotid >= SVM_MEM_SLOTS_NUM)
		goto out;

	/* make sure that the new slot does not overlapp any other slot */
	if (memslot_overlap(svm, start_gpa, nbytes, slotid))
		goto out;

	new.id = slotid;
	new.base_gfn = SVM_GPA_TO_GFN(start_gpa);
	new.npages = SVM_BYTES_TO_PAGES(nbytes);
	new.flags = flags;

	rc = populate_memslot_secure_pages(svm, &new);
	if (rc)
		goto out;

	/* add the slot and sort it */
	update_memslots(&svm->memslots, &new);
	svm->memslots.generation++;

	/* @todo: we should have allocate a new memslot datastructure, worked
	 * on it, and then committed with a new generation number. This is
	 * guard against racing with a deletion of the same VM.
	 */
	return 0;
out:
	return U_PARAMETER;
}

static void release_pagetable(struct svm *svm, struct svm_memory_slot *slot);

int free_memslot(struct svm *svm, u16 slotid)
{
	struct svm_memory_slot new;
	struct svm_memory_slot *slotp;
	int i;

	i = svm->memslots.id_to_index[slotid];
	/*
	 * If freeing the last memslot, cleanup all pagetables
	 */
	slotp = &svm->memslots.memslots[i];
	if (svm->memslots.used_slots == 1)
		slotp = NULL;

	/*
	 * Release associated page tables associated
	 * first before freeing the memslot.
	 */
	release_pagetable(svm, slotp);

	new.id = slotid;
	new.base_gfn = 0;
	new.npages = 0;
	new.flags = 0;
	update_memslots(&svm->memslots, &new);
	return 0;
}

struct svm_memory_slot *search_memslots(struct svm_memslots *slots, gfn_t gfn)
{
	int start = 0, end = slots->used_slots;
	int slot = atomic_read(&slots->lru_slot);
	struct svm_memory_slot *memslots = slots->memslots;

	if (gfn >= memslots[slot].base_gfn &&
	    gfn < memslots[slot].base_gfn + memslots[slot].npages)
		return &memslots[slot];

	while (start < end) {
		slot = start + (end - start) / 2;

		if (gfn >= memslots[slot].base_gfn)
			end = slot;
		else
			start = slot + 1;
	}

	if (gfn >= memslots[start].base_gfn &&
	    gfn < memslots[start].base_gfn + memslots[start].npages) {
		atomic_set(&slots->lru_slot, start);
		return &memslots[start];
	}

	return NULL;
}

static void memslots_clean(struct svm_memslots *memslots)
{
	memset(memslots, 0, sizeof(struct svm_memslots));
}

static void svm_cleanup(struct svm *svm)
{
	svm->next_state_id = -1;
	svm_cleanup_cookie(svm);
	__del_reflect_states_svm(svm);
	del_esmb_file_ctx(svm);
	release_pagetable(svm, NULL);
	release_page_reservation(svm->reserved_pages);
	svm->reserved_pages = 0;

	/*
	 * release_pagetable() needs ->svm_pagemap.
	 * So do not clear it prior to calling release_pagetable()
	 */
	svm_pagemap_clear(&svm->svm_pagemap);
	memslots_clean(&svm->memslots);
	if (IS_SVM_SECURE(svm))
		mmu_partition_table_set_entry(svm->lpid, 0, 0);

	/* release the runtime key */
	free_non_dumpable(svm->encdec_key);
	svm->encdec_key = NULL;

	/* Clear fwnmi registered address */
	svm->fwnmi_machine_check_addr = 0;

	/* cleanup page-in tracking */
	destroy_pagein_tracking(svm);

	svm->lpid = -1;
	list_del(&svm->link);

	free(svm);

//#define DUMP_ACTIVE_ALLOCS
#ifdef DUMP_ACTIVE_ALLOCS
	/*
	 * Dump memory usage to debug leaks. Hurts performance though!
	 */
	mem_dump_allocs();
	mem_dump_free();
#endif /* DUMP_ACTIVE_ALLOCS */
}

static void svm_initialize(struct svm *svm, u64 lpid)
{
	int i;
	struct svm_memslots *slots = &svm->memslots;

	svm->next_state_id = -1;
	svm_pagemap_init(&svm->svm_pagemap);
	init_lock(&svm->page_lock);
	init_lock(&svm->lock);
	list_head_init(&svm->refl_states);
	list_head_init(&svm->esmb_file_ctx);
	list_add_tail(&uv_svms, &svm->link);

	/*
	 * This value never changes.
	 * __get_svm() locates this structure using this field
	 */
	svm->lpid = lpid;

	SET_SVM_ACTIVE(svm);

	for (i = 0; i < SVM_MEM_SLOTS_NUM; i++)
		slots->id_to_index[i] = slots->memslots[i].id = i;

	for (i = 0; i < NUM_GPF_LOCKS; i++)
		init_lock(&svm->svm_gfn_lock[i]);

	/* Set default MCE vector number */
	svm->fwnmi_machine_check_addr = 0x200;
}

u64 create_svm(u64 lpid)
{
	u64 rc;
	struct svm *sh_svm, *tmp;

	sh_svm = zalloc(sizeof(*sh_svm));
	if (!sh_svm)
		return U_RETRY;

	lock(&svm_lock);

	tmp = __get_svm(lpid);
	if (tmp) {
		rc = U_BUSY;
		free(sh_svm);
		goto out_unlock;
	}

	svm_initialize(sh_svm, lpid);
	rc = U_SUCCESS;
	pr_info("%s: Created svm with lpid %lld\n", __func__, lpid);

out_unlock:
	unlock(&svm_lock);
	return rc;
}

void destroy_svm(u64 lpid)
{
	struct svm *sh_svm;

	lock(&svm_lock);

	sh_svm = __get_svm(lpid);

	if (sh_svm)
		svm_cleanup(sh_svm);

	unlock(&svm_lock);
}

struct svm *__get_svm(u64 lpid)
{
	struct svm *sh_svm;

	list_for_each(&uv_svms, sh_svm, link) {
		if (sh_svm->lpid == lpid) {
			return sh_svm;
		}
	}

	return NULL;
}

struct svm *get_svm(u64 lpid)
{
	struct svm *sh_svm;

	lock(&svm_lock);

	sh_svm = __get_svm(lpid);

	unlock(&svm_lock);
	return sh_svm;
}

/*
 * svm_pin_page() -- Back the GPA with a normal page and
 * do not allow the page to be invalidated.
 *
 * return holding the lock 'lk'.
 *
 * Must be called on a shared GPA only.
 * Must be called with *lk lock held.
 */
void svm_pin_pages(struct refl_state *r_state, gpa_t gpa,
		   unsigned int num_pages, struct lock *lk,
		   bool (*is_gpa_present)(struct svm *svm, gpa_t gpa))
{
	struct svm *svm = r_state->svm;
	unsigned int i;
	bool all_present;
	int count = 0;
	int rc;

	do {
		all_present = true;

		for (i = 0; i < num_pages; i++) {
			if (is_gpa_present(svm, gpa + i * SVM_PAGESIZE))
				continue;

			all_present = false;

			unlock(lk);

			rc = h_svm_page_in(r_state, gpa + i * SVM_PAGESIZE,
					   H_PAGE_IN_SHARED);

			lock(lk);

			if (rc) {
				pr_warn("%s %d H_SVM_PAGE_IN failed %d\n",
					__func__, __LINE__, rc);
			}
		}
	} while (!all_present && ++count < 10);

	if (count == 10) {
		pr_warn("%s: GPA still invalid after %d tries.\n",
			__func__, count);
		svm_abort(r_state);
	}
}

#ifdef ESM_BLOB_CHK_WARN_ONLY
int page_in_from_hv(struct refl_state *rstate)
{
	struct svm_memory_slot *slot;
	struct svm *svm = rstate->svm;
	u64 nbytes;
	gpa_t start_gpa;
	void *addr;

	svm_for_each_memslot(slot, svm->memslots) {
		start_gpa = SVM_GFN_TO_GPA(slot->base_gfn);
		nbytes = SVM_PAGES_TO_BYTES(slot->npages);

		addr = get_page_range(rstate, start_gpa, nbytes);
		if (!addr)
			return -1;
	}
	return 0;
}
#endif /* ESM_BLOB_CHK_WARN_ONLY */

static bool svm_valid_hv_address(u64 hv_page)
{
	if (!hv_page)
		return false;

	/* hv_page must not point to secure memory */
	if (hv_page & PPC_BIT(secure_ra_bit))
		return false;

	/*
	 * @todo check the hypervisor's device tree and validate the
	 * address
	 */
	return true;
}

static bool  svm_valid_address(struct svm *svm, gpa_t gpa)
{
	struct svm_memory_slot *slot;
	gpa_t start_gpa;
	u64 nbytes;

	/* if access is out of the size of the guest error */
	svm_for_each_memslot(slot, svm->memslots) {
		start_gpa = SVM_GFN_TO_GPA(slot->base_gfn);
		nbytes = SVM_PAGES_TO_BYTES(slot->npages);

		if (gpa >= start_gpa && gpa < (start_gpa+nbytes))
			return true;
	}
	return false;
}

bool  svm_valid_gfn_range(struct svm *svm, gfn_t start_gfn, u64 npages)
{
	struct svm_memory_slot *slot;
	gfn_t last_gfn = start_gfn + npages -1;
	gfn_t mslot_start_gfn, mslot_end_gfn;

	/* if access is out of the size of the guest error */
	svm_for_each_memslot(slot, svm->memslots) {
		mslot_start_gfn = slot->base_gfn;
		mslot_end_gfn = mslot_start_gfn + slot->npages - 1 ;

		if (last_gfn > mslot_end_gfn)
			return false;

		if (last_gfn >= mslot_start_gfn) {
			if (start_gfn >= mslot_start_gfn)
				return true;
			else
				last_gfn = mslot_start_gfn-1;
		}
	}
	return false;
}

/*
 * Unshare the address corresponding to the guest frame number.
 * @rstate: the reflection state.
 * @gfn: the guest frame number.
 *
 * Ones the address is unshared, it is replaced with a secure
 * frame.
 */
static int unshare_gfn(struct refl_state *rstate, gfn_t gfn)
{
	struct svm *svm = rstate->svm;
	int rc;

	svm_hv_unsharing_gfn(svm, gfn);

	svm_gfn_unlock(svm, gfn);
	rc = h_svm_page_in(rstate, SVM_GFN_TO_GPA(gfn), H_PAGE_IN_NONSHARED);
	svm_gfn_lock(svm, gfn);

	if (!rc) {
		/*
		 * H_SVM_PAGE_IN is not expected to callback into UV_PAGE_IN.
		 * Hence do not have an opportunity to mark it as HV_UNSHARED.
		 * We can mark the gfn as HV_UNSHARED here.
		 */
		svm_hv_unshared_gfn(svm, gfn);
	}

	return rc;
}

/*
 * must be called with svm->page_lock held.
 */
static int handle_shared_page(struct svm *svm, u64 hv_page,
				gpa_t gpa, u64 flags, bool present)
{
	/*
	 * A invalidated shared page is getting validated with a new HV page.
	 * The page contains important data that has been passed back and
	 * forth. It cannot be zeroed.
	 */
	pre_shared_pagein_notify(svm, gpa);

	flags |= _PAGE_SOFT_SHARED;
	if (present) {
		setup_page(&svm->mm, svm->lpid, gpa, (void *)__va(hv_page),
			SVM_PAGESIZE, flags);
	} else {
		setup_page_notpresent(&svm->mm, svm->lpid, gpa,
			(void *)__va(hv_page), SVM_PAGESIZE, flags);
	}

	post_shared_pagein_notify(svm, gpa);

	return 0;
}

/*
 * must be called with svm->page_lock held.
 * mut be called with GPF lock for the corresponding GPA held.
 */
static int handle_pseudoshared_page(struct svm *svm, u64 hv_page,
				gpa_t gpa)
{
	pre_shared_pagein_notify(svm, gpa);
	svm_pseudoshared_gfn(svm, SVM_GPA_TO_GFN(gpa), (void *)__va(hv_page));
	post_shared_pagein_notify(svm, gpa);
	return 0;
}

/*
 * Invalidate a PTE.
 * Invalidation is a heavy operation. It can split large pages
 * into smaller pages. So avoid the heavy-lifting, if the SVM is
 * already in an aborted state.
 */
static int __svm_page_invalidate(struct svm *svm, gpa_t gpa)
{
	if (IS_SVM_ABORT(svm))
		return 0;

	return setup_page_invalidate(&svm->mm, svm->lpid, gpa, SVM_PAGESIZE);
}

/*
 * must be called with svm->page_lock held.
 * mut be called with GPF lock for the corresponding GPA held.
 */
static int svm_page_invalidate(struct svm *svm, gpa_t gpa,
		enum gpf_state state)
{
	int ret = 0;
	gfn_t gfn = SVM_GPA_TO_GFN(gpa);

	pre_invalidate_notify(svm, gpa);

	switch (state) {
	case GPF_SHARED:
		ret = __svm_page_invalidate(svm, gpa);
		if (!ret)
			svm_shared_explicit_invalidate_gfn(svm, gfn);
		break;

	case GPF_SHARED_IMPLICIT:
		ret = __svm_page_invalidate(svm, gpa);
		if (!ret)
			svm_shared_implicit_invalidate_gfn(svm, gfn);
		break;

	case GPF_HV_UNSHARING:
		/*
		 * if the GFN is in HV_UNSHARING state, it means the hypervisor
		 * has not yet received our unshare request. Lets invalidate
		 * the GFN. Whenever the hypervisor receives our unshare
		 * request, and corrects its view of the GFN as secure, it will
		 * return back to UV with success; in uv_unshare_with_hv(). And
		 * UV will correctly mark the pte; corresponding to the GFN, as
		 * valid and will point it to the correct secure page. In case
		 * the HV returned with failue to our unshare request, UV would
		 * have anyway had the pte in the right state; i.e invalidated.
		 */
		svm_hv_unsharing_invalidate_gfn(svm, gfn);
		break;

	case GPF_HV_SHARED:
		/* noted down the NULL page */
		svm_hv_shared_invalidate_gfn(svm, gfn, NULL);
		break;

	case GPF_PSEUDO_SHARED:
		/* noted down the NULL page */
		svm_pseudoshared_invalidate_gfn(svm, gfn, NULL);
		break;
	default:
		pr_warn("page invalidate called on a unshared "
			"GFN=%llx state=%s\n",
			gfn, state_stringify(state));
	}
	post_invalidate_notify(svm, gpa);

	return ret;
}

static inline int warn_if_not_shared_with_hv(enum gpf_state state)
{
	if ((state == GPF_HV_SHARED) || (state == GPF_HV_SHARED_INV))
		return 0;
	pr_warn("%s H_SVM_PAGE_IN returned success without "
		"marking the gfn as hypervisor_shared. GFN state is %s\n",
		__func__, state_stringify(state));
	return 1;
}

static inline int warn_if_not_unshared_with_hv(enum gpf_state state)
{
	if (state == GPF_HV_UNSHARED)
		return 0;
	pr_warn("%s H_SVM_PAGE_IN returned success without "
		"marking the gfn as hypervisor_shared. GFN state is %s\n",
		__func__, state_stringify(state));
	return 1;
}

/*
 * Commit all the gfns that are in HV_SHARED state.
 * Move them to their final state as requested in 'share_type'
 *
 * Assumption: the caller must ensure that all the pages are in
 * HV_SHARED state or SHARED state.
 */
static void commit_all_gfns_as_shared(struct refl_state *rstate,
		gfn_t gfn, u64 npages, enum share_type share_type)
{
	int i, rc = 0;
	u64 hv_page;
	gpa_t gpa;
        void *addr;
	struct svm *svm = rstate->svm;
	enum gpf_state state;

	lock(&svm->page_lock);
	for (i=0; i < npages; i++) {

		svm_gfn_lock(svm, (gfn + i));
		state = svm_get_gfn_state(svm, (gfn + i));

		if (SVM_GPF_SHARED(state))
			goto end;

		rc = warn_if_not_shared_with_hv(state);
		if (rc)
			goto end;

		/*
		 * The hv_page must be retrived first, before changing
		 * the state of the gfn. Because changing the state
		 * of the gfn can overwrite the addr of hv_page
		 */
		hv_page = (u64) svm_gfn_get_data(svm, (gfn + i));
		gpa = SVM_GFN_TO_GPA((gfn + i));

		memset((void *)__va(hv_page), 0, SVM_PAGESIZE);

		if (share_type == SHARE_PSEUDO) {
			svm_pseudoshared_gfn(svm, (gfn + i),
					     (void *)__va(hv_page));
			goto end;
		}

		/*
		 * @todo. SHARE_IMPLICIT pages must be marked invalid.
		 * The SVM should not be allowed to access the gpa address,
		 * which the ultravisor has shared with the hypervisor,
		 * without the SVM's knowledge.
		 */
		addr = gpa_to_addr(&svm->mm, gpa, NULL);
		if (share_type == SHARE_IMPLICIT)
			svm_shared_implicit_gfn(svm, (gfn + i), addr);
		else
			svm_shared_explicit_gfn(svm, (gfn + i), addr);

		if (hv_page) {
			rc = handle_shared_page(svm, hv_page, gpa, 0,
					(share_type == SHARE_EXPLICIT));
		} else {
			/*
			 * In case, hypervisor invalidates the gfn before we
			 * reach here, invalidate the page.
			 */
			rc = svm_page_invalidate(svm, gpa, state);
		}

		if (rc)
			pr_error("%s: setting up page in the page table failed.\n",
				 __func__);

end:		svm_gfn_unlock(svm, (gfn + i));
		if (rc)
			break;
	}
	unlock(&svm->page_lock);
	if (rc) {
		svm_abort(rstate);
		/* control never comes here */
	}
	return;
}

/*
 * To be called only when any GPF fails to share in page_share_with_hv()
 * attempt will be made to revert the pages back to secure. If the attempt
 * fails, than the SVM will be aborted and control will not to be returned.
 */
static void revert_transient_pages_to_secure(struct refl_state *rstate,
		gfn_t gfn, u64 npages)
{
	int j, rc = 0;
	struct svm *svm = rstate->svm;
	enum gpf_state state;

	/* failed to share all :-( Revert the one that were modified */
	for (j=0; j < npages; j++) {
		svm_gfn_lock(svm, (gfn + j));

		state = svm_get_gfn_state(svm, (gfn + j));
		/*
		 * Skip shared gfn.
		 * They were shared when we got called. Hence must
		 * continue to be so.
		 */
		if (SVM_GPF_SHARED(state))
			goto end;

		/*
		 * Skip secure gfn.
		 * They were secure when we got called. Hence must
		 * continue to be so.
		 */
		if (SVM_GPF_SECURE(state))
			goto end;

		if (state == GPF_HV_SHARING) {
			svm_secure_gfn(svm, gfn, false);
			goto end;
		}

		if (state != GPF_HV_SHARED && state != GPF_HV_SHARED_INV) {
			svm_gfn_unlock(svm, (gfn + j));
			pr_error("%s GFN in unexpected state "
				 "gfn=%llx state=%d\n",
				 __func__, gfn + j, state);
			svm_abort(rstate);
			/* never reaches here */
		}

		rc = unshare_gfn(rstate, (gfn + j));

		if (rc) {
			svm_gfn_unlock(svm, (gfn + j));
			pr_error("%s HV failed to (revert) unshare a gfn=%llx\n",
				 __func__, gfn + j);
			svm_abort(rstate);
			/* never reaches here */
		}
end:
		svm_gfn_unlock(svm, (gfn + j));
	}

	/* all are successfully reverted. Mark them SECURE */
	for (j=0; j < npages; j++) {
		svm_gfn_lock(svm, (gfn + j));

		state = svm_get_gfn_state(svm, (gfn + j));
		if (SVM_GPF_SHARED(state))
			goto end1;

		warn_if_not_unshared_with_hv(state);
		svm_secure_gfn(svm, gfn + j, false);
end1:
		svm_gfn_unlock(svm, (gfn + j));
	}
	return;
}

int page_share_with_hv(struct refl_state *rstate, gpa_t gpa, u64 npages,
		enum share_type share_type)
{
	int i, max_tries, rc = 0;
	struct svm *svm = rstate->svm;
	gfn_t gfn = SVM_GPA_TO_GFN(gpa);
	enum gpf_state state;

	if (!svm_valid_gfn_range(svm, gfn, npages))
		return U_P2;

	for (i=0; i < npages; i++) {

		svm_gfn_lock(svm, (gfn + i));
		state = svm_get_gfn_state(svm, (gfn + i));

		/*
		 * Sharing a shared page is an idempotent
		 * operation.
		 */
		if (SVM_GPF_SHARED(state)) {
			svm_gfn_unlock(svm, (gfn + i));
			continue;
		}

		/*
		 * fail the operation if the gfn is in some
		 * transient shared state.
		 */
		if (SVM_GPF_TRANSIENT(state)) {
			svm_gfn_unlock(svm, (gfn + i));
			return U_P2;
		}

		max_tries = 4; /* do not loop infinitely */
		while (state == GPF_PAGEDOUT && max_tries--) {
			/* pagedout pages have to be pagedin first */
			svm_gfn_unlock(svm, (gfn + i));
			rc = h_svm_page_in(rstate, SVM_GFN_TO_GPA((gfn + i)),
						H_PAGE_IN_NONSHARED);
			svm_gfn_lock(svm, (gfn + i));

			if (rc)
				break;
			state = svm_get_gfn_state(svm, (gfn + i));
			/*
			 * The H_SVM_PAGE_IN could have returned success, but
			 * another thread can race in here and pageout the page
			 * right before we take the lock. Hence loop till the
			 * state is GPF_PAGEDOUT.
			 */
		}

		if (!max_tries)
			rc = U_RETRY;

		if (rc) {
			svm_gfn_unlock(svm, (gfn + i));
			break;
		}

		svm_hv_sharing_gfn(svm, (gfn + i));

		svm_gfn_unlock(svm, (gfn + i));
		rc = h_svm_page_in(rstate, SVM_GFN_TO_GPA((gfn + i)),
				H_PAGE_IN_SHARED);
		if (rc)
			break;

		/*
		 * The gfn must be HV_SHARED by now; accomplished through
		 * H_SVM_PAGE_IN/UV_PAGE_IN
		 */
	}

	if (rc) {
		revert_transient_pages_to_secure(rstate, gfn, i+1);
		return U_P2;
	}

	commit_all_gfns_as_shared(rstate, gfn, npages, share_type);
	return 0;
}

int page_unshare_with_hv(struct refl_state *rstate, gpa_t gpa, u64 npages)
{
	struct svm *svm = rstate->svm;
	gfn_t gfn = SVM_GPA_TO_GFN(gpa);
	int i, rc;
	enum gpf_state state;

	if (!svm_valid_gfn_range(svm, gfn, npages))
		return U_P2;

	/* sanity check, before diving into the execution */
	for (i=0; i < npages; i++) {

		svm_gfn_lock(svm, (gfn + i));
		state = svm_get_gfn_state(svm, (gfn + i));
		/*
		 * Allow unsharing, on secure GPFs and explicitly
		 * shared GPFs; not anything else.
		 * Unsharing a secure page is a idempotent
		 * operation.
		 */
		if (SVM_GPF_TRANSIENT(state) ||
			 SVM_GPF_UNSHARABLE(state)) {
			svm_gfn_unlock(svm, (gfn + i));
			return U_P2;
		}
		svm_gfn_unlock(svm, (gfn + i));
	}

	for (i=0; i < npages; i++) {
		svm_gfn_lock(svm, (gfn + i));
		state = svm_get_gfn_state(svm, (gfn + i));

		/* do nothing for secure gfns */
		if (SVM_GPF_SECURE(state))
			goto end;

		rc = unshare_gfn(rstate, (gfn+i));
		if (rc) {
			svm_gfn_unlock(svm, (gfn + i));
			pr_error("HV failed to (revert) unshare a gfn=%llx\n",
				 gfn+i);
			svm_abort(rstate);
		}
end:
		svm_gfn_unlock(svm, (gfn + i));
	}

	/* all are successfully unshared. Mark them all SECURE */
	for (i=0; i < npages; i++) {
		svm_gfn_lock(svm, gfn);
		svm_secure_gfn(svm, gfn + i, true);
		svm_gfn_unlock(svm, gfn);
	}

	return 0;
}

static bool unshare_entry_with_hv(gfn_t gfn, void *pointer, void *handle)
{
	struct refl_state *rstate = (struct refl_state *)handle;
	struct svm *svm = rstate->svm;
	enum gpf_state state;
	bool ret = true;
	(void ) pointer;

	svm_gfn_lock(svm, gfn);
	state = svm_get_gfn_state(svm, gfn);

	/*
	 * implictly shared and pusedo-shared gfns cannot be
	 * unshared. So, nothing to do. Just return true.
	 */
	if (SVM_GPF_UNSHARABLE(state))
		goto out;

	/*
	 * secure gfns (pagedin or pagedout) are already
	 * unshared. So, nothing to do. Just return true.
	 */
	if (SVM_GPF_SECURE(state))
		goto out;

	/*
	 * shared (valid and invalidated) GPFs are the only
	 * one that can be unshared. Unsharing the rest is
	 * an error. Return false
	 */
	if (state != GPF_SHARED &&
		state != GPF_SHARED_INV) {
		ret = false;
		goto out;
	}

	if (unshare_gfn(rstate, gfn)) {
		ret = false;
		pr_error("%s HV failed to unshare a gfn=%llx\n",
			 __func__, gfn);
		goto out;
	}

	svm_secure_gfn(svm, gfn, true);
out:
	svm_gfn_unlock(svm, gfn);
	return ret;
}

int page_unshare_all_with_hv(struct refl_state *rstate)
{
	struct svm *svm = rstate->svm;

	return !svm_pagemap_iterate_safe(&svm->svm_pagemap,
			unshare_entry_with_hv, (void *)rstate);
}

/* mut be called with state lock held. */
static int __handle_page_in(struct svm *svm, u64 hv_page, gpa_t gpa)
{
	void *uv_page;
	int present;
	int ret = U_P3;

	/*
	 * case (1) : VM is switching to SVM, mapping already
	 * 		exits. PTE_PRESENT will be set.
	 * 		Copy the content.
	 * case (2) : page was paged out and now is being
	 *		paged in.
	 * 		PTE_PRESENT will not be set.
	 *		Decrypt the content and remap the
	 *		original page.
	 */
	uv_page = gpa_to_addr(&svm->mm, gpa, &present);
	if (!uv_page)
		return ret;

	if (IS_SVM_SECURE(svm)) {
		struct encrypt_struct *enc_dec;

		enc_dec = (struct encrypt_struct *)
			svm_gfn_get_data(svm, SVM_GPA_TO_GFN(gpa));
		if (!enc_dec) {
			pr_warn("%s internal inconsistency detected."
				" No metadata available to"
				" decrypt a encrypted page\n", __func__);
			return ret;
		}

		if (page_decrypt(uv_page, __va(hv_page), SVM_PAGESIZE,
				 enc_dec)) {
			pr_error("Hypervisor tampering detected,"
				 " for SVM lpid=%llx\n", svm->lpid);
			return ret;
		}

		svm_gfn_release_data(svm, SVM_GPA_TO_GFN(gpa));
		free(enc_dec);

	} else
		memcpy(uv_page, __va(hv_page), SVM_PAGESIZE);

	svm_secure_gfn(svm, SVM_GPA_TO_GFN(gpa), false);

	/* if the page was paged-out remap */
	if (!present && setup_page(&svm->mm, svm->lpid, gpa,
					(void *)uv_page, SVM_PAGESIZE, 0)) {
		pr_error("%s page table setup failed, ABORTing SVM \n",
			 __func__);
		return ret;
	}

	return 0;
}


int handle_page_in(u64 lpid, u64 hv_page, gpa_t gpa, u64 flags, u64 order)
{
	struct svm *svm;
	int ret = 0;
	gfn_t gfn = SVM_GPA_TO_GFN(gpa);
	enum gpf_state state;

	if (order != SVM_PAGESHIFT)
		return U_P5;

	if (!svm_valid_hv_address(hv_page))
		return U_P2;

	svm = get_svm(lpid);
	if (!svm)
		return U_PARAMETER;

	if (IS_SVM_ABORT(svm))
		return U_STATE;

	if (!svm_valid_address(svm, gpa))
		return U_P3;

	lock(&svm->page_lock);

	svm_gfn_lock(svm, gfn);
	state = svm_get_gfn_state(svm, gfn);
	switch (state) {
	case GPF_SECURE:
	case GPF_HV_UNSHARED:
		if (IS_SVM_SECURE(svm)) {
			pr_warn("PAGIN called on a non pagedout GPF\n");
			ret = U_P2;
			break;
		}
		/* FALL THROUGH */

	case GPF_PAGEDOUT:
		ret = __handle_page_in(svm, hv_page, gpa);
		break;

	case GPF_SHARED:
	case GPF_SHARED_INV:
		svm_shared_explicit_gfn(svm, gfn, NULL);
		ret = handle_shared_page(svm, hv_page, gpa, flags,
				true /* mark pte as present */);
		break;

	case GPF_SHARED_IMPLICIT:
	case GPF_SHARED_IMPLICIT_INV:
		svm_shared_implicit_gfn(svm, gfn, NULL);
		ret = handle_shared_page(svm, hv_page, gpa, flags,
				false /* mark pte as not-present */);
		break;

	case GPF_PSEUDO_SHARED:
	case GPF_PSEUDO_SHARED_INV:
		ret = handle_pseudoshared_page(svm, hv_page, gpa);
		break;

	case GPF_HV_UNSHARING:
	case GPF_HV_UNSHARING_INV:
		svm_hv_unsharing_gfn(svm, gfn);
		break;

	case GPF_HV_SHARED:
	case GPF_HV_SHARING:
	case GPF_HV_SHARED_INV:
		svm_hv_shared_gfn(svm, gfn, (void *)hv_page);
		break;

	default:
		pr_warn("%s called on a %s page at gfn=%llx\n",
			__func__, state_stringify(state), gfn);
		ret = U_P2;
		break;
	}
	svm_gfn_unlock(svm, gfn);
	unlock(&svm->page_lock);
	return ret;
}


static uv_key_t *svm_get_encrypt_key(struct svm *svm)
{
	if (!svm->encdec_key) {
		/*
		 * allocate this from a non dumpable memory location. The key
		 * needs to be in a safe location which cannot be retrieved
		 * even from the dump of the ultravisor.
		 */
		svm->encdec_key =
			(uv_key_t *)malloc_non_dumpable(sizeof(uv_key_t));
		if (!svm->encdec_key) {
			pr_error("%s Key allocation failed. "
				 "Irrecoverable error for lpid=%llx\n",
				 __func__, svm->lpid);
			goto out;
		}

		/* initialize the key with a random value */
		uv_crypto_rand_bytes(*(svm->encdec_key), sizeof(uv_key_t));

		/* Initialize the IV. */
		uv_crypto_rand_bytes(svm->iv_state.fixed,
				     sizeof(svm->iv_state.fixed));
		svm->iv_state.counter = 0;
	}
out:
	return svm->encdec_key;
}

/*
 * must be called with svm->page_lock held.
 * mut be called with GPF lock for the corresponding GPA held.
 */
static int __handle_page_out(struct svm *svm, u64 hv_page, gpa_t gpa,
		enum gpf_state state)
{
	struct encrypt_struct *enc_dec;
	int ret;
	gfn_t gfn = SVM_GPA_TO_GFN(gpa);
	void *uv_page;
	uv_key_t *key;

	if (state == GPF_HV_UNSHARED) {
		/*
		 * GPF is in HV_UNSHARED state, which means the secure
		 * page is not yet committed to the pte.
		 * Ultravisor is still waiting on something, before
		 * it can officially coomit the pte and mark the GPF
		 * as SECURE. So please check back with us a bit later.
		 */
		return U_RETRY;
	}

	if (IS_SVM_ABORT(svm))
		return 0;

	if (state != GPF_SECURE)
		return U_P3;

	ret = __svm_page_invalidate(svm, gpa);
	if (ret)
		return ret;

	uv_page = gpa_to_addr(&svm->mm, gpa, NULL);
	if (!uv_page)
		return U_P3;

	key = svm_get_encrypt_key(svm);
	if (!key)
		return U_RETRY;

	enc_dec = page_encrypt(__va(hv_page), uv_page, SVM_PAGESIZE,
				       key, &svm->iv_state);
	if (!enc_dec) {
		pr_warn("Unable to encrypt a page-out, lpid=%llx\n", svm->lpid);
		return U_RETRY;
	}

	/*
	 * only secure gfns can be paged-out and paged-in.
	 * if a gfn is paged in or paged out, it means its a
	 * secure gfn
	 */
	svm_pagedout_gfn(svm, gfn, (void *)enc_dec);
	return 0;
}

int handle_page_out(u64 lpid, u64 hv_page, gpa_t gpa, u64 flags, u64 order)
{
	struct svm *svm;
	int ret;
	gfn_t gfn = SVM_GPA_TO_GFN(gpa);
	enum gpf_state state;

	if (order != SVM_PAGESHIFT)
		return U_P5;

	if (!svm_valid_hv_address(hv_page))
		return U_P2;

	svm = get_svm(lpid);
	if (!svm)
		return U_PARAMETER;

	/*
	 * NOTE: unlike UV_PAGE_IN or UV_PAGE INVALIDATE requests,
	 * we allow UV_PAGE_OUT operation while the SVM is in
	 * ABORT state. This is to facilitate the
	 * HV to recover any page that it chooses to.
	 */

	if (!svm_valid_address(svm, gpa))
		return U_P3;

	lock(&svm->page_lock);
	svm_gfn_lock(svm, gfn);
	state = svm_get_gfn_state(svm, gfn);
	/*
	 * Only secure GPFs can be meaningfully paged out.
	 * However a GPF that the HV thinks is secure, but
	 * UV has not yet noted as secure, must wait till
	 * UV makes it secure. So return U_RETRY.
	 */
	if (state == GPF_HV_UNSHARED) {
		ret = U_RETRY;
		goto out;
	}

	if (state != GPF_SECURE) {
		ret = U_PARAMETER;
		goto out;
	}

	(void) flags;
	ret = __handle_page_out(svm, hv_page, gpa, state);
out:
	svm_gfn_unlock(svm, gfn);
	unlock(&svm->page_lock);
	return ret;
}

int handle_page_inval(u64 lpid, gpa_t gpa, u64 order)
{
	struct svm *svm;
	int ret = 0;
	gfn_t gfn = SVM_GPA_TO_GFN(gpa);
	enum gpf_state state;

	if (order != SVM_PAGESHIFT)
		return U_P3;

	svm = get_svm(lpid);
	if (!svm)
		return U_PARAMETER;

	if (IS_SVM_ABORT(svm))
		return U_STATE;

	if (!svm_valid_address(svm, gpa))
		return U_P3;

	lock(&svm->page_lock);
	svm_gfn_lock(svm, gfn);
	state = svm_get_gfn_state(svm, gfn);
	switch (state) {
	case GPF_SHARED:
	case GPF_SHARED_IMPLICIT:
	case GPF_PSEUDO_SHARED:
	case GPF_HV_SHARED:
	case GPF_HV_UNSHARING:
		svm_page_invalidate(svm, gpa, state);
		break;
	case GPF_SECURE:
	case GPF_PAGEDOUT:
	case GPF_HV_SHARING:
	case GPF_HV_UNSHARED:
		pr_warn_once(
		      "%s invalidate called on a non-shared page at gfn=%llx\n",
		      __func__, gfn);
		ret = U_P2;
		break;
	case GPF_SHARED_INV:
	case GPF_SHARED_IMPLICIT_INV:
	case GPF_PSEUDO_SHARED_INV:
	case GPF_HV_SHARED_INV:
	case GPF_HV_UNSHARING_INV:
		/* invalidate an invalidated page? hmm.ok. Nothing to do */
		break;
	default:
		pr_warn("%s invalidate called on a %s page at gfn=%llx\n",
			__func__, state_stringify(state), gfn);
		ret = U_P2;
		break;
	}
	svm_gfn_unlock(svm, gfn);
	unlock(&svm->page_lock);
	return ret;
}

int svm_setup_partition_table(u64 lpid, u64 dw0, u64 dw1)
{
	struct svm *svm;

	lock(&svm_lock);

	svm = __get_svm(lpid);

	if (!svm) {
		cache_hv_endianness();
		mmu_partition_table_set_entry(lpid, dw0, dw1);
	} else
		mmu_partition_table_set_dw1(lpid, dw1);

	unlock(&svm_lock);
	return 0;
}

int svm_esm_commit(struct svm *svm)
{
	unsigned long dw0, rts_field;

	rts_field = radix__get_tree_size();
	dw0 = rts_field | __pa(svm->mm.pgd) | RADIX_PGD_INDEX_SIZE | PATB_HR;
	mmu_partition_table_set_dw0(svm->lpid, dw0);
	SET_SVM_SECURE(svm); /* mark the svm as secured */

#ifdef NUMA_STATISTIC
	numa_fault_init(svm);
#endif
	return 0;
}

struct unshare_entry_args {
	struct svm *svm;
	struct svm_memory_slot *slot;
};

static bool secure_the_entry(gfn_t gfn, struct svm_page_info *pointer, void *handle)
{
	struct unshare_entry_args *uargs = handle;
	struct svm_memory_slot *slot = uargs->slot;
	struct svm *svm = uargs->svm;
	u64 last_gfn = 0ULL;
	enum gpf_state state;

	(void ) pointer;

	if (slot) {
		last_gfn = slot->base_gfn + slot->npages;

		/* If gfn is not in specified memory slot skip */
		if (gfn < slot->base_gfn || gfn > last_gfn)
			return true;
	}

	svm_gfn_lock(svm, gfn);
	state = svm_get_gfn_state(svm, gfn);
	if (state != GPF_SECURE)
		svm_secure_gfn(svm, gfn, false);
	svm_gfn_unlock(svm, gfn);

	return true;
}

static void secure_page_table_entries(struct svm *svm,
		struct svm_memory_slot *slot)
{
	struct unshare_entry_args uargs;

	uargs.svm = svm;
	uargs.slot = slot;

	svm_pagemap_iterate_safe(&svm->svm_pagemap, secure_the_entry, &uargs);
}

static void release_pagetable(struct svm *svm, struct svm_memory_slot *slotp)
{
	u64 end = 0;
	u64 slot_end;
	u64 start;
	bool all;

	if (slotp) {
		start = SVM_GFN_TO_GPA(slotp->base_gfn);
		end = start + SVM_PAGES_TO_BYTES(slotp->npages);
		all = false;
	} else {
		struct svm_memory_slot *slot;

		start = 0;
		/* if it is sorted, than just go to the last slot*/
		svm_for_each_memslot(slot, svm->memslots) {
			slot_end = (SVM_GFN_TO_GPA(slot->base_gfn) +
					SVM_PAGES_TO_BYTES(slot->npages));
			end = max(end, slot_end);
		}
		all = true;
	}

	/*
	 * revert all the page table entries to point to their corresponding
	 * secure pages
	 */
	secure_page_table_entries(svm, slotp);

	/*
	 * now that the page table entries point to their corresponding secure
	 * pages, time to release the secure pages.
	 */
	release_page_range(&(svm->mm), all, start, end);
}

struct uv_page_data {
	gpa_t gpa;    	/* guest physical address */
	u64 npages; 	/* contiguous number of pages to share */
};

static void __noreturn ex_page_in(struct refl_state *r_state, void *data)
{
	struct uv_page_data *page_data = (struct uv_page_data *)data;
	int rc;

	rc = h_svm_page_in(r_state, (page_data->gpa & SVM_PAGEMASK),
			H_PAGE_IN_NONSHARED);
	if (rc)
		goto error;

	/** @todo this could go in the context wrapper */
	r_state->excp_frame.hsrr1 &= ~(MSR_HV);
	r_state->excp_frame.usrr0 = r_state->excp_frame.hsrr0;
	r_state->excp_frame.usrr1 = r_state->excp_frame.hsrr1;
error:
	free(data);
	ctx_end_context(r_state);
}

static inline int svm_page_in(struct stack_frame *stack, gpa_t gpa)
{
	struct uv_page_data *page_data;
	int rc;

	page_data = zalloc(sizeof(*page_data));
	if (!page_data) {
		pr_error("%s: page allocation failure\n", __func__);
		return U_RETRY;
	}

	page_data->gpa = gpa;
	page_data->npages = 1;
	rc = ctx_new_context_svm(stack->lpidr, stack, ex_page_in, page_data);
	if (rc)
		pr_error("%s: new_context returned %d\n", __func__, rc);

	free(page_data);
	return rc;
}

int svm_e00_handle(struct stack_frame *stack, gpa_t gpa)
{
	struct svm *svm = get_svm(stack->lpidr);
	gfn_t gfn;
	enum gpf_state state;

	/* The CPU ignores the top 2 bits of the address in real mode. */
	if (!(stack->usrr1 & MSR_DR))
		gpa &= ~0xc000000000000000;

	if (!svm_valid_address(svm, gpa)) {
		/*
		 * If the address isn't valid then it's most likely an MMIO
		 * access.
		 */
		return ctx_new_context_svm(stack->lpidr, stack,
					   emulate_mmio, NULL);
	}

	gfn = SVM_GPA_TO_GFN(gpa);
	svm_gfn_lock(svm, gfn);
	state = svm_get_gfn_state(svm, gfn);
	svm_gfn_unlock(svm, gfn);

	switch (state) {
	case GPF_SHARED_INV:
		return ctx_new_context_svm(stack->lpidr, stack,
					   exception_reflect, 0);

	case GPF_SHARED_IMPLICIT:
	case GPF_SHARED_IMPLICIT_INV:
		/*
		 * The SVM should never touch a implicitly shared page.
		 * Terminate the SVM.
		 */
		svm_abort(NULL);
		break;

	case GPF_PSEUDO_SHARED_INV:
	case GPF_PSEUDO_SHARED:
		/*
		 * We should never get a exception on a pseudo shared. That
		 * gfn's pte entry is never invalidated.
		 */
		pr_error("%s: e00 exeption on pseudo shared page gpa=%llx\n",
			 __func__, gpa);
		urfid_return(stack); /* Go back to the SVM */
		break;

	case GPF_SHARED:
		urfid_return(stack); /* Go back to the SVM */
		break;

	case GPF_SECURE:
#ifdef NUMA_STATISTIC
		if (is_page_noaccess(&svm->mm, gpa)) {
		    numa_fault(svm, gpa);
		    urfid_return(stack); /* Go back to the SVM */
		}
#endif
		pr_warn("%s: e00 exeption on a secure non-pagedout page gpa=%llx\n",
			__func__, gpa);
		urfid_return(stack); /* Go back to the SVM */

	case GPF_PAGEDOUT:
		return svm_page_in(stack, gpa);

	default:
		pr_warn("%s: e00 exeption on a page in an expected state gpa=%llx state=%x\n",
			__func__, gpa, state);
		urfid_return(stack); /* Go back to the SVM */
	}

	return 0; /* never reached */
}

/*
 * Return the interruption cause from the HFSCR register for an HV
 * Facility Unavailable interrupt (HFU).
 */
static inline int hfscr_ic(uint64_t hfscr)
{
	return ((hfscr >> HFSCR_IC_SHIFT) & HFSCR_IC_MASK);
}

/*
 * Return true if any of the "insecure" CPU features resulted in
 * an HV Facility Unavailable exception.
 */
static inline bool insecure_cpu_feature(void)
{
	return hfscr_ic(mfspr(SPR_HFSCR)) == HFSCR_IC_TM;
}

int svm_f80_handle(struct stack_frame *stack)
{
	if (insecure_cpu_feature()) {
		synthesize_prog_intr(stack, SRR1_PROGILL);
		/* not reached */
	}

	pr_error("Reflecting HFU, ic %d, hfscr 0x%lx\n",
		 hfscr_ic(mfspr(SPR_HFSCR)), mfspr(SPR_HFSCR));

	return ctx_new_context_svm(stack->lpidr, stack, exception_reflect, 0);
}

int __noreturn svm_e40_handle(struct stack_frame *stack, u64 heir)
{
	struct svm *svm = get_svm(stack->lpidr);
	gpa_t gpa = stack->hsrr0;
	void *uv_page;
	int present;

	/* The CPU ignores the top 2 bits of the address in real mode */
	if (!(stack->usrr1 & MSR_IR))
		gpa &= ~0xc000000000000000;

	if (!svm_valid_address(svm, gpa))
		pr_error("E40 invalid gpa=0x%llx heir=0x%llx \n",
			 gpa, heir);

	uv_page = gpa_to_addr(&svm->mm, gpa, &present);
	pr_error("Invalid E40 at gpa=0x%llx uv_page=0x%llx present=%d\n",
		 gpa,(u64)uv_page, present);
	dump_regs("Bad E40 in ultravisor", stack, 1);
	svm_abort(NULL);
}

int svm_e20_handle(struct stack_frame *stack, gpa_t gpa)
{
	struct svm *svm = get_svm(stack->lpidr);
	gfn_t gfn;
	enum gpf_state state;

	/* The CPU ignores the top 2 bits of the address in real mode */
	if (!(stack->usrr1 & MSR_IR))
		gpa &= ~0xc000000000000000;

	if (!svm_valid_address(svm, gpa))
		return ctx_new_context_svm(stack->lpidr, stack,
					   exception_reflect, 0);

	gfn = SVM_GPA_TO_GFN(gpa);
	svm_gfn_lock(svm, gfn);
	state = svm_get_gfn_state(svm, gfn);
	svm_gfn_unlock(svm, gfn);

#ifdef NUMA_STATISTIC
	if ((SVM_GPF_SECURE(state) || state == GPF_PSUEDO_SHARED)
			&& (is_page_noaccess(&svm->mm, gpa))) {
	    numa_fault(svm, gpa);
	    urfid_return(stack); /* Go back to the SVM */
	}
#endif

	/*
	 * code execution is allowed only on secure and pseudo-shared pages.
	 *
	 * receiving this exception on a paged-out page is normal and expected.
	 * However sometime the MMU generates this exception if it is unable to
	 * update the R/C bit in the PTE. Its a transient error. Ignore it and
	 * return back to the SVM.
	 */
	if (state != GPF_PAGEDOUT) {
		pr_debug("Spurious E20 at gpa=0x%llx asdr=0x%llx state=%s\n",
			 gpa, stack->asdr, state_stringify(state));
	    	urfid_return(stack); /* Go back to the SVM */
	}

	return svm_page_in(stack, gpa);
}

#ifdef NUMA_STATISTIC
void svm_task(struct stack_frame *stack)
{
	struct svm *svm = get_svm(stack->lpidr);

	numa_task(svm);
}
#endif
