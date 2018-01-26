/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SVM Hosts
 *
 * Copyright 2018, IBM Corporation.
 *
 */

#ifndef SVM_HOST_H
#define SVM_HOST_H

#include "lock.h"
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <atomic.h>
#include <pgtable.h>
#include <stack.h>
#include <hlist.h>
#include <logging.h>
#include <page_encrypt.h>
#include <svm/svm-pagemap.h>
#include <cookies.h>
#include <hvcall.h>

/*
 * @todo: There are also PAGE_SHIFT, PAGE_SIZE and PAGE_MASK defined in
 * pgtable.h. We may want to consolidate them or to rename these ones to avoid
 * confusion.
 */

#define SVM_USER_MEM_SLOTS      512
#define SVM_PAGESHIFT 		16
#define SVM_PAGESIZE 		( 0x1UL << SVM_PAGESHIFT )
#define SVM_PAGEMASK 		(~( SVM_PAGESIZE - 1 ))
#define SVM_GPA_TO_GFN(gpa)	(gpa >> SVM_PAGESHIFT)
#define SVM_GFN_TO_GPA(gfn)	(gfn << SVM_PAGESHIFT)

#define SVM_PAGES_TO_BYTES(pfn)		(pfn << SVM_PAGESHIFT)
#define SVM_BYTES_TO_PAGES(bytes) ((bytes+SVM_PAGESIZE-1) >> SVM_PAGESHIFT)

/**
 * @brief Memory slot
 */
struct svm_memory_slot {
	gfn_t base_gfn;
	u64 npages;
	u64 *dirty_bitmap;
	u64 userspace_addr;
	u32 flags;
	s16 id;
};

#define SVM_MEM_SLOTS_NUM SVM_USER_MEM_SLOTS

/**
 * @brief Memory slots
 */
struct svm_memslots {
	u64 generation;
	/* sorted by address */
	struct svm_memory_slot memslots[SVM_MEM_SLOTS_NUM];
	/* The mapping table from slot id to the index in memslots[]. */
	s16 id_to_index[SVM_MEM_SLOTS_NUM];
	atomic_t lru_slot; /* speeds up slot search */
	int used_slots;
	gpa_t svm_rmo_top;	/* svm RMO(RMA) top */
};

enum svm_state {
	SVM_ACTIVE = 0,
	SVM_SECURE,	/* SVM has fully transitioned to Secure mode */
	SVM_ABORT,	/* SVM has aborted while transitioning to Secure mode */
};
#define svm_for_each_memslot(memslot, slots)    \
	for (memslot = &slots.memslots[0];     \
		memslot < slots.memslots + SVM_MEM_SLOTS_NUM && memslot->npages;\
		memslot++)

/**
 * @brief RTAS start-cpu state
 */
struct start_cpu_state {
       u64 cpu_id;
       u64 start_here;
       u64 r3_contents;
       struct svm *svm;
};

/**
 * @ brief SVM Flatten Device Tree
 */
struct svm_fdt {
	gpa_t gpa_fdt;		/**< gpa_t of svm fdt. */
	void *workspace; 	/**< workspace pages for fdt updates. */
	void *wc_fdt;		/**< working copy of updated fdt in workspace. */
};

struct svm_rtas {
	struct lock rtas_gpa_lock; /**< protect the *bbuf and the present
				      bitmap */
	gpa_t rtas_args_bbuf;	/**< gpa_t of rtas_args bbuf. */
	gpa_t rtas_buf_bbuf;	/**< gpa_t of rtas buf bbuf. */
	uint8_t rtas_buf_present; /**< bitmap to track the presence
				  of RTAS buf GPAs */
	struct lock rtas_bitmap_lock; /**< protect bbuf_alloc_map */
	uint64_t bbuf_alloc_map; /**< map to track bbuf allocations. */
	gpa_t rtas_base;	/**< start of rtas area */
	size_t rtas_size;	/**< size of rtas area */
	size_t text_size;	/**< size of rtas instructions area */

	uint32_t stop_self_token;
	gpa_t stop_self_args;	/**< Argument buffers for stop-self call. */
};

/* Argument buffer for stop-self RTAS call. */
struct stop_self_args {
	__be32 token;
	__be32 nargs;	/* Always 0. */
	__be32 nret;	/* Always 1. */
	__be32 status;
};
#define RTAS_STOP_SELF_ARGS_SIZE sizeof(struct stop_self_args)

/*
 * Our limit on the number of guest CPUs is the number of stop-self argument
 * buffers that fit in a shared page.
 */
#define MAX_GUEST_CPUS	(SVM_PAGESIZE / RTAS_STOP_SELF_ARGS_SIZE)

struct svm_vcpus {
	/*
	 * Only track vcpus after max is set and the boot vcpu is identified.
	 * There are some hypercalls made before that happens, but they're too
	 * early too be tracked.
	 *
	 * WARNING: Currently this variable is updated only on two occasions:
	 * during processing of the UV_ESM call, and right before calling
	 * svm_abort() if vcpu tracking goes wrong. In neither case concurrency
	 * causes a problem so there's no lock protecting this variable. If the
	 * code becomes more complex, one could become necessary.
	 */
	bool tracking;

	/* Maximum number of vcpus. */
	uint32_t max;
};

void svm_rtas_pre_invalidate(struct svm *svm, gpa_t gpa);
void svm_rtas_post_invalidate(struct svm *svm, gpa_t gpa);
void svm_rtas_pre_shared_pagein(struct svm *svm, gpa_t gpa);
void svm_rtas_post_shared_pagein(struct svm *svm, gpa_t gpa);

struct svm_tss {
	struct lock tss_gpa_lock; /**< protect the *bbuf and the valid
				      bitmap */
	gpa_t	bbuf;	/**< gpa_t of bbuf for tpm communication. */
	gpa_t	xfer;	/**< gpa_t of xfer struct for svm tss use. */
	uint8_t tss_buf_present; /**< bitmap to track the presence
				  of TSS buf GPAs */
};

void svm_tss_pre_invalidate(struct svm *svm, gpa_t gpa);
void svm_tss_post_invalidate(struct svm *svm, gpa_t gpa);
void svm_tss_pre_shared_pagein(struct svm *svm, gpa_t gpa);
void svm_tss_post_shared_pagein(struct svm *svm, gpa_t gpa);

/*
 * Since rtas and tss are the only consumer of the invalidate event,
 * pre_invalidate_notify and post_invalidate_notify are shortcut to
 * {svm_rtas_pre_invalidate, svm_tss_pre_invalidate} and
 * {svm_rtas_post_invalidate, svm_tss_post_invalidate} respectively.
 *
 * The same is true for the shared_pagein notification.
 *
 * @todo: Implement a generic notification infrastructure that has an API
 * to register handlers for any kind of notification event.
 */
#define pre_invalidate_notify(svm, gpa)	{		\
		svm_rtas_pre_invalidate(svm, gpa);	\
		svm_tss_pre_invalidate(svm, gpa);	\
}
#define post_invalidate_notify(svm, gpa) {		\
		svm_rtas_post_invalidate(svm, gpa);	\
		svm_tss_post_invalidate(svm, gpa);	\
}
#define pre_shared_pagein_notify(svm, gpa) {		\
		svm_rtas_pre_shared_pagein(svm, gpa);	\
		svm_tss_pre_shared_pagein(svm, gpa);	\
}
#define post_shared_pagein_notify(svm, gpa) {		\
		svm_rtas_post_shared_pagein(svm, gpa);	\
		svm_tss_post_shared_pagein(svm, gpa);	\
}

/**
 * @brief An object containing buffers and addresses of oft-used
 * elements from the ESM blob of an SVM. The ESM Blob is an FDT that
 * contains guest secrets. It includes two nested FDTs, one for
 * digests and another for user files/attachments.
 */
struct svm_esmb {
	uint8_t	buf_key[4096];		/**< buf for svm esmb use. */
	uint8_t	buf_digest[4096];	/**< buf for svm esmb use. */
};

/**
 * @brief SVM ESMB file context
 *
 * Used to enforce read-once semantics on the ESMB file.
 *
 * ->last_byte_read contains the offset of the last byte in the ESMB file
 * that was read. Attempts to read parts of the file before this offset
 * will fail.
 *
 * ->pid contains the pid of the process that first attempted to read the
 * file. If a different PID attempts to subsequently read the same file,
 * the read will again fail.
 */
struct esmb_file_ctx {
	struct list_node link;
	char filename[65];
	u32  pid;
	u32  last_byte_read;
};

#ifdef NUMA_STATISTIC
struct svm_numa_fault {
	struct lock lock;
	u64 last_tb;
	u64 delay;
	atomic_t distant;
	atomic_t local;
	unsigned int last_distant;		/* protected by lock */
	unsigned int last_local;
	unsigned int page_ratio;
	struct svm_memory_slot *slot;
	gpa_t next_gpa;
	u64 slot_end;
};
#endif

/*
 * allocate NUM_GPF_LOCKS locks to manage the states of
 * each GPF. Ideally one lock must be allocated per GPF.
 * But than it a overkill. GPFs do not change state that
 * often. Using a lock to guard multiple GPFs saves the
 * number of lock without unduely adding latencies on
 * the GPFs. Stagger the GPFs protected by a given lock.
 * Eg: lock 0 protects all GPF ending with 0x0
 *     lock 1 protects all GPF ending with 0x1
 *     .....
 *     lock f protects all GPF ending with 0xf
 */
#define NUM_GPF_LOCKS 0x10

/**
 * @brief SVM guest
 */
struct svm {
	struct list_node link;
	u64 lpid;
	enum svm_state state;
	int next_state_id;
	struct mm_struct mm;
	svm_pagemap_t svm_pagemap;
	/*
	 * @todo: make this a pointer, since we want this to be
	 * transactionally updated, where the generation number is
	 * updated every time a memslot is changed.
	 */
	struct svm_memslots memslots;
	struct list_head refl_states;	/* active reflections for svm */
	struct list_head esmb_file_ctx;
	struct lock lock;
	struct lock page_lock;	/* very coarse lock to protect pte changes */
	struct hlist_head cookie_table[COOKIE_HASHSIZE];

	struct svm_fdt fdt;
	struct svm_rtas rtas;
	struct svm_tss tss;
	struct svm_vcpus vcpus;

#ifdef NUMA_STATISTIC
	struct svm_numa_fault numa_fault;
#endif

	u64    reserved_pages;
	gpa_t svm_esmb;
	gpa_t esmb_files_fdt;
	uv_key_t *encdec_key;  /* pointer to a key area in memory
				  that is **not dumpable** */

	/* State for generating the IV for each page encryption. */
	struct iv_state iv_state;
	struct lock svm_gfn_lock[NUM_GPF_LOCKS];

	/* Keep note of fwnmi registered address for MCE */
	u64	fwnmi_machine_check_addr;
	u64	*pagein_bitmap;	/* bitmap to temporarily track pageins
				   during ESM */
};

#define SET_SVM_ACTIVE(svm)  (svm->state = SVM_ACTIVE)
#define SET_SVM_SECURE(svm)  (svm->state = SVM_SECURE)
#define SET_SVM_ABORT(svm)  (svm->state = SVM_ABORT)
#define IS_SVM_SECURE(svm)  (svm->state == SVM_SECURE)
#define IS_SVM_ACTIVE(svm)  (svm->state == SVM_ACTIVE || IS_SVM_SECURE(svm))
#define IS_SVM_ABORT(svm)   (svm->state == SVM_ABORT)

extern u64 create_svm(u64 lpid);
extern struct svm *get_svm(u64 lpid);
extern void destroy_svm(u64 lpid);
extern int populate_secure_pages(struct svm *svm);

extern int create_memslot(struct svm *svm, gpa_t start_gpa, u64 nbytes,
			  u64 flags, u16 slotid);
extern int free_memslot(struct svm *svm, u16 slotid);
extern struct svm_memory_slot *search_memslots(struct svm_memslots *slots,
					       gfn_t gfn);

extern struct refl_state *get_reflect_state_svm(u64 lpid);
extern void put_reflect_state(struct refl_state *state);
extern struct refl_state *find_reflect_state(u64 lpid, u64 magic);
extern void svm_pin_pages(struct refl_state *r_state, gpa_t gpa,
			  unsigned int num_pages, struct lock *lk,
			  bool (*is_gpa_present)(struct svm *svm, gpa_t gpa));
#ifdef ESM_BLOB_CHK_WARN_ONLY
extern int page_in_from_hv(struct refl_state *rstate);
#endif /* ESM_BLOB_CHK_WARN_ONLY */

extern int64_t do_hcall(struct refl_state *r_state, u64 hcall, uint8_t arg_cnt,
			uint64_t *retbuf, uint8_t ret_cnt, ...);
extern int handle_page_in(u64 lpid, u64 hv_page, gpa_t gpa,
			  u64 flags, u64 order);
extern int handle_page_out(u64 lpid, u64 hv_page, gpa_t gpa,
			   u64 flags, u64 order);
extern int handle_page_inval(u64 lpid, gpa_t gpa, u64 order);
extern int svm_esm_commit(struct svm *svm);
extern int svm_register_pate(u64 lpid, u64 dw0, u64 dw1);
extern int svm_add_share_req(struct svm *svm, u64 gpfn, u64 npages);

enum share_type {
	SHARE_EXPLICIT    = 0, /* explicit share request originated from SVM. */
	SHARE_IMPLICIT    = 1, /* implicit share request originated from UV. */
	SHARE_PSEUDO	  = 2  /* implicit pseudo share request originated
				  from UV. */
};
extern int page_share_with_hv(struct refl_state *rstate, gpa_t gpa, u64 npages,
				enum share_type type);
extern int page_unshare_with_hv(struct refl_state *rstate, gpa_t gpa,
				u64 npages);
extern int page_unshare_all_with_hv(struct refl_state *rstate);
extern int svm_setup_partition_table(u64 lpid, u64 dw0, u64 dw1);
extern int svm_e00_handle(struct stack_frame *stack, gpa_t gpa);
extern int svm_e20_handle(struct stack_frame *stack, gpa_t gpa);
extern int svm_e40_handle(struct stack_frame *stack, u64 heir);
extern int svm_f80_handle(struct stack_frame *stack);
extern u64 svm_generate_cookie(struct svm *svm, void *data, u64 mask,
			       u64 min_value);
extern void *svm_find_del_cookie(struct svm *svm, u64 cookie);
extern bool svm_valid_gfn_range(struct svm *svm, u64 start_gfn, u64 npages);
static inline int h_svm_page_in(struct refl_state *rstate, gpa_t gpa, int type)
{
	return do_hcall(rstate, H_SVM_PAGE_IN, 3, NULL, 0,
			gpa, type, SVM_PAGESHIFT);
}
extern int rtas_start_cpu_end(struct svm *svm, struct stack_frame *stack);
#ifdef NUMA_STATISTIC
extern void svm_task(struct stack_frame *stack);
#else
#define svm_task(s) do {} while(0)
#endif

extern void __noreturn emulate_mmio(struct refl_state *r_state,
				    void *UNUSED(arg));
extern struct esmb_file_ctx *find_esmb_file_ctx(struct svm *svm, char *name);
extern int svm_esmb_file_get(hpa_t esmb, const char *path,
		const unsigned char *key, unsigned int key_len,
		uint8_t *file_buf, size_t *file_len);
extern void dump_fdt(void *fdt);

extern bool hv_is_LE;
extern void __noreturn svm_abort(struct refl_state *rstate);

#define svm_get_rmo_top(svm) svm->memslots.svm_rmo_top
#define svm_set_rmo_top(svm, rmo) (svm->memslots.svm_rmo_top = (rmo))

#ifndef __TEST__
static inline void cache_hv_endianness(void) {
	hv_is_LE = (mfspr(SPR_HID0) & SPR_HID0_POWER9_HILE) ? true : false;
}
#endif

#define __gfn_lock(svm, gfn) (&(svm->svm_gfn_lock[gfn & (NUM_GPF_LOCKS-1)]))
#define svm_gfn_lock(svm, gfn) lock(__gfn_lock(svm, gfn))
#define svm_gfn_unlock(svm, gfn) unlock(__gfn_lock(svm, gfn))

/*
 * Guest Page Frame(GPF) states:
 * -------------------------------------
 *
 *  A GPF can be in one of the following states:
 *
 * GPF_SHARED: the GPF is secure and is mapped to a secure-page-frame.
 *
 * GPF_PAGEDOUT: the GPF is secure but no page-frame is currently mapped.
 *
 * GPF_HV_SHARING: the GPF is initiated for sharing. A request to share is
 * currently pending with the hypervisor.
 *
 * GPF_HV_SHARED: the GPF is initiated for sharing. The hypervisor has
 * confirmed the share request, and has offered a normal-page-frame for
 * mapping.  However that page is not yet mapped, because the Ultravisor is
 * waiting on some other internal conditions to be satisfied before mapping it
 * in. In most cases the ultravisor waits for all the other GPFs to be
 * confirmed as shared by the hypervisor, before bulk moving them all to this
 * state.
 *
 * GPF_HV_SHARED_INV: The GPF is acknowledged by HV as a shared page frame, and
 * UV is waiting for some internal conditions to be satisfied. But the
 * hypervisor has invalidated and recalled the normal-page-frame that it had
 * earlier offered for mapping.
 *
 * GPF_SHARED_EXPLICIT: Both the HV and UV confirm that the GPF is a
 * shared-page-frame, and a normal-page-frame is mapped to that GPF address.
 * BTW: The SVM is aware that this GPF is shared.
 *
 * GPF_SHARED_EXPLICIT_INV: Both the HV and UV confirm that the GPF is shared,
 * but the normal-page-frame associated with the GPF is invalidated. BTW: the
 * SVM is also aware that this GPF is shared.
 *
 * GPF_SHARED_IMPLICIT: Both the HV and UV confirm that the GPF is shared, and
 * a normal-page is mapped to that GPF. The SVM is NOT aware that the GPF is
 * shared. (this is possible for RTAS pages that are shared with the
 * hypervisor, by the ultravisor. The SVM is told that those GPAs are reserved
 * and should not be used).
 *
 * GPF_SHARED_IMPLICIT_INV: Both the HV and UV confirm that the GPF is shared,
 * but the normal-page associated with the GPF is invalidated. The SVM is not
 * NOT aware that the GPF is shared.
 *
 * GPF_PSEUDO_SHARED: Both the HV and UV confirm that the GPF is shared.
 * However ultravisor continues to map the secure-page-frame, to the GPF
 * address in the page table.  The normal-page-frame; provided by the
 * hypervisor, is noted down in the gpfpage datastructure. According the SVM
 * this GPF is secure.  According to HV the GPF is shared. According to UV it
 * is both.
 *
 * GPF_PSEUDO_SHARED_INV: Both the HV and UV confirm that the GPF is shared.
 * However ultravisor continues to map the secure-page-frame, to the GPF
 * address in the page table.  No normal-page-frame is noted down in the
 * gpfpage datastructure. According to SVM this GPF is secure.  According to HV
 * the GPF is shared. According to UV it is both.
 *
 * GPF_HV_UNSHARING: the shared GPF is initiated to be unshared. A request to
 * unshare is currently pending with the hypervisor. NOTE: only explicitly
 * shared GFPs can be unshared, and hence can transition to this state.
 * Implicitly shared GPFs are never be unshared. They continue to be shared
 * till the SVM terminates.
 *
 * GPF_HV_UNSHARING_INV: the shared GPF is initiated to be unshared. A request
 * to unshare is currently pending with the hypervisor. The hypervisor however
 * thinks that the GPF is shared, and has invalidate the shared page.
 *
 * GPF_HV_UNSHARED: the shared GPF is initiated to be unshared. The hypervisor
 * has confirmed that the page is now unshared. However the Ultravisor is
 * waiting on some internal conditions to be satisfied before unmapping that
 * normal-page-frame from the GPF-address.  In most cases the ultravisor waits
 * for all the other GPFs to be confirmed as shared by the hypervisor, before
 * bulk moving them all to this state.
 */
enum gpf_state {

	GPF_SECURE 		= 0, /* secure. the default value 	 */

	GPF_PAGEDOUT		= 1,  /* a GPF_SECURE is paged out */

	GPF_SHARED 		= 2,  /* shared. Explicitly shared by SVM.*/

	GPF_SHARED_INV		= 3, /* shared. but the page is invalidated*/

	GPF_SHARED_IMPLICIT	= 4, /* Shared. Implicitly shared by
					Ultravisor.  SVM does not know about
					it.  Cannot be unshared explicitly by
					SVM. */

	GPF_SHARED_IMPLICIT_INV	= 5, /* It is a implicitly shared page.  But
					the page is invalidated	*/

      /*
       * NOTE, a GPF that is shared or unshared with HV, does not necessarily
       * mean it is so in the UV. The GPF will be committed only when all the
       * GPFs of the transactions are committed.
       */

	GPF_HV_SHARING		= 6, /* sharing with HV initiated. (transitent
					state) 	*/

	GPF_HV_SHARED		= 7, /* shared with HV, but not committed yet
					in UV 	*/

	GPF_HV_SHARED_INV	= 8, /* shared with HV, and HV invalidates the
					page even before the ultravisor has
					commited the page as shared */

	GPF_HV_UNSHARING 	= 9, /* unsharing with HV initiated.
					 (transitent state) */

	GPF_HV_UNSHARING_INV 	= 10, /* unsharing with HV initiated. But
					 hypervisor thinks it is still shared
					 and invalidates it   */

	GPF_HV_UNSHARED		= 11, /* unshared from HV, but not committed
					 yet in UV 	*/

	GPF_PSEUDO_SHARED	= 12, /* Its a secure page. However hypervisor
					thinks it is a shared page.  */

	GPF_PSEUDO_SHARED_INV	= 13, /* Its a pseudo_shared page, but the page
					is invalidated */

};

#define state_stringify(state) (\
  (state == GPF_SECURE) ? "GPF_SECURE" : \
  (state == GPF_PAGEDOUT) ? "GPF_PAGEDOUT": \
  (state == GPF_SHARED) ? "GPF_SHARED_EXPLICIT": \
  (state == GPF_SHARED_INV) ?  "GPF_SHARED_EXPLICIT_INVALIDATED": \
  (state == GPF_PSEUDO_SHARED) ? "GPF_PSEUDO_SHARED": \
  (state == GPF_PSEUDO_SHARED_INV) ? "GPF_PSEUDO_SHARED_INVALIDATED": \
  (state == GPF_SHARED_IMPLICIT) ? "GPF_SHARED_IMPLICIT": \
  (state == GPF_SHARED_IMPLICIT_INV) ?  "GPF_SHARED_IMPLICIT_INVALIDATED": \
  (state == GPF_HV_SHARING) ? "GPF_HV_SHARING": \
  (state == GPF_HV_SHARED) ? "GPF_HV_SHARED": \
  (state == GPF_HV_SHARED_INV) ?  "GPF_HV_SHARED_INVALIDATED": \
  (state == GPF_HV_UNSHARING) ?  "GPF_HV_UNSHARING": \
  (state == GPF_HV_UNSHARING_INV) ?  "GPF_HV_UNSHARING_INVALIDATED": \
  (state == GPF_HV_UNSHARED) ? "GPF_HV_UNSHARED" : "")

/*
 *  GPF operations:
 *  --------------
 *
 *  Share:  Share the GPF with the hypervisor.
 *
 *  Unshare: Unshare a shared GPF from the hypervisor.
 *
 *  Invalidate: Invalidate the page associated with the GPF.
 *
 *  Page-in:  Move the page frame associated with the GPF from normal-page to
 *  secure-page.
 *
 *  Page-out:  Move the page frame associated with the GPF from
 *  secure-page-frame to a normal-page-frame. NOTE: Data in the normal
 *  page-frame is encrypted.
 *
 *  GPF state diagram:
 *  ------------------
 * Below is the state transition diagram of a Guest Page Frame Address(GPF).
 *------------------------------------------------------------------------------
 *|  Operation->| share  | unshare| invalidate | page-in  | page-out| Internal |
 *|             |        |        |            |          |         | condition|
 *|   GPF |state|        |        |            |          |         | satisfied|
 *|       V     |        |        |            |          |         | in UV    |
 *------------------------------------------------------------------------------
 *| SECURE      |HV_SHAR | SECURE |   Error    |  Error   | PAGEDOUT|  SECURE  |
 *|             |RING    |        |            |          |         |          |
 *------------------------------------------------------------------------------
 *| PAGEDOUT    |HV_SHAR |PAGEDOUT|   Error    |  SECURE  | PAGEDOUT|  PAGEDOUT|
 *|             |RING    |        |            |          |         |          |
 *------------------------------------------------------------------------------
 *| HV_SHARING  |Error   | Error  |   Error    | HV_SHARED| Error   |HV_SHARING|
 *------------------------------------------------------------------------------
 *| HV_SHARED   |Error   | Error  |  HV_SHARED | Error    | Error   |  SHARED  |
 *|             |        |        |  _INV      |          |         |          |
 *------------------------------------------------------------------------------
 *| HV_SHARED   |Error   | Error  | HV_SHARED_ | HV_SHARED| Error   |SHARED_INV|
 *| _INV        |        |        |   INV      |          |         |          |
 *------------------------------------------------------------------------------
 *| SHARED      |SHARED  |HV_UNSHA|  SHARED_INV| SHARED   | Error   |SHARED_INV|
 *|             |        |RING    |            |          |         |          |
 *-----------------------------------------------------------------------------|
 *| SHARED_INV  |SHARED_ |HV_UNSHA|  SHARED    | SHARED   | Error   |SHARED_INV|
 *|             |INV     |RING_INV|            |          |         |          |
 *-----------------------------------------------------------------------------|
 *| SHARED_IMP  |SHARED_ | Error  |SHARED_     |SHARED_IM |Error    |SHARED_IMP|
 *|  LICIT      |IMPLICIT|        |_IMPLICT_INV| PLICIT   |         |LICIT     |
 *------------------------------------------------------------------------------
 *| SHARED_IMP  |SHARED_ | Error  |SHARED_IMPLI|SHARED_IMP| Error   |SHARED_IMP|
 *| LICIT_INV   |IMPLICIT|        |CIT         | LICIT    |         |LICIT_INV |
 *|             |_INV    |        |            |          |         |          |
 *-----------------------------------------------------------------------------|
 *| HV_UNSHARING|Error   | Error  |HV_UNSHARING|HV_UNSHARI| Error   |HV_UNSHAR |
 *|             |        |        |_INV        |NG        |         |ING       |
 *-----------------------------------------------------------------------------|
 *| HV_UNSHARING|Error   | Error  |HV_UNSHARING|HV_UNSHARI| Error   |HV_UNSHAR |
 *|  _INV       |        |        |_INV        |NG        |         | ING_INV  |
 *------------------------------------------------------------------------------
 *|PSEUDO_SHARED|PSEUDO_ | Error  |PSEUDO_     |PSEUDO_   | Error   |PSEUDO_   |
 *|             |SHARED_ |        |SHARED_INV  |SHARED    |         |SHARED    |
 *------------------------------------------------------------------------------
 *|PSEUDO_SHARED|PSEUDO_ | Error  |PSEUDO_     |PSEUDO_   | Error   |PSEUDO_   |
 *|_INV         |SHARED_ |        |_SHARED_INV |SHARED    |         |SHARED    |
 *|             |_INV    |        |            |          |         |          |
 *------------------------------------------------------------------------------
 *| HV_UNSHARED |Error   | Error  | Error      | Error    | Busy/   |HV_UNSHAR |
 *|             |        |        |            |          |   retry |ED        |
 *------------------------------------------------------------------------------
 * NOTE: State names in the above table are shortened by deleting the GPF
 * prefix, to fit the column size.
 *
 * 'Error' means the state of the GPF will remain the same, but the operation
 * returns with an error.
 *
 * 'Busy/Retry' means the sate of the GPF will remain the same, the operation
 * returns with U_RETRY.
 *
 *  In the case of SHARED_INV  and SHARED_IMPLICIT_INV  the pte entry is
 *  invalidated.
 *
 *  In the case of GPF_PSEUDO_SHARED_INV the pte entry continues to be
 *  valid, the page shared by the hypervisor that was noted down in the
 *  gpfpage_opaque, is now unnoted.
 *
 *  When in PAGEDOUT state, the gpfpage_opaque contains the address of opaque
 *  handle. Hint: this opaque handle may contain the encryption/decryption keys
 *  or anything the caller chooses to store and retrieve.
 *
 * Life cycle of a guest page frame:
 *
 * When a GPF is requested to be shared, a gpfpage is created and it enters
 * GPF_HV_SHARING state.  When the HV confirms and offers a normal-page-frame,
 * the GPF enter GPF_HV_SHARED state. It is moved to GPF_SHARED state only when
 * the UV has ensured that every other constraints are met. Eg: in the case of
 * bulk GPF sharing, it may wait for confirmation from HV for all other GPFs,
 * as shared.
 *
 * Generally GPFs are shared when the SVM makes a explicit request to share
 * them, through a UV_PAGE_SHARE ucall. Such GPFs will have normal-page-frames
 * mapped.  Such GPFs are marked as SHARED_EXPLICIT.
 *
 * In some cases the ultravisor decides to share some of the SVM's GPF without
 * the SVM's knowledge. Such GPF will also have normal-page-frames mapped.
 * However these GPFs are marked as SHARED_IMPLICIT. These GPFs cannot be
 * unshared by the SVM.  They can never be unshared for the life of the SVM.
 *
 * A GPF_SHARED GPF can transition back to GPF_SECURE. This can happen when the
 * SVM requests that GPF to be unshared.  When unshare is initiated the GPF is
 * marked as GPF_HV_UNSHARING. When the HV confirms the request, the GPF is
 * marked as GPF_HV_UNSHARED. It is moved to GPF_SECURE state only when UV has
 * ensured that every other constraints are met.  Eg: in the case of bulk GPF
 * sharing, it may wait for confirmation from HV for all other GPFs, as secure.
 *
 * A GPF_SECURE GPF can receive a pageout request, through UV_PAGEOUT ucall.
 * The content of the secure-page-frame is encrypted and copied into
 * normal-page-frame. The state of the GPF moves to GPF_PAGEDOUT.  A page-in
 * request on that GPF; through UV_PAGE_IN, copies the decrypted content of the
 * normal-page-frame back into the secure-page-frame. The GPF is moved to
 * GPF_SECURE state.
 *
 * When in any of the above states, except GPF_SECURE, the
 * ->gpfpage_opaque contains some information.  GPF_PAGEDOUT will contain some
 *  information related to encryption/decryption.
 *  GPF_SHARED_IMPLICIT/GPF_SHARE_EXPLCITY/GPF_HV_* will contain the address of
 *  the secure-page-frame that was originally assigned to that GPF.
 *  GPF_PSEUDO_SHARED the address of the normal-page sent to it by the
 *  hypervisor.
 *
 * Only GPFs that are in
 * GPF_SHARED_IMPLICIT/GPF_SHARE_EXPLCIT/GPF_PSEUDO_SHARED state, can receive a
 * invalidate request from the hypervisor. When invalidated the GPFs goes to
 * GPF_SHARED_IMPLICIT_INV, GPG_SHARED_EXPLCIT_INV state GPF_PSEUDO_SHARED_INV
 * state respectively.
 *
 * A pagein request on such pages will bring those GPFs back to their
 * non-invalidated state.
 */

#define SVM_GPF_TRANSIENT(state) (state == GPF_HV_SHARING || \
			 state == GPF_HV_SHARED || \
			 state == GPF_HV_SHARED_INV || \
			 state == GPF_HV_UNSHARED || \
			 state == GPF_HV_UNSHARING_INV || \
			 state == GPF_HV_UNSHARING)

#define SVM_GPF_SHARED(state) (state == GPF_SHARED || \
			 state == GPF_SHARED_INV || \
			 state == GPF_SHARED_IMPLICIT || \
			 state == GPF_SHARED_IMPLICIT_INV || \
			 state == GPF_PSEUDO_SHARED || \
			 state == GPF_PSEUDO_SHARED_INV)

#define SVM_GPF_UNSHARABLE(state) (state == GPF_SHARED_IMPLICIT || \
			 state == GPF_PSEUDO_SHARED || \
			 state == GPF_SHARED_IMPLICIT_INV || \
			 state == GPF_PSEUDO_SHARED_INV)

#define SVM_GPF_SECURE(state) (state == GPF_SECURE || \
			 state == GPF_PAGEDOUT)

struct gpfpage {
	enum gpf_state gpfpage_state;
	void *gpfpage_opaque;
};

#ifndef __TEST__
/*
 * retrieve the gpfpage for the GPF. Create and return one,
 * if one does not exist.
 */
static inline struct gpfpage *svm_get_gpfpage(struct svm *svm,
						enum gpf_state gfn, bool alloc)
{
	struct gpfpage *gpfpage =
		(struct gpfpage *)svm_pagemap_load(&svm->svm_pagemap, gfn);

	if (gpfpage || !alloc)
		return gpfpage;

	gpfpage = (struct gpfpage *)zalloc(sizeof(struct gpfpage));

	if (!gpfpage) {
		prlog(PR_EMERG, "%s allocation failure Can't operate \n",
				__func__);
		return NULL;
	}

	svm_pagemap_store(&svm->svm_pagemap, gfn,
			(struct svm_page_info *)gpfpage);
	return gpfpage;
}


/**
 * @brief: If the gfn is secure, just cleanup the gfppage for that gfn; if
 * one exists.  REMINDER: A pagedout gfn, is also considered a secure gfn.
 *
 * If the gfn is not a secure gfn, than re-instate the original secure-page
 * into the pagetable. The original secure-page address is stored in the
 * gfppage for that gfn; which can be retreived through svm_gfn_get_data().
 */
static inline void svm_free_gpfpage(struct svm *svm, gfn_t gfn)
{
	struct gpfpage *gpfpage;

	gpfpage = (struct gpfpage *)svm_pagemap_load(&svm->svm_pagemap, gfn);
	if (!gpfpage)
		return;

	(void)svm_pagemap_del(&svm->svm_pagemap, gfn);

	if (gpfpage->gpfpage_state == GPF_PAGEDOUT && gpfpage->gpfpage_opaque)
		free(gpfpage->gpfpage_opaque);

	free(gpfpage);
	return;
}

static inline enum gpf_state svm_get_gfn_state(struct svm *svm, gfn_t gfn)
{
	struct gpfpage *gpfpage = svm_get_gpfpage(svm, gfn, 0);
	if (!gpfpage) /* by default all pages are secure */
	       return GPF_SECURE;
	return gpfpage->gpfpage_state;
}

static inline void svm_xxx_gfn_handle(struct svm *svm, gfn_t gfn,
				enum gpf_state flag, void *handle)
{
	struct gpfpage *gpfpage = svm_get_gpfpage(svm, gfn, 1);

	gpfpage->gpfpage_state = flag;
	if (handle)
		gpfpage->gpfpage_opaque = handle;
}

/*
 * a gfn that is paged out is always a SECURE page. In other words,
 * only secure-pages can be paged out.
 */
static inline void svm_pagedout_gfn(struct svm *svm, gfn_t gfn,
			void *handle)
{
	svm_xxx_gfn_handle(svm, gfn, GPF_PAGEDOUT, handle);
}

static inline void svm_hv_shared_gfn(struct svm *svm,
			enum gpf_state gfn, void *handle)
{
	svm_xxx_gfn_handle(svm, gfn, GPF_HV_SHARED, handle);
}

static inline void svm_hv_shared_invalidate_gfn(struct svm *svm,
		enum gpf_state gfn, void *handle)
{
	svm_xxx_gfn_handle(svm, gfn, GPF_HV_SHARED_INV, handle);
}

static inline void svm_pseudoshared_gfn(struct svm *svm,
			enum gpf_state gfn, void *handle)
{
	svm_xxx_gfn_handle(svm, gfn, GPF_PSEUDO_SHARED, handle);
}

static inline void svm_pseudoshared_invalidate_gfn(struct svm *svm,
			enum gpf_state gfn, void *handle)
{
	svm_xxx_gfn_handle(svm, gfn, GPF_PSEUDO_SHARED_INV, handle);
}

static void svm_xxx_gfn(struct svm *svm, gfn_t gfn, enum gpf_state flag)
{
	struct gpfpage *gpfpage = svm_get_gpfpage(svm, gfn, 1);

	gpfpage->gpfpage_state = flag;
}

static inline void svm_shared_explicit_gfn(struct svm *svm,
			enum gpf_state gfn, void *handle)
{
	if (handle)
		svm_xxx_gfn_handle(svm, gfn, GPF_SHARED, handle);
	else
		svm_xxx_gfn(svm, gfn, GPF_SHARED);
}

static inline void svm_shared_implicit_gfn(struct svm *svm,
			enum gpf_state gfn, void *handle)
{
	if (handle)
		svm_xxx_gfn_handle(svm, gfn, GPF_SHARED_IMPLICIT, handle);
	else
		svm_xxx_gfn(svm, gfn, GPF_SHARED_IMPLICIT);
}

static inline void svm_hv_unsharing_gfn(struct svm *svm,
			enum gpf_state gfn)
{
	svm_xxx_gfn(svm, gfn, GPF_HV_UNSHARING);
}

static inline void svm_shared_explicit_invalidate_gfn(struct svm *svm,
			enum gpf_state gfn)
{
	svm_xxx_gfn(svm, gfn, GPF_SHARED_INV);
}

static inline void svm_shared_implicit_invalidate_gfn(struct svm *svm,
			enum gpf_state gfn)
{
	svm_xxx_gfn(svm, gfn, GPF_SHARED_IMPLICIT_INV);
}

static inline void svm_hv_sharing_gfn(struct svm *svm,
			enum gpf_state gfn)
{
	svm_xxx_gfn(svm, gfn, GPF_HV_SHARING);
}

static inline void svm_hv_unsharing_invalidate_gfn(struct svm *svm,
			enum gpf_state gfn)
{
	svm_xxx_gfn(svm, gfn, GPF_HV_UNSHARING_INV);
}

static inline void svm_hv_unshared_gfn(struct svm *svm,
			enum gpf_state gfn)
{
	svm_xxx_gfn(svm, gfn, GPF_HV_UNSHARED);
}

static inline void *svm_gfn_get_data(struct svm *svm, gfn_t gfn)
{
	struct gpfpage *gpfpage = svm_get_gpfpage(svm, gfn, 0);

	if (gpfpage)
		return gpfpage->gpfpage_opaque;

	return NULL;
}

static inline void svm_gfn_release_data(struct svm *svm, gfn_t gfn)
{
	struct gpfpage *gpfpage = svm_get_gpfpage(svm, gfn, 0);

	if (gpfpage)
		gpfpage->gpfpage_opaque = NULL;
}

static inline void svm_secure_gfn(struct svm *svm, gfn_t gfn, bool zero)
{
	void *addr;
	enum gpf_state state = svm_get_gfn_state(svm, gfn);

	if (state == GPF_SECURE || \
		state == GPF_PAGEDOUT || \
		state == GPF_PSEUDO_SHARED_INV || \
		state == GPF_PSEUDO_SHARED)
		goto out;

	addr = svm_gfn_get_data(svm, gfn);
	if (!addr) {
		pr_warn("%s Secure page address unavailable\n", __func__);
		goto out;
	}

	if (zero)
		memset((void *)addr, 0, SVM_PAGESIZE);

	setup_page(&svm->mm, svm->lpid, SVM_GFN_TO_GPA(gfn),
			(void *)addr, SVM_PAGESIZE, 0);
out:
	/*
	 * @toto: if all the pte for the pmd are secure
	 * coalesce them into a single PMD? Is it worth the effort?
	 */
	svm_free_gpfpage(svm, gfn);
	return;
}
#endif

#endif /* SVM_HOST_H */
