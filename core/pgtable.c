// SPDX-License-Identifier: GPL-2.0
/*
 * Page Table setup
 *
 * Copyright 2018 IBM Corp.
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
#include <ppc-opcode.h>
#include <bitmap.h>
#include <pgtable.h>
#include <tlbflush.h>
#include <svm_host.h>

/*
 * partition table and process table for ISA 3.0
 */
struct prtb_entry *process_tb;
struct patb_entry *partition_tb;

u32 mmu_pid_bits;
u32 mmu_base_pid;

int (*register_process_table)(u64 base, u64 page_size, u64 tbl_size);

static int __pud_alloc(pgd_t *pgd);
static int __pmd_alloc(pud_t *pud);

void mmu_partition_table_set_entry(u32 lpid, u64 dw0, u64 dw1)
{
	u64 old = be64_to_cpu(partition_tb[lpid].patb0);

	partition_tb[lpid].patb0 = cpu_to_be64(dw0);
	partition_tb[lpid].patb1 = cpu_to_be64(dw1);

	/*
	 * Global flush of TLBs and partition table caches for this lpid.
	 * The type of flush (hash or radix) depends on what the previous
	 * use of this partition ID was, not the new use.
	 */
	asm volatile("ptesync" : : : "memory");
	if (old & PATB_HR) {
		asm volatile(PPC_TLBIE_5(%0,%1,2,0,1) : :
				"r" (TLBIEL_INVAL_SET_LPID), "r" (lpid));
		asm volatile(PPC_TLBIE_5(%0,%1,2,1,1) : :
				"r" (TLBIEL_INVAL_SET_LPID), "r" (lpid));
	} else {
		asm volatile(PPC_TLBIE_5(%0,%1,2,0,0) : :
				"r" (TLBIEL_INVAL_SET_LPID), "r" (lpid));
	}
	asm volatile("eieio; tlbsync; ptesync" : : : "memory");
}

void mmu_partition_table_set_dw0(u32 lpid, u64 dw0)
{
	u64 dw1 = be64_to_cpu(partition_tb[lpid].patb1);
	mmu_partition_table_set_entry(lpid, dw0, dw1);
}

void mmu_partition_table_set_dw1(u32 lpid, u64 dw1)
{
	u64 dw0 = be64_to_cpu(partition_tb[lpid].patb0);
	mmu_partition_table_set_entry(lpid, dw0, dw1);
}

static void mmu_partition_table_init(void)
{
	u64  patb_size = 1UL << PATB_SIZE_SHIFT;
	u64  ptcr;

	partition_tb = memalign(patb_size, patb_size);

	memset(partition_tb, 0, patb_size);

	ptcr = __pa(partition_tb) | (PATB_SIZE_SHIFT - 12);
	pr_notice("[%s]: Setting ptcr to 0x%llx\n", __func__, ptcr);
	mtspr(SPR_PTCR, ptcr);
}

static void radix_init_partition_table(void)
{
	mmu_partition_table_init();

	pr_notice("Initializing Radix MMU\n");
	pr_notice("Partition table %p\n", partition_tb);
}

void radix__early_init_mmu(void)
{
	u64 lpcr;

	lpcr = mfspr(SPR_LPCR);
	mtspr(SPR_LPCR, lpcr | SPR_LPCR_P9_UPRT | SPR_LPCR_P9_HR);

	radix_init_partition_table();
}

void radix__early_init_mmu_secondary(void)
{
	u64 lpcr;
	u64 ptcr;

	lpcr = mfspr(SPR_LPCR);
	mtspr(SPR_LPCR, lpcr | SPR_LPCR_P9_UPRT | SPR_LPCR_P9_HR);

	ptcr = __pa(partition_tb) | (PATB_SIZE_SHIFT - 12);
	pr_notice("[%s]: Setting ptcr to 0x%llx\n", __func__, ptcr);
	mtspr(SPR_PTCR, ptcr);
}

#define PTRS_PER_PTE	(1 << RADIX_PTE_INDEX_SIZE)
#define PTRS_PER_PMD	(1 << RADIX_PMD_INDEX_SIZE)
#define PTRS_PER_PUD	(1 << RADIX_PUD_INDEX_SIZE)
#define PTRS_PER_PGD	(1 << RADIX_PGD_INDEX_SIZE)

/* PMD_SHIFT determines what a second-level page table entry can map */
#define PMD_SHIFT	(PAGE_SHIFT + RADIX_PTE_INDEX_SIZE)
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))

/* PUD_SHIFT determines what a third-level page table entry can map */
#define PUD_SHIFT	(PMD_SHIFT + RADIX_PMD_INDEX_SIZE)
#define PUD_SIZE	(1UL << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE-1))

/* PGDIR_SHIFT determines what a fourth-level page table entry can map */
#define PGDIR_SHIFT	(PUD_SHIFT + RADIX_PUD_INDEX_SIZE)
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))

/* Bits to mask out from a PMD to get to the PTE page */
#define PMD_MASKED_BITS		0xc0000000000000ffUL
/* Bits to mask out from a PUD to get to the PMD page */
#define PUD_MASKED_BITS		0xc0000000000000ffUL
/* Bits to mask out from a PGD to get to the PUD page */
#define PGD_MASKED_BITS		0xc0000000000000ffUL

#define pmd_page_vaddr(x)	__va((x).pmd & ~PMD_MASKED_BITS)
#define pud_page_vaddr(x)	__va((x).pud & ~PUD_MASKED_BITS)
#define pgd_page_vaddr(x)	__va((x).pgd & ~PGD_MASKED_BITS)

#define pgd_index(address) (((address) >> (PGDIR_SHIFT)) & (PTRS_PER_PGD - 1))
#define pud_index(address) (((address) >> (PUD_SHIFT)) & (PTRS_PER_PUD - 1))
#define pmd_index(address) (((address) >> (PMD_SHIFT)) & (PTRS_PER_PMD - 1))
#define pte_index(address) (((address) >> (PAGE_SHIFT)) & (PTRS_PER_PTE - 1))

#define __pgtable_ptr_val(ptr)	__pa(ptr)

#define	HUGE_PAGE_SIZE (1ul << PMD_SHIFT)

/*
 * Find an entry in a page-table-directory.  We combine the address region
 * (the high order N bits) and the pgd portion of the address.
 */

#define pgd_offset(mm, address)	 ((mm)->pgd + pgd_index(address))
#define pud_offset(pgdp, addr)	\
	(((pud_t *) pgd_page_vaddr(*(pgdp))) + pud_index(addr))
#define pmd_offset(pudp,addr) \
	(((pmd_t *) pud_page_vaddr(*(pudp))) + pmd_index(addr))
#define pte_offset(dir,addr) \
	(((pte_t *) pmd_page_vaddr(*(dir))) + pte_index(addr))

static inline void pgd_populate(pgd_t *pgd, pud_t *pud)
{
	pgd->pgd = __pgtable_ptr_val(pud) | RADIX_PGD_VAL_BITS;
}

/* Inverse of pgd_populate */
static inline void *pgd_ptr(pgd_t *pgd)
{
	return (void *)(pgd->pgd & ~RADIX_PGD_VAL_BITS);
}

static inline void pud_populate(pud_t *pud, pmd_t *pmd)
{
	pud->pud = __pgtable_ptr_val(pmd) | RADIX_PUD_VAL_BITS;
}

/* Inverse of pud_populate */
static inline void *pud_ptr(pud_t *pud)
{
	return (void *)(pud->pud & ~RADIX_PUD_VAL_BITS);
}

static inline void pmd_populate(pmd_t *pmd, pte_t* pte)
{
	pmd->pmd = __pgtable_ptr_val(pte) | RADIX_PMD_VAL_BITS;
}

/* Inverse of pmd_populate */
static inline void *pmd_ptr(pmd_t *pmd)
{
	return (void *)(pmd->pmd & ~RADIX_PMD_VAL_BITS);
}

static inline bool pgd_present(pgd_t pgd)
{
	return pgd.pgd;
}

static inline bool pud_present(pud_t pud)
{
	return pud.pud;
}

static inline bool pmd_present(pmd_t pmd)
{
	return pmd.pmd;
}

static inline bool pte_present(pte_t pte)
{
	return pte.pte & _PAGE_PRESENT;
}

static inline bool pgtable_leaf(u64 entry)
{
	return entry & _PAGE_PTE;
}

static inline unsigned long pgtable_pfn(u64 entry)
{
	return (entry & PTE_RPN_MASK) >> PAGE_SHIFT;
}

static inline pgprot_t pgtable_pgprot(u64 entry)
{
	return __pgprot(entry & PAGE_PROT_BITS);
}

static inline bool pte_shared(pte_t pte)
{
	return pte.pte & _PAGE_SOFT_SHARED;
}

static pmd_t mk_pmd(void *addr, pgprot_t pgprot)
{
	unsigned long pmdv;
	pmd_t pmd;

	pmdv = (unsigned long) addr & PTE_RPN_MASK;
	pmd.pmd = pmdv | pgprot.pgprot;
	return pmd;
}

static pte_t mk_pte(void *addr, pgprot_t pgprot)
{
	pte_t out;

	out.pte = ((unsigned long) addr & PTE_RPN_MASK);
	out.pte |= _PAGE_PTE | pgprot.pgprot;
	return out;
}

static void *pte_page(pte_t *pte)
{
	return (void *)(pte->pte & ~(PAGE_PROT_BITS|_PAGE_PTE));
}

/*
 * mk_pte(NULL, prot) has a side-effect of setting _PAGE_PTE bit. So
 * define a way to clear the pte (as if it was just allocated/zeroed).
 */
static void clear_pte(pte_t *pte)
{
	pte->pte = 0ULL;
}

static pte_t mk_nopte(pte_t *pte)
{
	pte_t out;
	out.pte = pte->pte & ~_PAGE_PRESENT;
	return out;
}

static inline pte_t mk_normalpte(pte_t *in)
{
	pte_t out;
	pgprot_t pgprot = PAGE_NORMAL_X;

	out.pte = in->pte | pgprot.pgprot;
	out.pte &= ~_PAGE_INVALID;
	return out;
}

static inline pmd_t radix__pmd_mkhuge(pmd_t pmd)
{
	pmd.pmd |= _PAGE_PTE;
	return pmd;
}

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t *new;
	size_t pgd_size = sizeof(pgd_t) << RADIX_PGD_INDEX_SIZE;

	new = memalign(pgd_size, pgd_size);
	mm->pgd = new;
	if (new)
		memset(new, 0, pgd_size);
	return new;
}

/*
 * Allocate page upper directory.
 */
static int __pud_alloc(pgd_t *pgd)
{
	size_t pud_size = sizeof(pud_t) << RADIX_PUD_INDEX_SIZE;
	pud_t *new = memalign(pud_size, pud_size);
	if (!new)
		return -ENOMEM;

	memset(new, 0, pud_size);
	pgd_populate(pgd, new);
	return 0;
}

/*
 * Allocate page middle directory.
 */
static int __pmd_alloc(pud_t *pud)
{
	size_t pmd_size = sizeof(pmd_t) << RADIX_PMD_INDEX_SIZE;
	pmd_t *new = memalign(pmd_size, pmd_size);
	if (!new)
		return -ENOMEM;

	memset(new, 0, pmd_size);
	pud_populate(pud, new);
	return 0;
}

static int __pte_alloc(pmd_t *pmd)
{
	size_t pte_size = sizeof(pte_t) << RADIX_PTE_INDEX_SIZE;
	pte_t *new = memalign(pte_size, pte_size);
	if (!new)
		return -ENOMEM;

	memset(new, 0, pte_size);
	pmd_populate(pmd, new);
	return 0;
}

static int __pmd_split(pmd_t *pmdp, gpa_t gpa, struct tlb_flush *tlbf)
{
	u64 i;
	pte_t *pte, *new;
	pmd_t pmd;

        u64 pmd_entry = pmdp->pmd;
	unsigned long s_pfn = pgtable_pfn(pmd_entry);
	pgprot_t pgprot = pgtable_pgprot(pmd_entry);
	void *s_page;

	if (__pte_alloc(&pmd))
		return -ENOMEM;

	new = pmd_ptr(&pmd);

	__radix_pte_update((pte_t *)pmdp, _PAGE_PRESENT, _PAGE_INVALID);
	if (tlbf)
		_tlbie_lpid_gpa(gpa & PMD_MASK, tlbf->lpid,
				MMU_PAGE_2M, RIC_FLUSH_TLB);

	for (i = 0; i < PTRS_PER_PTE; i++) {
		s_page = (void *)((s_pfn + i) << PAGE_SHIFT);
		pte = new + i;
		*pte = mk_pte(s_page, pgprot);
	}
	__radix_pte_update((pte_t *)pmdp, ~0ul, (u64)pmd.pmd);

	return 0;
}

static inline pud_t *pud_alloc(pgd_t *pgd, unsigned long address)
{
	return (!pgd_present(*pgd) && __pud_alloc(pgd)) ?
		NULL : pud_offset(pgd, address);
}

static inline pmd_t *pmd_alloc(pud_t *pud, unsigned long address)
{
	return (!pud_present(*pud) && __pmd_alloc(pud)) ?
		NULL : pmd_offset(pud, address);
}

static inline pte_t *pte_alloc(pmd_t *pmd, unsigned long address,
		struct tlb_flush *tlbf)
{
	/* Split it if it is a pmd page. */
	if (pgtable_leaf(pmd->pmd) && __pmd_split(pmd, address, tlbf))
		return NULL;

	if (!pmd_present(*pmd) && __pte_alloc(pmd))
		return NULL;

	return pte_offset(pmd, address);
}

static int setup_pmd_page(struct mm_struct *mm, unsigned long address,
			  pgprot_t pgprot)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pmd_t entry;
	size_t alloc_size;
	void *page;

	pgd = pgd_offset(mm, address);

	pud = pud_alloc(pgd, address);
	if (!pud)
		return -ENOMEM;

	pmd = pmd_alloc(pud, address);
	if (!pmd)
		return -ENOMEM;

	page = alloc_uv_page(1, &alloc_size);
	if (!page)
		return -ENOMEM;

	memset(page, 0, UV_PAGE_SIZE);
	entry = radix__pmd_mkhuge(mk_pmd(page, pgprot));
	*pmd = entry;

	return 0;
}

static pte_t *get_pte(struct mm_struct *mm, unsigned long address,
		struct tlb_flush *tlbf)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, address);
	pud = pud_alloc(pgd, address);
	if (!pud)
		return NULL;

	pmd = pmd_alloc(pud, address);
	if (!pmd)
		return NULL;

	pte = pte_alloc(pmd, address, tlbf);
	if (!pte)
		return NULL;

	return pte;
}

static int setup_pte_page(struct mm_struct *mm, unsigned long address,
		   void *page, pgprot_t pgprot)
{
	pte_t *pte = get_pte(mm, address, NULL);
	if (!pte)
		return -ENOMEM;
	*pte = mk_pte(page, pgprot);
	return 0;
}

// Setup a range of pte pages within the same pmd.
static int setup_pte_range(struct mm_struct *mm, unsigned long start,
			   unsigned long end, pgprot_t pgprot)
{
	size_t alloc_size;
	void *page;
	int ret;
	if (start >= end)
		return 0;

	page = alloc_uv_page(1, &alloc_size);
	if (!page)
		return -ENOMEM;
	memset(page, 0, UV_PAGE_SIZE);
	page += start & UV_PAGE_OFFSET_MASK;

	// Mark the parts of the page that are used.
	for (; start < end; start += PAGE_SIZE, page += PAGE_SIZE) {
		ret = setup_pte_page(mm, start, page, pgprot);
		if (ret) {
			free_uv_page(page);
			return ret;
		}
	}

	return 0;
}

static int __setup_page(struct mm_struct *mm, u64 lpid, gpa_t gpa, void *page,
			int psize, u64 flags, bool present)
{
	pte_t new_pte;
	pgprot_t pgprot = PAGE_NORMAL_X;
	struct tlb_flush tlbf;
	pte_t *ptep;

	tlbf.lpid = lpid;
	tlbf.gpa = gpa;
	ptep = get_pte(mm, gpa, &tlbf);

	if (!ptep)
		return -ENOMEM;

	pgprot.pgprot |= flags;
	__radix_pte_update(ptep, _PAGE_PRESENT, _PAGE_INVALID);

	new_pte = mk_pte(page, pgprot);
	if (!present)
		new_pte = mk_nopte(&new_pte);

	_tlbie_lpid_gpa(gpa, lpid, radix_get_mmu_psize(psize),
			RIC_FLUSH_TLB);
	__radix_pte_update(ptep, ~0ul, new_pte.pte);
	return 0;
}

int setup_page(struct mm_struct *mm, u64 lpid, gpa_t gpa, void *page,
			int psize, u64 flags)
{
	return __setup_page(mm, lpid, gpa, page, psize, flags, true);
}

int setup_page_notpresent(struct mm_struct *mm, u64 lpid, gpa_t gpa, void *page,
			int psize, u64 flags)
{
	return __setup_page(mm, lpid, gpa, page, psize, flags, false);
}

int setup_page_invalidate(struct mm_struct *mm, u64 lpid, gpa_t gpa, u64 psize)
{
	pte_t new_pte, old_pte;
	struct tlb_flush tlbf;
	pte_t *ptep;

	tlbf.lpid = lpid;
	tlbf.gpa = gpa;
	ptep = get_pte(mm, gpa, &tlbf);

	if (!ptep)
		return -ENOMEM;
	old_pte = __radix_pte_update(ptep, _PAGE_PRESENT, _PAGE_INVALID);
	new_pte = mk_nopte(&old_pte);
	_tlbie_lpid_gpa(gpa, lpid, radix_get_mmu_psize(psize),
			RIC_FLUSH_TLB);
	__radix_pte_update(ptep, ~0ul, new_pte.pte);
	return 0;
}

// pgd needs to be setup first: pgd_alloc(mm);
int setup_page_range(struct mm_struct *mm, unsigned long start, size_t size)
{
	unsigned long end = start + size;
	unsigned long unaligned_start = start;
	int ret;
	pgprot_t pgprot = PAGE_NORMAL_X;

	assert((start & PAGE_OFFSET_MASK) == 0);
	assert((end & PAGE_OFFSET_MASK) == 0);

	// Take care of 2M misalignment at start.
	if (start < (end & UV_PAGE_MASK)) {
		start = (start + UV_PAGE_SIZE - 1) & UV_PAGE_MASK;
		ret = setup_pte_range(mm, unaligned_start, start, pgprot);
		if (ret)
			return ret;
	}

	for (; start < (end & UV_PAGE_MASK); start += UV_PAGE_SIZE) {
		ret = setup_pmd_page(mm, start, pgprot);
		if (ret)
			return ret;
	}

	// Take care of 2M misalignment at end.
	ret = setup_pte_range(mm, start, end, pgprot);
	if (ret)
		return ret;

	asm volatile("ptesync" ::: "memory");
	return 0;
}

static inline pmd_t *get_pmd(struct mm_struct *mm, gpa_t gpa)
{
	pgd_t *pgd;
	pud_t *pud;

	pgd = pgd_offset(mm, gpa);
	if (!pgd_present(*pgd))
		return NULL;

	pud = pud_offset(pgd, gpa);
	if (!pud_present(*pud))
		return NULL;

	return pmd_offset(pud, gpa);
}

#define PAGES_PER_HUGE_PAGE (1 << RADIX_PTE_INDEX_SIZE)

/**
 * set_noaccess_range - invalidate access to a range
 * @mm : the mm descriptor
 * @lpid : the partition id
 * @max_pages : the maximum number of pages to invalidate
 * @start : the start address to invalidate
 * @end : the end address of the area
 * @next : the address of the next byte to invalidate.
 *
 * Invalidate up to @max_pages in the area between @start and @end.
 * The process is stopped when the number of invalidated pages reach @max_pages
 * or when the next page to invalidate is over @end.
 * On return @next would contain the base address of the next page to
 * invalidate.
 * The return value is the number of invalidated pages which may be higher than
 * @max_pages when the last invalidated area is a huge page.
 */
int set_noaccess_range(struct mm_struct *mm, u64 lpid, int max_pages,
		       u64 start, u64 end, u64 *next)
{
	unsigned int npages = 0;
	u32 npmd = 0, npte = 0;

	while (start < end && npages <= max_pages) {
		u64 psize = HUGE_PAGE_SIZE;
		pte_t *ptep;
		pmd_t *pmdp = get_pmd(mm, start);

		if (!pmdp || !pmd_present(*pmdp))
			goto next;

		if (pgtable_leaf(pmdp->pmd)) {
			/* Manage the huge page */
			ptep = (pte_t*) pmdp;
		}
		else {
			psize = PAGE_SIZE;
			ptep = pte_offset(pmdp, start);
			if (!ptep || !pte_present(*ptep))
				goto next;
		}

		if (!pte_shared(*ptep)) {
			if (ptep == (pte_t *)pmdp) {
				npages += PAGES_PER_HUGE_PAGE;
				npmd++;
			}
			else {
				npages++;
				npte++;
			}

			/* Clear the RWX bits in the PTE */
			_tlbie_lpid_gpa(start, lpid, radix_get_mmu_psize(psize),
					RIC_FLUSH_TLB);
			__radix_pte_update(ptep,
					   _PAGE_READ | _PAGE_WRITE | _PAGE_EXEC,
					   0ul);
		} else
			pr_numa_debug("NUMA: ignoring shared range %llx - %llx\n",
				      start, start + psize);
next:
		start += psize;
	}

	*next = start;
	return npages;
}

/*
 * Called in the page fault path for page set to PAGE_NONE.
 * Assumption is that _PAGE_PRESENT is set for this page.
 * Return the number of processes pages or -1 on error.
 */
int set_normal_page(struct mm_struct *mm, u64 lpid, gpa_t gpa)
{
	pmd_t *pmdp;
	pte_t *ptep, new_pte;
	u64 psize;

	pmdp = get_pmd(mm, gpa);
	if (!pmdp)
		return -1;

	if (pgtable_leaf(pmdp->pmd)) {
		ptep = (pte_t *) pmdp;
		psize = HUGE_PAGE_SIZE;
	}
	else {
		ptep = pte_offset(pmdp, gpa);
		if (!ptep)
			return -1;
		psize = PAGE_SIZE;
	}

	__radix_pte_update(ptep, _PAGE_PRESENT, _PAGE_INVALID);
	new_pte = mk_normalpte(ptep);
	_tlbie_lpid_gpa(gpa, lpid, radix_get_mmu_psize(psize),
			RIC_FLUSH_TLB);
	__radix_pte_update(ptep, ~0ul, new_pte.pte);
	pr_numa_debug("Set Normal %s 0x%llx - 0x%llx\n",
		      ptep == (pte_t *)pmdp ? "PMD" : "PTE", gpa, gpa + psize);

	return psize >> PAGE_SHIFT;
}

bool is_page_noaccess(struct mm_struct *mm, gpa_t gpa)
{
	pmd_t *pmdp;
	pte_t *ptep = NULL;
	u64 value;

	pmdp = get_pmd(mm, gpa);
	if (!pmdp || !pmd_present(*pmdp))
		return false;

	if (pgtable_leaf(pmdp->pmd))
		value = pmdp->pmd;
	else {
		ptep = pte_offset(pmdp, gpa);
		if (!ptep)
			return false;
		value = ptep->pte;
	}

	pr_numa_debug("is noaccess %s 0x%llx 0x%llx : %d\n",
		      (ptep) ? "PTE" : "PMD", gpa, value,
		      (int)((value  & (_PAGE_PRESENT | _PAGE_PTE |
				       _PAGE_READ | _PAGE_WRITE | _PAGE_EXEC)) ==
			    (_PAGE_PRESENT | _PAGE_PTE)));
	return (value  & (_PAGE_PRESENT | _PAGE_PTE |
			  _PAGE_READ | _PAGE_WRITE | _PAGE_EXEC)) ==
		(_PAGE_PRESENT | _PAGE_PTE);
}

#define PARTIAL_CLEANUP 1
#define SUCCESS_CLEANUP 0

static void release_page(pmd_t *pmd)
{
	unsigned long pfn;
	void *page;

	pfn = pgtable_pfn(pmd->pmd);
	page =  (void*) (pfn << PAGE_SHIFT);
	if (page == 0x0) {
		pr_error("%s(0x%lx) Ignore page %p!\n", __func__, pfn, page);
	} else {
		free_uv_page(page);
	}
	return;
}

/**
 * cleanup all the pte_t entries in the table pointed to by pmd_t
 * @mm: the mm_struct pointing to the page table.
 * @addr: is the start GPA address that pmd represents.
 * @all: if set @start to @end are ignored and the unmap all the pages mapped in
 *       the pmd.
 * @start: the GPA address starting from which the pages have to be unmapped.
 * @end: the last GPA address, prior to which pages have to be unmapped.
 * @start and @end may or may not fall in the GPA address range mapped in
 * the pmd.
 */
static int cleanup_pmd(pmd_t *pmd, u64 addr, bool all, u64 start, u64 end)
{
	pte_t *pte = NULL;
	u64 pte_addr_start = addr;
	u64 pte_addr_end = pte_addr_start + (((u64)PTRS_PER_PTE << PAGE_SHIFT));
	int count=0;
	void *page = NULL;

	/*
	 * If we failed to allocate memory when setting up pagetables,
	 * we don't have anything to do here.
	 */
	if (!pmd || !pmd->pmd)
		return SUCCESS_CLEANUP;

	if (all)
		/* Force a walk of all the entries */
		end = pte_addr_end;
	else {
		if (start > pte_addr_end || end < pte_addr_start)
			return PARTIAL_CLEANUP;
		addr = min(max(pte_addr_start, start), pte_addr_end);
	}

	for (; addr < min(end, pte_addr_end); addr += PAGE_SIZE) {
		pte = pte_offset(pmd, addr);
		if (pte) {
			if (!page)
				page = pte_page(pte);

			clear_pte(pte);
		}
		count++;
	}

	if (!all && count != PTRS_PER_PTE)
		return PARTIAL_CLEANUP;

	if (page)
		free_uv_page(page);

	free(pmd_ptr(pmd));
	return SUCCESS_CLEANUP;
}

/**
 * cleanup all the pmd_t entries in the table pointed to by pud_t
 * @mm: the mm_struct pointing to the page table.
 * @addr: is the start GPA address that pud represents.
 * @all: if set @start to @end are ignored and the unmap all the pages mapped in
 *       the pud.
 * @start: the GPA address starting from which the pages have to be unmapped.
 * @end: the last GPA address, prior to which pages have to be unmapped.
 * @start and @end may or may not fall in the GPA address range mapped in
 * the pud.
 */
static int cleanup_pud(pud_t *pud, u64 addr, bool all, u64 start, u64 end)
{
	pmd_t *pmd;
	u64 pmd_addr_start = addr;
	u64 pmd_addr_end = pmd_addr_start + (((u64)PTRS_PER_PMD) << PMD_SHIFT);
	int count=0;

	/*
	 * If we failed to allocate memory when setting up pagetables,
	 * we don't have anything to do here.
	 */
	if (!pud || !pud->pud)
		return SUCCESS_CLEANUP;

	if (all)
		/* Force a walk of all entries */
		end = pmd_addr_end;
	else {
		if (start > pmd_addr_end || end < pmd_addr_start)
			return PARTIAL_CLEANUP;
		addr = min(max(pmd_addr_start, start), pmd_addr_end);
	}

	for (; addr < min(end, pmd_addr_end); addr += PMD_SIZE) {
		pmd = pmd_offset(pud, addr);
		if (!pmd_present(*pmd))
			goto end;
		if (pgtable_leaf(pmd->pmd))
			release_page(pmd);
		else if (cleanup_pmd(pmd, addr, all,
				     start, end) == PARTIAL_CLEANUP)
			break;
		pmd->pmd = 0;
end:
		count++;
	}

	if (!all && count != PTRS_PER_PMD)
		return PARTIAL_CLEANUP;

	free(pud_ptr(pud));
	return SUCCESS_CLEANUP;
}

/**
 * cleanup all the pud_t entries in the table pointed to by pgd_t
 * @addr: is the start GPA address that pgd represents.
 * @all: if set @start to @end are ignored and the unmap all the pages mapped in
 *       the pgd.
 * @start: the GPA address starting from which the pages have to be unmapped.
 * @end: the last GPA address, prior to which pages have to be unmapped.
 * @start and @end may or may not fall in the GPA address range mapped in
 * the pgd.
 */
static int cleanup_pgd(pgd_t *pgd, u64 addr, bool all, u64 start, u64 end)
{
	pud_t *pud;
	u64 pud_addr_start = addr;
	u64 pud_addr_end = pud_addr_start + (((u64)PTRS_PER_PUD) << PUD_SHIFT);
	int count=0;

	/*
	 * If we failed to allocate memory when setting up pagetables,
	 * we don't have anything to do here.
	 */
	if (!pgd || !pgd->pgd)
		return SUCCESS_CLEANUP;

	if (all)
		end = pud_addr_end;
	else {
		if (start > pud_addr_end || end < pud_addr_start)
			return PARTIAL_CLEANUP;
		addr = min(max(pud_addr_start, start), pud_addr_end);
	}

	for (; addr < min(end, pud_addr_end); addr += PUD_SIZE) {
		pud = pud_offset(pgd, addr);
		if (!pud_present(*pud))
			goto end;
		if (cleanup_pud(pud, addr, all, start, end) == PARTIAL_CLEANUP)
			break;
		pud->pud = 0;
end:
		count++;
	}

	if (!all && count != PTRS_PER_PUD)
		return PARTIAL_CLEANUP;

	free(pgd_ptr(pgd));
	return SUCCESS_CLEANUP;
}

/*
 * cleanup all the pgd_t entries in the table pointed to by mm
 * @mm: the mm_struct pointing to the page table.
 * @all: if set @start to @end contains all the pages allocated to the @mm.
 * @start: the start gpa address.
 * @end: the end gpa address.
 */
static int cleanup_pagetable(struct mm_struct *mm, bool all, u64 start, u64 end)
{
	pgd_t *pgd;
	u64 pgd_addr_start = 0;
	u64 pgd_addr_end = ((u64)PTRS_PER_PGD) << PGDIR_SHIFT;
	u64 addr = min(max(pgd_addr_start, start), pgd_addr_end);
	int count=0;

	/*
	 * If we failed to allocate memory when setting up pagetables,
	 * we don't have anything to do here.
	 */
	if (!mm->pgd)
		return SUCCESS_CLEANUP;

	if (start > pgd_addr_end || end < pgd_addr_start)
		return PARTIAL_CLEANUP;

	for (; addr < min(end, pgd_addr_end); addr += PGDIR_SIZE) {
		pgd = pgd_offset(mm, addr);
		if (!pgd_present(*pgd))
			goto end;
		if (cleanup_pgd(pgd, addr, all, start, end) == PARTIAL_CLEANUP)
			break;
		pgd->pgd = 0;
end:
		count++;
	}

	if (!all && count != PTRS_PER_PGD)
		return PARTIAL_CLEANUP;

	free(mm->pgd);
	mm->pgd=NULL;
	return SUCCESS_CLEANUP;
}

/*
 * release all the pages and the tables associated with this page table.
 * @mm: the mm_struct pointing to the page table.
 * @all: if set @start to @end contains all the pages allocated to the @mm.
 * @start: the start gpa address.
 * @end: the end gpa address.
 */
void release_page_range(struct mm_struct *mm, bool all, u64 start, u64 end)
{
	assert((start & PAGE_OFFSET_MASK) == 0);
	assert((end & PAGE_OFFSET_MASK) == 0);

	/*
	 * @todo FIXME:
	 * Some Page Directory table's synchronization is required here,
	 * Before release the page pointed by the underlying PTE/PMD, the
	 * page table directory must be synchronized over all the CPUs so
	 * the page cannot be reused while other CPUs are having stale
	 * state. However, this has to be done in a smart way to avoid
	 * too much synchronization to be done, leading to a performance
	 * hit.
	 */

	(void) cleanup_pagetable(mm, all, start, end);

	return;
}

/* 
 * Return the host physical address of the requested guest physical address
 * @gpa.  if @present is requested, return 1 if the mapping exists; otherwise
 * return 0.
 * 
 * @todo: since this function walks the page table, ensure that it does not
 * race with any other thread modifying the page table. Currently the caller is
 * expected to serialize.  Modify the logic to serialize within the functions
 * in this file that walk the page table; thus the caller can be relieved of
 * the responsibility.
 */
void *gpa_to_addr(struct mm_struct *mm, gpa_t gpa, int *present)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	void  *ret;
	unsigned long entry;
	unsigned long pfn;

	if (present)
		*present = 0;

	pgd = pgd_offset(mm, gpa);
	if (!pgd_present(*pgd))
		return NULL;

	pud = pud_offset(pgd, gpa);
	if (!pud_present(*pud))
		return NULL;

	pmd = pmd_offset(pud, gpa);

	if (!pmd_present(*pmd))
		return NULL;

	if (pgtable_leaf(pmd->pmd)) {
		entry = pmd->pmd;
		if (pte_present(*(pte_t *)pmd) && present)
			*present = 1;
	} else {
		pte = pte_offset(pmd, gpa);
		if (pte_present(*pte) && present)
			*present = 1;
		entry = pte->pte;
	}

	pfn = pgtable_pfn(entry);
	ret =  (void*) (pfn << PAGE_SHIFT);

	if (pgtable_leaf(pmd->pmd))
		ret += (gpa & (PMD_SIZE-1));
	else
		ret += offset_in_page(gpa);

	return ret;
}
