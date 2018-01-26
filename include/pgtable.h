/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2018, IBM Corporation.
 *
 */

#ifndef PGTABLE_H
#define PGTABLE_H

#include <svm_page_alloc.h>

/* Bits to set in a RPMD/RPUD/RPGD */
#define RADIX_PMD_VAL_BITS		(0x8000000000000000UL | RADIX_PTE_INDEX_SIZE)
#define RADIX_PUD_VAL_BITS		(0x8000000000000000UL | RADIX_PMD_INDEX_SIZE)
#define RADIX_PGD_VAL_BITS		(0x8000000000000000UL | RADIX_PUD_INDEX_SIZE)

#define _PAGE_EXEC		0x00001 /* execute permission */
#define _PAGE_WRITE		0x00002 /* write access allowed */
#define _PAGE_READ		0x00004	/* read access allowed */
#define _PAGE_DIRTY		0x00080 /* C: page changed */
#define _PAGE_ACCESSED		0x00100 /* R: page referenced */
#define _PAGE_RW		(_PAGE_READ | _PAGE_WRITE | _PAGE_DIRTY | _PAGE_ACCESSED)
#define _PAGE_RWX		(_PAGE_RW | _PAGE_EXEC)
#define _PAGE_PRIVILEGED	0x00008 /* kernel access only */
#define _PAGE_SAO		0x00010 /* Strong access order */
#define _PAGE_NON_IDEMPOTENT	0x00020 /* non idempotent memory */
#define _PAGE_TOLERANT		0x00030 /* tolerant memory, cache inhibited */
/*
 * Software bits
 */
#define _RPAGE_SW0		0x2000000000000000UL
#define _RPAGE_SW1		0x00800
#define _RPAGE_SW2		0x00400
#define _RPAGE_SW3		0x00200
#define _RPAGE_RSV1		0x1000000000000000UL
#define _RPAGE_RSV2		0x0800000000000000UL
#define _RPAGE_RSV3		0x0400000000000000UL
#define _RPAGE_RSV4		0x0200000000000000UL
#define _RPAGE_RSV5		0x00040UL

#define _PAGE_PTE		0x4000000000000000UL	/* distinguishes PTEs from pointers */
#define _PAGE_PRESENT		0x8000000000000000UL	/* pte contains a translation */
#define _PAGE_INVALID		_RPAGE_SW0		/* temporary mark as invalid */

/*
 * No page size encoding in the linux PTE
 */
#define _PAGE_PSIZE		0

/*
 * Mask of bits returned by pte_pgprot()
 */
#define PAGE_PROT_BITS  (_PAGE_SAO | _PAGE_NON_IDEMPOTENT | _PAGE_TOLERANT | \
			 _PAGE_PRESENT | _PAGE_PRIVILEGED | _PAGE_ACCESSED | \
			 _PAGE_READ | _PAGE_WRITE |  _PAGE_DIRTY | _PAGE_EXEC)
/*
 * We define 2 sets of base prot bits, one for basic pages (ie,
 * cacheable kernel and user pages) and one for non cacheable
 * pages. We always set _PAGE_COHERENT when SMP is enabled or
 * the processor might need it for DMA coherency.
 */
#define _PAGE_BASE_NC	(_PAGE_PRESENT | _PAGE_ACCESSED | _PAGE_PSIZE)
#define _PAGE_BASE	(_PAGE_BASE_NC)

/*
 * Max physical address bit we will use for now.
 *
 * This is mostly a hardware limitation and for now Power9 has
 * a 51 bit limit.
 *
 * This is different from the number of physical bit required to address
 * the last byte of memory. That is defined by MAX_PHYSMEM_BITS.
 * MAX_PHYSMEM_BITS is a linux limitation imposed by the maximum
 * number of sections we can support (SECTIONS_SHIFT).
 *
 * This is different from Radix page table limitation above and
 * should always be less than that. The limit is done such that
 * we can overload the bits between _RPAGE_PA_MAX and _PAGE_PA_MAX
 * for hash linux page table specific bits.
 *
 * In order to be compatible with future hardware generations we keep
 * some offsets and limit this for now to 53
 */
#define _PAGE_PA_MAX		53

#define _PAGE_SOFT_SHARED	_RPAGE_SW2 /* page shared with HV */

/*
 * We support _RPAGE_PA_MAX bit real address in pte. On the linux side
 * we are limited by _PAGE_PA_MAX. Clear everything above _PAGE_PA_MAX
 * and every thing below PAGE_SHIFT;
 */
#define PTE_RPN_MASK	(((1UL << _PAGE_PA_MAX) - 1) & (PAGE_MASK))

/* Permission masks used to generate the __P and __S table,
 *
 * Write permissions imply read permissions for now (we could make write-only
 * pages on BookE but we don't bother for now). Execute permission control is
 * possible on platforms that define _PAGE_EXEC
 *
 * Note due to the way vm flags are laid out, the bits are XWR
 */
#define __pgprot(x)	((pgprot_t) { (x) } )
#define PAGE_NONE	__pgprot(_PAGE_BASE | _PAGE_PRIVILEGED)
#define PAGE_NORMAL	__pgprot(_PAGE_BASE | _PAGE_RW)
#define PAGE_NORMAL_X	__pgprot(_PAGE_BASE | _PAGE_RW | _PAGE_EXEC)
#define PAGE_COPY	__pgprot(_PAGE_BASE | _PAGE_READ)
#define PAGE_COPY_X	__pgprot(_PAGE_BASE | _PAGE_READ | _PAGE_EXEC)
#define PAGE_READONLY	__pgprot(_PAGE_BASE | _PAGE_READ)
#define PAGE_READONLY_X	__pgprot(_PAGE_BASE | _PAGE_READ | _PAGE_EXEC)
#define PAGE_SHARED	__pgprot(_PAGE_SOFT_SHARED)

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef uint64_t gva_t;
typedef uint64_t gpa_t;
typedef uint64_t gfn_t;

typedef uint64_t hva_t;
typedef uint64_t hpa_t;
typedef uint64_t hfn_t;


typedef struct { u64 pgd; } pgd_t;
typedef struct { u64 pud; } pud_t;
typedef struct { u64 pmd; } pmd_t;
typedef struct { u64 pte; } pte_t;
typedef struct { unsigned long pgprot; } pgprot_t;

struct mm_struct {
	pgd_t *pgd;
};

extern pgd_t *pgd_alloc(struct mm_struct *mm);
extern void *gpa_to_addr(struct mm_struct *mm, gpa_t gpa, int *present);
extern void mmu_partition_table_set_entry(u32 lpid, u64 dw0, u64 dw1);
extern void release_page_range(struct mm_struct *mm, bool all,
			       u64 start, u64 end);

#define __va(x) ((void *)(u64)((u64)(x) | PPC_BIT(0)))
#define __pa(x) ((u64)(x) & ~PPC_BIT(0))
#define __uvpa(x) ((void *)(u64)((u64)(x) | PPC_BIT(0)))

#define PAGE_SHIFT		16
#define PAGE_SIZE		(1ul << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE - 1))
#define PAGE_OFFSET_MASK	(PAGE_SIZE - 1)

#define offset_in_page(p) ((unsigned long )(p) & ~PAGE_MASK)

extern int setup_page_range(struct mm_struct *mm, unsigned long start,
				size_t size);
extern int setup_page(struct mm_struct *mm, u64 lpid, gpa_t gpa,
			void *page, int psize, u64 flags);
extern int setup_page_notpresent(struct mm_struct *mm, u64 lpid,
			gpa_t gpa, void *page, int psize, u64 flags);
extern int setup_page_invalidate(struct mm_struct *mm, u64 lpid,
				gpa_t gpa, u64 psize);

static inline u64 get_reservation_size(u64 start, size_t size)
{
	u64 first_page_start, last_page_start;

	if (!size)
		return 0;
	first_page_start = start & UV_PAGE_MASK;
	last_page_start = (start + size - 1) & UV_PAGE_MASK;

	return ((last_page_start - first_page_start) >> UV_PAGE_SHIFT) + 1;
}

extern bool is_page_noaccess(struct mm_struct *mm, gpa_t gpa);
extern int set_normal_page(struct mm_struct *mm, u64 lpid, gpa_t gpa);
extern int set_noaccess_range(struct mm_struct *mm, u64 lpid, int max_pages,
			      u64 start, u64 end, u64 *next);
#endif /* PGTABLE_H */
