/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on Ealier Work: arch/powerpc/include/asm/book3s/64/mmu.h
 * Obtained from: https://github.com/torvalds/linux
 */
#ifndef _MMU_H_
#define _MMU_H_

#include <device.h>
#include <pgtable.h>

#ifndef __ASSEMBLY__
/*
 * ISA 3.0 partition and process table entry format
 */
struct prtb_entry {
	__be64 prtb0;
	__be64 prtb1;
};
extern struct prtb_entry *process_tb;

struct patb_entry {
	__be64 patb0;
	__be64 patb1;
};
extern struct patb_entry *partition_tb;

/* Bits in patb0 field */
#define PATB_HR		(1UL << 63)
#define RPDB_MASK	0x0fffffffffffff00UL
#define RPDB_SHIFT	(1UL << 8)
#define RTS1_SHIFT	61		/* top 2 bits of radix tree size */
#define RTS1_MASK	(3UL << RTS1_SHIFT)
#define RTS2_SHIFT	5		/* bottom 3 bits of radix tree size */
#define RTS2_MASK	(7UL << RTS2_SHIFT)
#define RPDS_MASK	0x1f		/* root page dir. size field */

/* Bits in patb1 field */
#define PATB_GR		(1UL << 63)	/* guest uses radix; must match HR */
#define PRTS_MASK	0x1f		/* process table size field */
#define PRTB_MASK	0x0ffffffffffff000UL

/* Number of supported PID bits */
extern unsigned int mmu_pid_bits;

/* Base PID to allocate from */
extern unsigned int mmu_base_pid;

#define PRTB_SIZE_SHIFT	(mmu_pid_bits + 4)
#define PRTB_ENTRIES	(1ul << mmu_pid_bits)

/*
 * Power9 currently only support 64K partition table size.
 */
#define PATB_SIZE_SHIFT	16

/*
 * For 64K page size supported index is 13/9/9/5
 */
#define RADIX_PTE_INDEX_SIZE  5  /* 2MB huge page */
#define RADIX_PMD_INDEX_SIZE  9  /* 1G huge page */
#define RADIX_PUD_INDEX_SIZE     9
#define RADIX_PGD_INDEX_SIZE  13

extern void radix__early_init_mmu(void);
extern void radix__early_init_mmu_secondary(void);

extern void mmu_partition_table_set_entry(u32 lpid, u64 dw0, u64 dw1);
extern void mmu_partition_table_set_dw0(u32 lpid, u64 dw0);
extern void mmu_partition_table_set_dw1(u32 lpid, u64 dw1);


static inline unsigned long radix__get_tree_size(void)
{
	unsigned long rts_field;
	/*
	 * We support 52 bits, hence:
	 *  DD1    52-28 = 24, 0b11000
	 *  Others 52-31 = 21, 0b10101
	 * RTS encoding details
	 * bits 0 - 3 of rts -> bits 6 - 8 unsigned long
	 * bits 4 - 5 of rts -> bits 62 - 63 of unsigned long
	 */
	rts_field = (0x5UL << 5); /* 6 - 8 bits */
	rts_field |= (0x2UL << 61);
	return rts_field;
}
#define RADIX_PGD_INDEX_SIZE 13
#define PATB_HR         (1UL << 63)


/* These are #defines as they have to be used in assembly */
#define MMU_PAGE_4K     0
#define MMU_PAGE_16K    1
#define MMU_PAGE_64K    2
#define MMU_PAGE_64K_AP 3       /* "Admixed pages" (hash64 only) */
#define MMU_PAGE_256K   4
#define MMU_PAGE_512K   5
#define MMU_PAGE_1M     6
#define MMU_PAGE_2M     7
#define MMU_PAGE_4M     8
#define MMU_PAGE_8M     9
#define MMU_PAGE_16M    10
#define MMU_PAGE_64M    11
#define MMU_PAGE_256M   12
#define MMU_PAGE_1G     13
#define MMU_PAGE_16G    14
#define MMU_PAGE_64G    15
static inline int radix_get_mmu_psize(u64 page_size)
{
	switch (page_size) {
		case (1UL << 12):
			return MMU_PAGE_4K;
		case (1UL << 14):
			return MMU_PAGE_16K;
		case (1UL << 16):
			return MMU_PAGE_64K;
		case (1UL << 18):
			return MMU_PAGE_256K;
		case (1UL << 19):
			return MMU_PAGE_512K;
		case (1UL << 20):
			return MMU_PAGE_1M;
		case (1UL << 21):
			return MMU_PAGE_2M;
		case (1UL << 22):
			return MMU_PAGE_4M;
		case (1UL << 23):
			return MMU_PAGE_8M;
		case (1UL << 24):
			return MMU_PAGE_16M;
		case (1UL << 26):
			return MMU_PAGE_64M;
		case (1UL << 28):
			return MMU_PAGE_256M;
		case (1UL << 30):
			return MMU_PAGE_1G;
		case (1UL << 34):
			return MMU_PAGE_16G;
		case (1UL << 36):
			return MMU_PAGE_64G;
		default:
			return -1;
	}
}

#define AP_SIZE_64K 0x5 /* 64k Page */
 /*
  * @todo: this value has to be got dynamically from the device tree property
  *  ibm,processor-radix-AP-encodings
  */
#define AP_SIZE_2M  0x1

static inline int mmu_get_ap(int psize)
{
	if (psize == MMU_PAGE_2M)
		return AP_SIZE_2M;
	if (psize == MMU_PAGE_64K)
		return AP_SIZE_64K;
	/** @todo currently we only support 64K and 2M page size **/
	assert(0);
}

static inline pte_t __radix_pte_update(pte_t *ptep, unsigned long clr,
				unsigned long set)
{
	__be64 old_be, tmp_be;

	__asm__ __volatile__(
	"1:     ldarx   %0,0,%3         # pte_update\n"
	"       andc    %1,%0,%5        \n"
	"       or      %1,%1,%4        \n"
	"       stdcx.  %1,0,%3         \n"
	"       bne-    1b"
	: "=&r" (old_be), "=&r" (tmp_be), "=m" (*ptep)
	: "r" (ptep), "r" (cpu_to_be64(set)), "r" (cpu_to_be64(clr))
	: "cc" );

	return (pte_t){be64_to_cpu(old_be)};
}

#endif /* __ASSEMBLY__ */
#endif /* _MMU_H_ */
