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
#include <cpu_has_feature.h>
#include <tlbflush.h>


static inline void __tlbie_lpid_gpa(gpa_t gpa, unsigned long lpid,
                              unsigned long ap, unsigned long ric)
{
	unsigned long rb,rs,prs,r;

	rb = gpa & ~(PPC_BITMASK(52, 63));
	rb |= ap << PPC_BITLSHIFT(58);
	rs = lpid;
	prs = 0; /* partition scoped */
	r = 1;   /* radix format */
	(void) ric;

	asm volatile(PPC_TLBIE_5(%0, %4, %3, %2, %1)
		     :
		     : "r"(rb), "i"(r), "i"(prs), "i"(RIC_FLUSH_TLB), "r"(rs)
		     : "memory");
}

static inline void fixup_tlbie_lpid(unsigned long lpid)
{
	gpa_t gpa = ((1UL << 52) - 1);

	if (cpu_has_feature(CPU_FTR_P9_TLBIE_BUG)) {
		asm volatile("ptesync": : :"memory");
		__tlbie_lpid_gpa(gpa, lpid, mmu_get_ap(MMU_PAGE_64K),
				RIC_FLUSH_TLB);
	}
}

void _tlbie_lpid_gpa(gpa_t gpa, unsigned long lpid,
			unsigned long psize, unsigned long ric)
{
	unsigned long ap = mmu_get_ap(psize);

	asm volatile("ptesync": : :"memory");
	__tlbie_lpid_gpa(gpa, lpid, ap, ric);
	fixup_tlbie_lpid(lpid);
	asm volatile("eieio; tlbsync; ptesync": : :"memory");
}
