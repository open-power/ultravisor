/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on Ealier Work: arch/powerpc/include/asm/ppc-opcode.h
 * Obtained from: https://github.com/torvalds/linux
 */
#ifndef _ASM_POWERPC_PPC_OPCODE_H
#define _ASM_POWERPC_PPC_OPCODE_H

#define  TLBIEL_INVAL_SET_LPID  0x800   /* invalidate a set for current LPID */

#define PPC_INST_CLRBHRB	0x7c00035c
#define PPC_INST_TABORT		0x7c00071d
#define PPC_INST_SLBIA		0x7c0003e4
#define PPC_INST_TLBIE		0x7c000264
#define PPC_INST_DARN		0x7c0005e6

/* macros to insert fields into opcodes */
#define ___PPC_RA(a)    (((a) & 0x1f) << 16)
#define ___PPC_RB(b)    (((b) & 0x1f) << 11)
#define ___PPC_RS(s)    (((s) & 0x1f) << 21)
#define ___PPC_RT(t)    ___PPC_RS(t)
#define ___PPC_R(r)     (((r) & 0x1) << 16)
#define ___PPC_PRS(prs) (((prs) & 0x1) << 17)
#define ___PPC_RIC(ric) (((ric) & 0x3) << 18)
#define __PPC_RA(a)     ___PPC_RA(__REG_##a)
#define __PPC_RA0(a)    ___PPC_RA(__REGA0_##a)
#define __PPC_RB(b)     ___PPC_RB(__REG_##b)
#define __PPC_RS(s)     ___PPC_RS(__REG_##s)
#define __PPC_RT(t)     ___PPC_RT(__REG_##t)
#define __PPC_XA(a)     ((((a) & 0x1f) << 16) | (((a) & 0x20) >> 3))
#define __PPC_XB(b)     ((((b) & 0x1f) << 11) | (((b) & 0x20) >> 4))
#define __PPC_XS(s)     ((((s) & 0x1f) << 21) | (((s) & 0x20) >> 5))
#define __PPC_XT(s)     __PPC_XS(s)
#define __PPC_T_TLB(t)  (((t) & 0x3) << 21)
#define __PPC_WC(w)     (((w) & 0x3) << 21)
#define __PPC_WS(w)     (((w) & 0x1f) << 11)
#define __PPC_SH(s)     __PPC_WS(s)
#define __PPC_SH64(s)   (__PPC_SH(s) | (((s) & 0x20) >> 4))
#define __PPC_MB(s)     (((s) & 0x1f) << 6)
#define __PPC_ME(s)     (((s) & 0x1f) << 1)
#define __PPC_MB64(s)   (__PPC_MB(s) | ((s) & 0x20))
#define __PPC_ME64(s)   __PPC_MB64(s)
#define __PPC_BI(s)     (((s) & 0x1f) << 16)
#define __PPC_CT(t)     (((t) & 0x0f) << 21)
#define __PPC_SPR(r)    ((((r) & 0x1f) << 16) | ((((r) >> 5) & 0x1f) << 11))

#ifdef __ASSEMBLY__
#define stringify_in_c(...) __VA_ARGS__
#else
#define __stringify_in_c(...) #__VA_ARGS__
#define stringify_in_c(...) __stringify_in_c(__VA_ARGS__) " "
#endif

#define PPC_TLBIE_5(rb,rs,ric,prs,r) \
	stringify_in_c(.long PPC_INST_TLBIE | \
			___PPC_RB(rb) | ___PPC_RS(rs) | \
			___PPC_RIC(ric) | ___PPC_PRS(prs) | \
			___PPC_R(r))

#define PPC_DARN(t, l) \
	stringify_in_c(.long PPC_INST_DARN |  \
			___PPC_RT(t)       |  \
			(((l) & 0x3) << 16))

#define PPC_SLBIA(IH)   stringify_in_c(.long PPC_INST_SLBIA | \
		((IH & 0x7) << 21))
#define PPC_INVALIDATE_ERAT     PPC_SLBIA(7)

#define PPC_CLRBHRB     stringify_in_c(.long PPC_INST_CLRBHRB)

#define TABORT(r)	stringify_in_c(.long PPC_INST_TABORT \
				| __PPC_RA(r))

/* Abort Transaction with "cause" = 1 */
#define TABORT0		stringify_in_c(.long PPC_INST_TABORT)


#endif /* _ASM_POWERPC_PPC_OPCODE_H */
