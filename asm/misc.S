// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp.
 */

#include <asm-utils.h>
#include <asm-offsets.h>
#include <processor.h>
#include <stack.h>

#define OLD_BINUTILS 1

	.section ".text","ax"
	.balign	0x10

	/* void set_hid0(unsigned long hid0) */
.global set_hid0
set_hid0:
	sync
	mtspr	SPR_HID0,%r3
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	mfspr	%r3,SPR_HID0
	isync
	blr

.global __trigger_attn
__trigger_attn:
	sync
	isync
	attn
	blr

#ifdef STACK_CHECK_ENABLED
.global _mcount
_mcount:
	mr	%r3,%r1
	mflr	%r4
	b	__mcount_stack_check
#endif

	.global cleanup_local_tlb
cleanup_local_tlb:
	/* Clean the TLB */
	li	%r3,512
	mtctr	%r3
	li	%r4,0xc00		/* IS field = 0b11 */
	ptesync
1:	tlbiel	%r4
	addi	%r4,%r4,0x1000
	bdnz	1b
	ptesync
	blr

	.global cleanup_global_tlb
cleanup_global_tlb:

	/* Only supported on P9 for now */
	mfspr	%r3,SPR_PVR
	srdi	%r3,%r3,16
	cmpwi	cr0,%r3,PVR_TYPE_P9
	bnelr

	/* Sync out previous updates */
	ptesync

#ifndef OLD_BINUTILS
	.machine "power9"
#endif
	/* Lead RB with IS=11 */
	li	%r3,3
	sldi	%r3,%r3,10
	li	%r0,0

	/* Blow up radix partition scoped translations */
#ifdef OLD_BINUTILS
	.long   0x7c0b1a64
#else
	tlbie	%r3, %r0 /* rs */, 2 /* ric */, 1 /* prs */, 1 /* r */
#endif
	eieio
	tlbsync
	ptesync
#ifdef OLD_BINUTILS
	.long   0x7c091a64
#else
	tlbie	%r3, %r0 /* rs */, 2 /* ric */, 0 /* prs */, 1 /* r */
#endif
	eieio
	tlbsync
	ptesync

	/* Blow up hash partition scoped translations */
#ifdef OLD_BINUTILS
	.long   0x7c0a1a64
#else
	tlbie	%r3, %r0 /* rs */, 2 /* ric */, 1 /* prs */, 0 /* r */
#endif
	eieio
	tlbsync
	ptesync
#ifdef OLD_BINUTILS
	.long   0x7c081a64
#else
	tlbie	%r3, %r0 /* rs */, 2 /* ric */, 0 /* prs */, 0 /* r */
#endif
	eieio
	tlbsync
	ptesync

	blr
