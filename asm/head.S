// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp.
 */

#include <asm-utils.h>
#include <asm-offsets.h>
#include <mem-map.h>
#include <processor.h>
#include <stack.h>

	.section ".head","ax"

	. = 0
.global __head
__head:
	b	boot_entry

	/*
	 * This is our boot semaphore used for CPUs to sync, it has to be
	 * at an easy to locate address (without relocation) since we
	 * need to get at it very early, before we apply our relocs
	 */
	. = 0xf0
boot_sem:
	.long   0

	/*
	 * And this is a boot flag used to kick secondaries into the
	 * main code.
	 */
boot_flag:
	.long   0

#include "exceptions.S"

/*
 * Entering into this code we make the following assumptions:
 *	1. The MMU is off, processor in UV mode.
 *	2. The primary CPU enters at 0.
 *		 R3: struct uv_opal
 *		 6 registers available for arguments.
 *	3. Scratch registers
 *		R9:  Scratch
 *		R10: Scratch
 *		R11: Scratch
 *		R12: Scratch
 *		CTR: Scratch
 */
.global	boot_entry
boot_entry:
	FIXUP_ENDIAN

	/* Save previous LR and TOC. Then get new TOC */
	mflr	%r11
	mtctr	%r11
	mr	%r11,%r2
	bcl	20,31,$+4
1:	mflr	%r12
	subi	%r12,%r12,(1b - __head)
	LOAD_IMM32(%r2,__toc_start - __head)
	add	%r2,%r2,%r12

	/* Save to USPRG0 for later setting of URMOR */
	mtspr	SPRG_UVSCRATCH0,%r12

	/* Get our per CPU stack */
	mfspr	%r10,SPR_PIR
	GET_STACK(%r12,%r10,%r9)

	/* Get first stack frame */
	stdu	%r12,-STACK_FRAMESIZE(%r12)

	/* Save caller registers */
	SAVE_GPR(1,%r12)		/* Caller R1 */
	std	%r11,STACK_GPR2(%r12)	/* Caller R2 */
	SAVE_GPR(13,%r12)		/* Caller R13 */
	mfctr	%r11
	std	%r11,STACK_LR(%r12)	/* Caller LR */

	/* Establish new R1 */
	mr	%r1,%r12

	/* Get our per-cpu pointer into R13 */
	GET_CPU()

	/* Check our PIR, avoid threads */
	mfspr	%r10,SPR_PIR
	li	%r11,3  /* Default to SMT4 */
	and.	%r10,%r10,%r11
	bne	secondary_wait

	/* Pick a boot CPU */
	mfspr	%r12,SPRG_UVSCRATCH0
	LOAD_IMM32(%r11, boot_sem - __head)
	add	%r11,%r11,%r12
1:      lwarx	%r12,0,%r11
	addi	%r10,%r12,1
	stwcx.	%r10,0,%r11
	bne	1b
	isync
	cmpwi	cr0,%r12,0
	bne	secondary_wait

	/* Relocate ourselves */
	stdu	%r1,-STACK_FRAMESIZE(%r1)
	SAVE_GPR(3,%r1)
	SAVE_GPR(8,%r1)
	SAVE_GPR(9,%r1)

	mfspr	%r12,SPRG_UVSCRATCH0
	bl	call_relocate

	REST_GPR(9,%r1)
	REST_GPR(8,%r1)
	REST_GPR(3,%r1)
	addi	%r1,%r1,STACK_FRAMESIZE

	/* Set ultra_base */
	mfspr	%r12,SPRG_UVSCRATCH0
	LOAD_ADDR_FROM_TOC(%r11, ultra_base)
	std	%r12,0(%r11)

	/**
	 * @todo: Can we drop this load of cpu_max_pir? init_boot_cpu()
	 * 	  and init_cpu_max_pir() compute/init cpu_max_pir and
	 *	  they run very early on (from uv_main_cpu_entry()).
	 */
	LOAD_ADDR_FROM_TOC(%r12, cpu_max_pir)
	/* Tell secondaries to move to second stage (relocated) spin loop */
	mfspr	%r12,SPRG_UVSCRATCH0
	LOAD_IMM32(%r11, boot_flag - __head)
	add	%r11,%r11,%r12
	li	%r10,1
	stw	%r10,0(%r11)

	/* Clear BSS */
	li	%r11,0
	LOAD_ADDR_FROM_TOC(%r12, _sbss)
	LOAD_ADDR_FROM_TOC(%r10, _ebss)
	subf	%r10,%r12,%r10
	srdi	%r10,%r10,3
	mtctr	%r10
1:	std	%r11,0(%r12)
	addi	%r12,%r12,8
	bdnz	1b

	/* Save OPAL base and entry */
	LOAD_ADDR_FROM_TOC(%r12, opal)
	std	%r8,0(%r12)
	std	%r9,8(%r12)

	/* Jump to C */
	stdu	%r1,-STACK_FRAMESIZE(%r1)
	bl	uv_main_cpu_entry
	addi	%r1,%r1,STACK_FRAMESIZE

return_to_skiboot:
	/* Save our R1 to SPRG_UVSTACK */
	mtspr	SPRG_UVSTACK,%r1

	/* Save our R2 to cpu_thread */
	std	%r2,CPUTHREAD_SAVE_R2(%r13)

	/* Restore caller registers and URFID to caller */
	mr	%r12,%r1
	REST_GPR(1,%r12)
	REST_GPR(2,%r12)
	REST_GPR(13,%r12)
	ld	%r10,STACK_LR(%r12)
	mtspr	SPR_USRR0,%r10
	urfid

	/* Secondary CPUs wait here */
secondary_wait:
	/*
	 * The primary might be in the middle of relocating us,
	 * so first we spin on the boot_flag
	 */
	mfspr	%r12,SPRG_UVSCRATCH0
	LOAD_IMM32(%r11, boot_flag - __head)
	add	%r11,%r11,%r12
1:	smt_lowest
	lwz	%r10,0(%r11)
	cmpdi	%r10,0
	beq	1b

	/* Now wait for cpu_secondary_start to be set */
	LOAD_ADDR_FROM_TOC(%r12, cpu_secondary_start)
1:	smt_lowest
	ld	%r11,0(%r12)
	cmpdi	%r11,0
	beq	1b

	smt_medium

	/* Check our PIR is in bound */
	mfspr   %r11,SPR_PIR
	LOAD_ADDR_FROM_TOC(%r12, cpu_max_pir)
	lwz	%r12,0(%r12)
	cmpw	%r11,%r12
	bgt-	secondary_not_found

	/* Get our stack and jump to C */
	stdu	%r1,-STACK_FRAMESIZE(%r1)
	bl	secondary_cpu_entry
	addi	%r1,%r1,STACK_FRAMESIZE
	b	return_to_skiboot

	/* Not found... what to do ? set some global error ? */
secondary_not_found:
	smt_lowest
	b	.

call_relocate:
	mflr	%r10
	std	%r10,STACK_LR(%r1)
	LOAD_IMM32(%r4,__dynamic_start - __head)
	LOAD_IMM32(%r5,__rela_dyn_start - __head)
	add	%r4,%r4,%r12
	add	%r5,%r5,%r12
	mr	%r3,%r12
	bl	relocate
	cmpwi	%r3,0
	bne	1f
	ld	%r10,STACK_LR(%r1)
	mtlr	%r10
	blr
1:	/* Fatal relocate failure */
	attn
