// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright 2018 IBM Corp.
 */

#include <asm-utils.h>
#include <asm-offsets.h>
#include <mem-map.h>
#include <processor.h>
#include <stack.h>

/*
 * Save (most) GPRs and SPRS on the given stack frame. Save the GPRs
 * first so we can them use some of them as temporary registers. And
 * remember to restore the temporary ones before returning!
 *
 * Note: Only save registers common to exception entry and exception
 *	 reflection code and expect callers to handle the others.
 *	 Eg: exception_entry needs to save CFAR early and should not
 *	 be saved here again.
 *
 * Note: @frame is expected to be either R1 or R3 only! Any other GPR
 *	 could get clobbered below.
 *
 * @todo: Can/should we skip restoring HDSISR on HV-exit? HDSISR is
 *	  set by hardware and once HV has seen its value, no need to
 *	  restore it?
 */
#define SAVE_REGS(frame)			 \
						;\
	SAVE_GPR(3, frame)			;\
	SAVE_GPR(4, frame)			;\
	SAVE_GPR(5, frame)			;\
	SAVE_GPR(6, frame)			;\
	SAVE_GPR(7, frame)			;\
	SAVE_GPR(8, frame)			;\
	SAVE_GPR(9, frame)			;\
	SAVE_GPR(10, frame)			;\
	SAVE_GPR(11, frame)			;\
	SAVE_GPR(12, frame)			;\
	/* R13 is caller's responsibiiity */	;\
	SAVE_GPR(14, frame)			;\
	SAVE_GPR(15, frame)			;\
	SAVE_GPR(16, frame)			;\
	SAVE_GPR(17, frame)			;\
	SAVE_GPR(18, frame)			;\
	SAVE_GPR(19, frame)			;\
	SAVE_GPR(20, frame)			;\
	SAVE_GPR(21, frame)			;\
	SAVE_GPR(22, frame)			;\
	SAVE_GPR(23, frame)			;\
	SAVE_GPR(24, frame)			;\
	SAVE_GPR(25, frame)			;\
	SAVE_GPR(26, frame)			;\
	SAVE_GPR(27, frame)			;\
	SAVE_GPR(28, frame)			;\
	SAVE_GPR(29, frame)			;\
	SAVE_GPR(30, frame)			;\
	SAVE_GPR(31, frame)			;\
						;\
	mfcr	%r28				;\
	mfxer	%r29				;\
	mfctr	%r30				;\
	mflr	%r31				;\
	std	%r28,STACK_CR(frame)		;\
	std	%r29,STACK_XER(frame)		;\
	std	%r30,STACK_CTR(frame)		;\
	std	%r31,STACK_LR(frame)		;\
						;\
	mfspr	%r28,SPR_HDAR			;\
	mfspr	%r29,SPR_PIDR			;\
	mfspr	%r30,SPR_LPCR			;\
	mfspr	%r31,SPR_LPIDR			;\
	std	%r28,STACK_HDAR(frame)		;\
	std	%r29,STACK_PIDR(frame)		;\
	std	%r30,STACK_LPCR(frame)		;\
	std	%r31,STACK_LPIDR(frame)		;\
						;\
	mfspr	%r28,SPR_HEIR			;\
	mfspr	%r29,SPR_ASDR			;\
	mfspr	%r30,SPR_SRR0			;\
	mfspr	%r31,SPR_SRR1			;\
	std	%r28,STACK_HEIR(frame)		;\
	std	%r29,STACK_ASDR(frame)		;\
	std	%r30,STACK_SRR0(frame)		;\
	std	%r31,STACK_SRR1(frame)		;\
						;\
	mfspr	%r28,SPR_SPRG0			;\
	mfspr	%r29,SPR_SPRG1			;\
	mfspr	%r30,SPR_SPRG2			;\
	mfspr	%r31,SPR_SPRG3			;\
	std	%r28,STACK_SPRG0(frame)		;\
	std	%r29,STACK_SPRG1(frame)		;\
	std	%r30,STACK_SPRG2(frame)		;\
	std	%r31,STACK_SPRG3(frame)		;\
						;\
	mfspr	%r30,SPR_HSRR0			;\
	mfspr	%r31,SPR_HSRR1			;\
	std	%r30,STACK_HSRR0(frame)		;\
	std	%r31,STACK_HSRR1(frame)		;\
						;\
	mfspr	%r30,SPR_USRR0			;\
	mfspr	%r31,SPR_USRR1			;\
	std	%r30,STACK_USRR0(frame)		;\
	std	%r31,STACK_USRR1(frame)		;\
						;\
	mfspr	%r30,SPR_DEC			;\
	mfspr	%r31,SPR_HDSISR			;\
	std	%r30,STACK_DEC(frame)		;\
	std	%r31,STACK_HDSISR(frame)	;\
						;\
	mfvrsave %r28				;\
	mfspr	%r29,SPR_MMCR0			;\
	mfspr	%r30,SPR_MMCRA			;\
	std	%r28,STACK_VRSAVE(frame)	;\
	std	%r29,STACK_MMCR0(frame)		;\
	std	%r30,STACK_MMCRA(frame)		;\
						;\
	mfspr	%r30,SPR_DAR			;\
	mfspr	%r31,SPR_DSISR			;\
	std	%r30,STACK_DAR(frame)		;\
	std	%r31,STACK_DSISR(frame)		;\
						;\
	/* restore the temp registers */	;\
	REST_GPR(28, frame)			;\
	REST_GPR(29, frame)			;\
	REST_GPR(30, frame)			;\
	REST_GPR(31, frame)			;\

/*
 * Restore (most) GPRs and SPRS from the given stack frame. Restore SPRs
 * first so we can use some of the GPRs as temporary registers.
 *
 * Note: Only restore registers common to urfid_return and uv_return.
 *	 and expect callers to handle the others. Eg: uv_return()
 *	 should NOT restore R13 (see refl_state_restore_regs)
 *
 * Note: @frame is expected to be either R1 or R3 only! Any other GPR
 *	 could get clobbered below.
 */
#define REST_REGS(frame)			 \
						;\
	ld	%r28,STACK_VRSAVE(frame)	;\
	ld	%r29,STACK_MMCR0(frame)		;\
	ld	%r30,STACK_MMCRA(frame)		;\
	mtvrsave %r28				;\
	mtspr	 SPR_MMCR0,%r29			;\
	mtspr	 SPR_MMCRA,%r30			;\
						;\
	ld	%r31,STACK_USRR1(frame)		;\
	ld	%r30,STACK_USRR0(frame)		;\
	mtspr	SPR_USRR1,%r31			;\
	mtspr	SPR_USRR0,%r30			;\
						;\
	ld	%r31,STACK_HDSISR(frame)	;\
	ld	%r30,STACK_DEC(frame)		;\
	mtspr	SPR_HDSISR,%r31			;\
	mtspr	SPR_DEC, %r30			;\
						;\
	ld	%r31,STACK_HSRR1(frame)		;\
	ld	%r30,STACK_HSRR0(frame)		;\
	mtspr	SPR_HSRR1,%r31			;\
	mtspr	SPR_HSRR0,%r30			;\
						;\
	ld	%r31,STACK_SPRG3(frame)		;\
	ld	%r30,STACK_SPRG2(frame)		;\
	ld	%r29,STACK_SPRG1(frame)		;\
	ld	%r28,STACK_SPRG0(frame)		;\
	mtspr	SPR_SPRG3,%r31			;\
	mtspr	SPR_SPRG2,%r30			;\
	mtspr	SPR_SPRG1,%r29			;\
	mtspr	SPR_SPRG0,%r28			;\
						;\
	ld	%r31,STACK_SRR1(frame)		;\
	ld	%r30,STACK_SRR0(frame)		;\
	ld	%r29,STACK_HDAR(frame)		;\
	ld	%r28,STACK_ASDR(frame)		;\
	mtspr	SPR_SRR1,%r31			;\
	mtspr	SPR_SRR0,%r30			;\
	mtspr	SPR_HDAR,%r29			;\
	mtspr	SPR_ASDR,%r28			;\
						;\
	ld	%r31,STACK_LR(frame)		;\
	ld	%r30,STACK_CTR(frame)		;\
	ld	%r29,STACK_XER(frame)		;\
	ld	%r28,STACK_CR(frame)		;\
	mtlr	%r31				;\
	mtctr	%r30				;\
	mtxer	%r29				;\
	mtcr	%r28				;\
						;\
	ld	%r31,STACK_CFAR(frame)		;\
	ld	%r30,STACK_HEIR(frame)		;\
	mtspr	SPR_CFAR,%r31			;\
	mtspr	SPR_HEIR,%r30			;\
						;\
	ld	%r30,STACK_DSISR(frame)		;\
	mtspr	SPR_DSISR,%r30			;\
						;\
	REST_GPR(31, frame)			;\
	REST_GPR(30, frame)			;\
	REST_GPR(29, frame)			;\
	REST_GPR(28, frame)			;\
	REST_GPR(27, frame)			;\
	REST_GPR(26, frame)			;\
	REST_GPR(25, frame)			;\
	REST_GPR(24, frame)			;\
	REST_GPR(23, frame)			;\
	REST_GPR(22, frame)			;\
	REST_GPR(21, frame)			;\
	REST_GPR(20, frame)			;\
	REST_GPR(19, frame)			;\
	REST_GPR(18, frame)			;\
	REST_GPR(17, frame)			;\
	REST_GPR(16, frame)			;\
	REST_GPR(15, frame)			;\
	REST_GPR(14, frame)			;\
	/* R13 is caller's responsibiiity */	;\
	REST_GPR(12, frame)			;\
	REST_GPR(11, frame)			;\
	REST_GPR(10, frame)			;\
	REST_GPR(9, frame)			;\
	REST_GPR(8, frame)			;\
	REST_GPR(7, frame)			;\
	REST_GPR(6, frame)			;\
	REST_GPR(5, frame)			;\
	REST_GPR(4, frame)			;\


#define EXCEPTION(nr)				\
	.= nr					;\
	mtspr   SPRG_UVSCRATCH0,%r1		;\
	mfspr   %r1,SPRG_UVSTACK		;\
	stdu    %r1,-STACK_FRAMESIZE(%r1)	;\
	SAVE_GPR(0,%r1)				;\
	mfspr   %r0,SPR_CFAR			;\
	SAVE_GPR(2,%r1)				;\
	li      %r2,nr				;\
	b       _exception

	/* More exception stubs */
	EXCEPTION(0x100)
	EXCEPTION(0x180)
	EXCEPTION(0x200)
	EXCEPTION(0x300)
	EXCEPTION(0x380)
	EXCEPTION(0x400)
	EXCEPTION(0x480)
	EXCEPTION(0x500)
	EXCEPTION(0x600)
	EXCEPTION(0x700)
	EXCEPTION(0x800)
	EXCEPTION(0x900)
	EXCEPTION(0x980)
	EXCEPTION(0xa00)
	EXCEPTION(0xb00)
	EXCEPTION(0xc00)
	EXCEPTION(0xd00)
	EXCEPTION(0xe00)
	EXCEPTION(0xe20)
	EXCEPTION(0xe40)
	EXCEPTION(0xe60)
	EXCEPTION(0xe80)
	EXCEPTION(0xea0)
	EXCEPTION(0xf00)
	EXCEPTION(0xf20)
	EXCEPTION(0xf40)
	EXCEPTION(0xf60)
	EXCEPTION(0xf80)
	EXCEPTION(0x1000)
	EXCEPTION(0x1100)
	EXCEPTION(0x1200)
	EXCEPTION(0x1300)
	EXCEPTION(0x1400)
	EXCEPTION(0x1500)
	EXCEPTION(0x1600)

	.= 0x1e00
_exception:

	/* save registers not saved by helper */
	std	%r0,STACK_CFAR(%r1)
	std     %r2,STACK_TYPE(%r1)
	mfspr	%r0,SPRG_UVSCRATCH0
	std	%r0,STACK_GPR1(%r1)

	/* R0 already saved above */
	/* R1 already saved above */
	/* R2 already saved above */
	/* save R13 here */
	SAVE_GPR(13,%r1)

	/* use helper to save most GPRs and SPRs */
	SAVE_REGS(%r1)

	/* Get our per-cpu pointer into R13 */
	GET_CPU()

	/* Restore TOC */
	ld	%r2,CPUTHREAD_SAVE_R2(%r13)

	/* Clear scratch register */
	li	%r31,0
	mtspr	SPRG_UVSCRATCH0,%r31

	mr      %r3,%r1
	b	exception_entry


.global _urfid_return
_urfid_return:

	mr	%r1,%r3

	/* use helper to restore most registers */
	REST_REGS(%r1)

	/* restore registers not restored by helper */
	REST_GPR(13,%r1)
	REST_GPR(2,%r1)
	REST_GPR(0,%r1)
	REST_GPR(3,%r1)

	/* R1 had the stack pointer, restore it last */
	REST_GPR(1,%r1)

	urfid

/*
 * Switch to the stack pointed by r4 and call put_reflect_state and
 * _urfid_return.
 * R3 : rstate pointer
 * R4 : excp_frame pointer
 */
.global put_rstate_urfid_return
put_rstate_urfid_return:
	mr	%r31, %r4

	/* Switching the stack */
	mr	%r1, %r4

	/* Let some space between the stack and the stack frame */
	stdu    %r1,-STACK_FRAMESIZE(%r1)

	bl	put_reflect_state

	mr	%r3, %r31
	b	_urfid_return

/*
 * Save the registers in the stack_frame object passed into R3.
 *
 * R13 contains the per_cpu value 'this_cpu' and was set by the
 * exception handler. Don't save/restore it as that would put the
 * old CPU's 'this_cpu' in the new CPU!
 *
 * R2 contains the TOC and was also set by the exception handler
 * so ignore that as well.
 */
.global refl_state_save_regs
refl_state_save_regs:

	SAVE_GPR(0,%r3)
	SAVE_GPR(1,%r3)

	/* skip R2 -see above */
	/* skip R13 - see above */

	/* use helper to save most registers */
	SAVE_REGS(%r3)

	/* save remaining SPRs - after GPRs so we have temp registers */
	mfspr	%r28,SPR_CFAR
	std	%r28,STACK_CFAR(%r3)

	/* restore the temp register(s) */
	REST_GPR(28,%r3)

	/* return zero when saving context */
	li	%r3, 0
	blr

/*
 * Restore live register state from the stack_frame object R3.
 * This function, like getcontext/setcontext, will "return" to
 * the point where the state was saved and _NOT_ to the caller.
 * To distinguish this return from refl_state_save_regs(), return
 * a non-zero value in R3.
 *
 * R13 contains the per_cpu value 'this_cpu' and was set by the
 * exception handler. Don't save/restore it as that would put the
 * old CPU's 'this_cpu' in the new CPU!
 *
 * R2 contains the TOC and was also set by the exception handler
 * so ignore that as well.
 */
.global refl_state_restore_regs
refl_state_restore_regs:

	/* restore SPRs not restored by helper. Do this before restoring
	 * GPRs so we have temp registers
	 */

	/* @todo: should we restore LPIDR and PIDR? */
	ld      %r31,STACK_LPIDR(%r3)
	ld      %r29,STACK_PIDR(%r3)
	mtspr   SPR_LPIDR,%r31
	mtspr   SPR_PIDR,%r29

	/* use helper to restore most registers */
	REST_REGS(%r3)

	/* restore GPRs not restored by helper */

	/* skip R13 - see above */
	/* skip R3 - see below, return value */
	/* skip R2 - see above */

	REST_GPR(1,%r3)
	REST_GPR(0,%r3)

	/* return non-zero when restoring context and do this last! */
	li	%r3, 1

	blr

/*
 * R3: Reflection State passed to func
 * R4: Void * passed to func
 * R5: opd entry for new context func
 * R6: New stack
 */
.global ctx_switch_context
ctx_switch_context:
	ld	%r5,0(%r5)
	mtctr	%r5
	mr	%r1,%r6
	stdu    %r1,-STACK_FRAMESIZE(%r1)
	bctr

/*
 * R3: struct stack_frame *
 */
.global __save_fp_state
__save_fp_state:
	SAVE_FPR(0, %r3)			;\
	SAVE_FPR(1, %r3)			;\
	SAVE_FPR(2, %r3)			;\
	SAVE_FPR(3, %r3)			;\
	SAVE_FPR(4, %r3)			;\
	SAVE_FPR(5, %r3)			;\
	SAVE_FPR(6, %r3)			;\
	SAVE_FPR(7, %r3)			;\
	SAVE_FPR(8, %r3)			;\
	SAVE_FPR(9, %r3)			;\
	SAVE_FPR(10, %r3)			;\
	SAVE_FPR(11, %r3)			;\
	SAVE_FPR(12, %r3)			;\
	SAVE_FPR(13, %r3)			;\
	SAVE_FPR(14, %r3)			;\
	SAVE_FPR(15, %r3)			;\
	SAVE_FPR(16, %r3)			;\
	SAVE_FPR(17, %r3)			;\
	SAVE_FPR(18, %r3)			;\
	SAVE_FPR(19, %r3)			;\
	SAVE_FPR(20, %r3)			;\
	SAVE_FPR(21, %r3)			;\
	SAVE_FPR(22, %r3)			;\
	SAVE_FPR(23, %r3)			;\
	SAVE_FPR(24, %r3)			;\
	SAVE_FPR(25, %r3)			;\
	SAVE_FPR(26, %r3)			;\
	SAVE_FPR(27, %r3)			;\
	SAVE_FPR(28, %r3)			;\
	SAVE_FPR(29, %r3)			;\
	SAVE_FPR(30, %r3)			;\
	SAVE_FPR(31, %r3)			;\
	mffs	%f0				;\
	stfd	%f0,STACK_FPSCR(%r3)		;\
	blr

/*
 * R3: struct stack_frame *
 */
.global __restore_fp_state
__restore_fp_state:
	lfd	%f0,STACK_FPSCR(%r3)		;\
	mtfsf	255,%f0,1,0			;\
	REST_FPR(0, %r3)			;\
	REST_FPR(1, %r3)			;\
	REST_FPR(2, %r3)			;\
	REST_FPR(3, %r3)			;\
	REST_FPR(4, %r3)			;\
	REST_FPR(5, %r3)			;\
	REST_FPR(6, %r3)			;\
	REST_FPR(7, %r3)			;\
	REST_FPR(8, %r3)			;\
	REST_FPR(9, %r3)			;\
	REST_FPR(10, %r3)			;\
	REST_FPR(11, %r3)			;\
	REST_FPR(12, %r3)			;\
	REST_FPR(13, %r3)			;\
	REST_FPR(14, %r3)			;\
	REST_FPR(15, %r3)			;\
	REST_FPR(16, %r3)			;\
	REST_FPR(17, %r3)			;\
	REST_FPR(18, %r3)			;\
	REST_FPR(19, %r3)			;\
	REST_FPR(20, %r3)			;\
	REST_FPR(21, %r3)			;\
	REST_FPR(22, %r3)			;\
	REST_FPR(23, %r3)			;\
	REST_FPR(24, %r3)			;\
	REST_FPR(25, %r3)			;\
	REST_FPR(26, %r3)			;\
	REST_FPR(27, %r3)			;\
	REST_FPR(28, %r3)			;\
	REST_FPR(29, %r3)			;\
	REST_FPR(30, %r3)			;\
	REST_FPR(31, %r3)			;\
	blr

/*
 * R3: struct fp_state *
 * R4: is clobbered
 */
.global __save_vsx_state
__save_vsx_state:
	SAVE_VSR(0, %r3)
	SAVE_VSR(1, %r3)
	SAVE_VSR(2, %r3)
	SAVE_VSR(3, %r3)
	SAVE_VSR(4, %r3)
	SAVE_VSR(5, %r3)
	SAVE_VSR(6, %r3)
	SAVE_VSR(7, %r3)
	SAVE_VSR(8, %r3)
	SAVE_VSR(9, %r3)
	SAVE_VSR(10, %r3)
	SAVE_VSR(11, %r3)
	SAVE_VSR(12, %r3)
	SAVE_VSR(13, %r3)
	SAVE_VSR(14, %r3)
	SAVE_VSR(15, %r3)
	SAVE_VSR(16, %r3)
	SAVE_VSR(17, %r3)
	SAVE_VSR(18, %r3)
	SAVE_VSR(19, %r3)
	SAVE_VSR(20, %r3)
	SAVE_VSR(21, %r3)
	SAVE_VSR(22, %r3)
	SAVE_VSR(23, %r3)
	SAVE_VSR(24, %r3)
	SAVE_VSR(25, %r3)
	SAVE_VSR(26, %r3)
	SAVE_VSR(27, %r3)
	SAVE_VSR(28, %r3)
	SAVE_VSR(29, %r3)
	SAVE_VSR(30, %r3)
	SAVE_VSR(31, %r3)
	mffs	%f0
	stfd	%f0,FP_STATE_FPSCR(%r3)
	blr

/*
 * R3: struct fp_state *
 * R4: is clobbered
 */
.global __restore_vsx_state
__restore_vsx_state:
	lfd	%f0,FP_STATE_FPSCR(%r3)
	mtfsf	255,%f0,1,0
	REST_VSR(0, %r3)
	REST_VSR(1, %r3)
	REST_VSR(2, %r3)
	REST_VSR(3, %r3)
	REST_VSR(4, %r3)
	REST_VSR(5, %r3)
	REST_VSR(6, %r3)
	REST_VSR(7, %r3)
	REST_VSR(8, %r3)
	REST_VSR(9, %r3)
	REST_VSR(10, %r3)
	REST_VSR(11, %r3)
	REST_VSR(12, %r3)
	REST_VSR(13, %r3)
	REST_VSR(14, %r3)
	REST_VSR(15, %r3)
	REST_VSR(16, %r3)
	REST_VSR(17, %r3)
	REST_VSR(18, %r3)
	REST_VSR(19, %r3)
	REST_VSR(20, %r3)
	REST_VSR(21, %r3)
	REST_VSR(22, %r3)
	REST_VSR(23, %r3)
	REST_VSR(24, %r3)
	REST_VSR(25, %r3)
	REST_VSR(26, %r3)
	REST_VSR(27, %r3)
	REST_VSR(28, %r3)
	REST_VSR(29, %r3)
	REST_VSR(30, %r3)
	REST_VSR(31, %r3)
	blr

/*
 * R3: struct vr_state *
 * R4: is clobbered
 */
.global __save_vr_state
__save_vr_state:
	SAVE_VR(0, %r3)
	SAVE_VR(1, %r3)
	SAVE_VR(2, %r3)
	SAVE_VR(3, %r3)
	SAVE_VR(4, %r3)
	SAVE_VR(5, %r3)
	SAVE_VR(6, %r3)
	SAVE_VR(7, %r3)
	SAVE_VR(8, %r3)
	SAVE_VR(9, %r3)
	SAVE_VR(10, %r3)
	SAVE_VR(11, %r3)
	SAVE_VR(12, %r3)
	SAVE_VR(13, %r3)
	SAVE_VR(14, %r3)
	SAVE_VR(15, %r3)
	SAVE_VR(16, %r3)
	SAVE_VR(17, %r3)
	SAVE_VR(18, %r3)
	SAVE_VR(19, %r3)
	SAVE_VR(20, %r3)
	SAVE_VR(21, %r3)
	SAVE_VR(22, %r3)
	SAVE_VR(23, %r3)
	SAVE_VR(24, %r3)
	SAVE_VR(25, %r3)
	SAVE_VR(26, %r3)
	SAVE_VR(27, %r3)
	SAVE_VR(28, %r3)
	SAVE_VR(29, %r3)
	SAVE_VR(30, %r3)
	SAVE_VR(31, %r3)
	mfvscr	%v0
	li	%r4,VR_STATE_VSCR
	stvx	%v0,%r4,%r3
	blr

/*
 * R3: struct vr_state *
 * R4: is clobbered
 */
.global __restore_vr_state
__restore_vr_state:
	li	%r4,VR_STATE_VSCR
	lvx	%v0,%r4,%r3
	mtvscr	%v0
	REST_VR(0, %r3)
	REST_VR(1, %r3)
	REST_VR(2, %r3)
	REST_VR(3, %r3)
	REST_VR(4, %r3)
	REST_VR(5, %r3)
	REST_VR(6, %r3)
	REST_VR(7, %r3)
	REST_VR(8, %r3)
	REST_VR(9, %r3)
	REST_VR(10, %r3)
	REST_VR(11, %r3)
	REST_VR(12, %r3)
	REST_VR(13, %r3)
	REST_VR(14, %r3)
	REST_VR(15, %r3)
	REST_VR(16, %r3)
	REST_VR(17, %r3)
	REST_VR(18, %r3)
	REST_VR(19, %r3)
	REST_VR(20, %r3)
	REST_VR(21, %r3)
	REST_VR(22, %r3)
	REST_VR(23, %r3)
	REST_VR(24, %r3)
	REST_VR(25, %r3)
	REST_VR(26, %r3)
	REST_VR(27, %r3)
	REST_VR(28, %r3)
	REST_VR(29, %r3)
	REST_VR(30, %r3)
	REST_VR(31, %r3)
	blr
