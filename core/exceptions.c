// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2018 IBM Corp.  */

#include <inttypes.h>
#include <console.h>
#include <stdio.h>
#include <stdlib.h>
#include <logging.h>
#include <compiler.h>
#include <stack.h>
#include <processor.h>
#include <cpu.h>
#include <exceptions.h>
#include <hvcall.h>
#include <uvcall.h>
#include <svm/svm-rtas.h>
#include <svm_host.h>
#include <utils.h>
#include <ppc-opcode.h>
#include <asm-utils.h>
#include <uv/uv-crypto.h>


/*
 * Undef UV_DEBUG after testing for some performance improvements
 * and to skip asserting on warnings.
 */
#define	UV_DEBUG	1

#define REG		"%016llx"
#define REGS_PER_LINE	4
#define _va(x)		((uint64_t)(x) | PPC_BIT(0) | PPC_BIT(1))

/*
 * SRR1 System Call Levels
 */
static inline uint8_t ssr1_sc_level(struct stack_frame *stack)
{
	return (stack->srr1 & SRR1_SC_MASK) >> PPC_BITLSHIFT(43);
}

static inline bool is_hv_interrupt(uint64_t type, uint64_t lpcr)
{
	return (type >= 0xe00 && type <= 0xea0) ||
		(type == 0x500 && !(lpcr & SPR_LPCR_P9_LPES)) ||
		type == 0x980 || type == 0xf80 || type == 0x1500;
}

void dump_regs(const char *msg, struct stack_frame *stack, int gprs)
{
	unsigned int i;

	if (msg)
		pr_error("===== Register dump (%s) =====\n", msg);

	pr_error("SRR0 : "REG" SRR1 : "REG"\n", stack->srr0, stack->srr1);
	pr_error("HSRR0: "REG" HSRR1: "REG"\n", stack->hsrr0, stack->hsrr1);
	pr_error("USRR0: "REG" USRR1: "REG"\n", stack->usrr0, stack->usrr1);
	pr_error("LR   : "REG" CTR  : "REG"\n", stack->lr, stack->ctr);
	pr_error("CFAR : "REG"\n", stack->cfar);
	pr_error("CR   : "REG"  XER: "REG"\n", stack->cr, stack->xer);
	pr_error("DSISR: "REG" DAR  : "REG"\n", stack->dsisr, stack->dar);
	pr_error("LPIDR: "REG" LPCR : "REG"\n", stack->lpidr, stack->lpcr);
	pr_error("HIER : "REG"\n", stack->heir);

	if (!gprs)
		return;

	for (i = 0;  i < 16;  i++)
		pr_error("GPR%02d: "REG" GPR%02d: "REG"\n",
			 i, stack->gpr[i], i + 16, stack->gpr[i + 16]);
}

#if 0
static void log_do_reflect(struct refl_state *r_state, u64 cookie)
{
	uint64_t func;
	struct stack_frame *stack = &r_state->hv_frame;

	func = 0ULL;
	if (r_state->vector == 0xc00)
		func =  stack->gpr[3];

	pr_error("%s(): EXID %lld vector 0x%llX, func 0x%llX, cookie 0x%llx\n",
		 __func__, stack->excp_id, r_state->vector, func, cookie);
}
#else
#define log_do_reflect(x, y)
#endif

static void save_and_mask_sprs(struct refl_state *r_state)
{
#define MASKED_SPR(r, i, v)			\
        r_state->masked_regs[i] = mfspr(r);	\
        mtspr(r, v);				\

#include "masked-sprs-raw.h"

#undef MASKED_SPR
}

static void restore_masked_sprs(struct refl_state *r_state)
{
#define MASKED_SPR(r, i, v)        mtspr(r, r_state->masked_regs[i]);

#include "masked-sprs-raw.h"

#undef MASKED_SPR
}

#ifdef UV_DEBUG
/*
 * Check that various registers have been cleared before entering HV.
 * This is just for debug. The order of registers below is based on
 * the order in doc/reflecting-exceptions.rst which is based on the
 * P9 user manual (and maybe numeric order of registers)
 */
static void check_cleared_regs(struct refl_state *r_state)
{
	struct stack_frame *hvf;
	struct stack_frame *excpf;
	struct svm *svm;

	hvf = &r_state->hv_frame;
	excpf = &r_state->excp_frame;
	svm = r_state->svm;

	if (!svm)			/* silence compiler about unused svm */
		pr_error("svm is %p\n", svm);

	svm_assert(r_state, hvf->cfar == 0ULL);
	svm_assert(r_state, mfspr(SPR_CIABR) == 0ULL);
	svm_assert(r_state, hvf->ctr == 0ULL);
	svm_assert(r_state, hvf->dar == 0ULL || hvf->dar == excpf->dar);
	svm_assert(r_state, mfspr(SPR_DAWR) == 0ULL);
	svm_assert(r_state, mfspr(SPR_DAWRX) == 0ULL);
	/* DEC has a random number, ignore */
	svm_assert(r_state, mfspr(SPR_DSCR) == 0ULL);
	svm_assert(r_state, mfspr(SPR_DSISR) == 0ULL);
	/* FSCR pending */
	svm_assert(r_state, hvf->hdar == 0ULL || hvf->hdar == excpf->hdar);
	svm_assert(r_state, hvf->hdsisr == 0ULL || hvf->hdsisr == excpf->hdsisr);
	svm_assert(r_state, mfspr(SPR_IAMR) == 0ULL);
	svm_assert(r_state, mfspr(SPR_TIDR) == 0ULL);
	svm_assert(r_state, hvf->lr == 0ULL);
	svm_assert(r_state, mfspr(SPR_MMCRC) == 0ULL);
	svm_assert(r_state, mfspr(SPR_PMC1) == 0ULL);
	svm_assert(r_state, mfspr(SPR_PMC2) == 0ULL);
	svm_assert(r_state, mfspr(SPR_PMC3) == 0ULL);
	svm_assert(r_state, mfspr(SPR_PMC4) == 0ULL);
	svm_assert(r_state, mfspr(SPR_PMC5) == 0ULL);
	svm_assert(r_state, mfspr(SPR_PMC6) == 0ULL);
	svm_assert(r_state, mfspr(SPR_PSPB) == 0ULL);
	svm_assert(r_state, mfspr(SPR_SDAR) == 0ULL);
	svm_assert(r_state, mfspr(SPR_SIAR) == 0ULL);
	svm_assert(r_state, mfspr(SPR_SIER) == 0ULL);
	svm_assert(r_state, mfspr(SPR_HEIR) == 0ULL);
	svm_assert(r_state, hvf->sprg0 == 0ULL);
	svm_assert(r_state, hvf->sprg1 == 0ULL);
	svm_assert(r_state, hvf->sprg2 == 0ULL);
	svm_assert(r_state, hvf->sprg3 == 0ULL);
	svm_assert(r_state, mfspr(SPR_TAR) == 0ULL);
	svm_assert(r_state, mfspr(SPR_TRACE) == 0ULL);
	svm_assert(r_state, mfspr(SPR_UAMOR) == 0ULL);
	svm_assert(r_state, mfspr(SPR_VRSAVE) == 0ULL);
	svm_assert(r_state, hvf->xer == 0ULL);

}
#else
#define check_cleared_regs(x)
#endif

/*
 * Disable Performance monitoring (and later clear the PMU registers
 * in fixup_regs_for_hv_entry()) to prevent information leak from UV
 * to HV. Since we disable PMU in UV mode, any "HV mode" counts would
 * be unreliable, so disable PMU in HV also. If HV or SVM enables HV-
 * mode counts we can only warn about it in check_regs_on_svm_exit()).
 *
 * This code is largely based on power_pmu_disable() in v5.6 of Linux
 * kernel. Probably sufficient to disable BHRB, EBB and disable PMU
 * exceptions.
 *
 * We have to do this on every reflection, even if we are entering the
 * HV multiple times before returning to SVM (eg: UV_ESM) because the
 * HV may have altered this PMU state.
 *
 * @todo: We should ideally save the HV's state of PMU registers when
 * 	  we enter UV from HV and restore that state when we later
 * 	  re-enter HV on the next exception from SVM. Saving/restoring
 * 	  state across SVM exceptions is TBD.
 */
static void disable_pmu(void)
{
	uint64_t mmcr0;

	mmcr0 = mfspr(SPR_MMCR0);
	mmcr0 |= MMCR0_FC;
	mmcr0 &= ~(MMCR0_BHRBA | MMCR0_EBE | MMCR0_PMCC | MMCR0_PMAO |
				 MMCR0_PMAE | MMCR0_FC56);

	mtspr(SPR_MMCR0, mmcr0);
	mb();
	isync();

	/* @todo can we avoid the second barrier/sync calls here? */
	mtspr(SPR_MMCRA, mfspr(SPR_MMCRA) & ~(MMCRA_SAMPLE_ENABLE));
	mb();
	isync();
}

/*
 * Initialize registers in r_state->hv_frame stack frame to prepare
 * for entry into the HV. Make sure to clear registers that could leak
 * sensitive information about the SVM and preserve other registers that
 * the HV would need (such as LPIDR, PIDR, LPCR etc).
 */
static void fixup_regs_for_hv_entry(struct refl_state *r_state)
{
	struct stack_frame *hvf;
	struct stack_frame *excpf;

	hvf = &r_state->hv_frame;
	excpf = &r_state->excp_frame;

	/*
	 * Ensure MSR_S is clear, since HV is untrusted
	 */
	hvf->usrr0 = r_state->vector;
	hvf->usrr1 = MSR_SF | MSR_HV | MSR_ME;

	/*
	 * Clear the MSR_ME while reflecting MCE to hypervisor. Hypervisor
	 * will set ME bit immediately after saving SRR0/1, DAR and DSISR
	 * registers which are required for decoding MCE reason. In the worst
	 * scenario if we hit another MCE before hypervisor saves the MCE
	 * reason and set ME bit then system will checkstop and hypervisor
	 * will get restarted cleanly.
	 */
	if (r_state->vector == 0x200)
		hvf->usrr1 &= ~MSR_ME;

	/* Set LE bit iff HV is LE */
	if (hv_is_LE)
		hvf->usrr1 |= MSR_LE;

	/*
	 * If VM had FP/VSX/VEC, forward them to HV as well. Those
	 * regs in hvf will be zero (due to zalloc of refl_state).
	 */
	hvf->usrr1 |= (excpf->usrr1 & (MSR_FP|MSR_VSX|MSR_VEC));

	if (is_hv_interrupt(r_state->vector, excpf->lpcr))
		hvf->usrr1 |= MSR_RI;

	/*
	 * Mask SRR0/HSRR0 with a random value (reuse cookie) to not
	 * leak SVM addresses into HV. uv_return() will also use this
	 * random value to detect a synthesized interrupt from HV.
	 */
	hvf->srr0 = hvf->hsrr0 = hvf->gpr[31];

	/*
	 * Set both SRR1/HSRR1 for the hypervisor. Depending on
	 * the interrupt we're generating for it, it will use one
	 * or other register.
	 *
	 * Set MSR_S in ->srr1, as we maybe in an UV_ESM call from
	 * a (so far) insecure guest.
	 */
	hvf->srr1 = excpf->usrr1 | MSR_S;
	if (r_state->vector == 0xc00) {
		/*
		 * We maybe issuing an hcall in response to an ucall as
		 * in case of UV_ESM, UV_SHARE_PAGE. Fixup the level
		 * field to be an hcall.
		 */
		hvf->srr1 = (hvf->srr1 & ~SRR1_SC_MASK) |
			(SSR1_SC_LEV1 << PPC_BITLSHIFT(43));
	}

	hvf->hsrr1 = hvf->srr1;

	/*
	 * Save and mask (zero) out registers that could leak info.
	 */
	save_and_mask_sprs(r_state);

	/* SPR_IC is special in that we must *update* it when restoring */
	r_state->ic = mfspr(SPR_IC);
	mtspr(SPR_IC, 0ULL);

	/*
	 * Mask decrementer with the max value, except in the case of
	 * H_CEDE as that would result in the guest not running again
	 * until the decrementer fires (about 4 seconds at 512MHz).
	 */
	if (hvf->gpr[3] == H_CEDE)
		hvf->dec = excpf->dec;
	else
		hvf->dec = 0x7FFFFFFF;

	/*
	 * Copy over registers that HV might need from exception frame.
	 * These registers can be "ignored" from a security point of
	 * view as they don't contain any sensitive info about the SVM.
	 */
	hvf->hsprg0 = excpf->hsprg0;
	hvf->hsprg1 = excpf->hsprg1;
	hvf->lpcr = excpf->lpcr;
	hvf->lpidr = excpf->lpidr;
	hvf->pidr = excpf->pidr;

	/*
	 * Forward interrupt-specific registers to HV as needed,
	 * from the original exception frame. [H]SRR0/1 and hence
	 * MSR (indirectly) were set above. Update others.
	 *
	 * Following interrupts only update [H]SRR0/1 so are not
	 * included in the switch table below:
	 *
	 * 	0x400:		// Instruction Storage
	 * 	0x480:		// Data Segment
	 * 	0x500:		// External
	 * 	0x700:		// Program
	 * 	0x800:		// Floating Point Unavailable
	 * 	0x900:		// Decrementer
	 * 	0x980:		// HV Decrementer
	 * 	0xA00:		// Directed Privileged Doorbell
	 * 	0xC00:		// System Call
	 *
	 * Followinging interrupts are handled by the SVM and should
	 * not result in an UV exception (exception_entry() aborts if
	 * they do):
	 *
	 *	0x300:		// Data Storage
	 *	0x380:		// Data Segment
	 *	0xD00:		// Trace Interupt
	 *	0x600:		// Alignment
	 *
	 * @todo: It is highly unlikely that HDSISR, HDAR and ASDR
	 * 	  changed since we entered UV for the exception. If
	 * 	  they never change, we could optimize by not saving/
	 * 	  restoring them on our stack frames. But if they do
	 * 	  change we want to make sure to forward the correct
	 * 	  values to the HV. So, if we hit this assert for a
	 * 	  valid reason during our testing, just drop the
	 * 	  assert! Otherwise consider dropping the code that
	 * 	  saves/restores that register.
	 * @note: Bypass the checks when aborting an svm - as we may
	 * 	  have a "minimally initialized" reflect state.
	 */
	if (!r_state->skip_debug_checks) {
		assert(excpf->hdsisr == mfspr(SPR_HDSISR));
		assert(excpf->hdar == mfspr(SPR_HDAR));
		assert(excpf->asdr == mfspr(SPR_ASDR));
	}
	switch(r_state->vector) {
	case 0x200:		/* Machine check */
		hvf->dsisr = excpf->dsisr;
		hvf->dar = excpf->dar;
		hvf->asdr = excpf->asdr;
		break;

	case 0xE00:		/* HV Data Storage */
		hvf->hdsisr = excpf->hdsisr;
		hvf->hdar = excpf->hdar;
		hvf->asdr = excpf->asdr;
		break;

	case 0xE20:		/* HV Instruction Storage */
		hvf->hdar = excpf->hdar;
		hvf->asdr = excpf->asdr;
		break;

	case 0xE40:		/* HV Emulation Assitance Interrupt */
		/* @todo save HEIR */
		break;

	default:
		break;
	}

	/* BHRB is security-sensitive, so clear any entries in it */
	asm(PPC_CLRBHRB);

}
#define EXCP_SRC(stack)		(stack->usrr1 & MSR_HV) ? "HV" : "SVM"

static void check_ebb_tm_status(struct stack_frame *stack)
{
	uint64_t hfscr, fscr, bescr, msr;

	hfscr = mfspr(SPR_HFSCR);
	if (hfscr & (HFSCR_EBB|HFSCR_TM)) {
		pr_debug_once("Insecure feature (hfscr 0x%llx) in %s!\n",
			      hfscr, EXCP_SRC(stack));
	}

	fscr = mfspr(SPR_FSCR);
	if (fscr & FSCR_EBB) {
		pr_debug_once("Insecure feature (fscr 0x%llx) in %s!\n",
			      fscr, EXCP_SRC(stack));
	}

	/*
	 * Warn if EBB or PME-based exceptions are enabled/occured.
	 */
	bescr = mfspr(SPR_BESCR);
	if (bescr & (BESCR_GE|BESCR_EE|BESCR_PME|BESCR_EEO|BESCR_PMEO)) {
		pr_debug_once("Insecure feature (bescr 0x%llx) in %s!\n",
			      bescr, EXCP_SRC(stack));
	}

	msr = mfmsr();
	if (msr & MSR_TM) {
		pr_debug_once("TM enabled in %s? Issuing TABORT\n",
			      EXCP_SRC(stack));
		asm(TABORT0);
	} else {
#ifdef UV_DEBUG
		/* HW team would like to assert these when TM is off */
		assert(!MSR_TM_TRANSACTIONAL(msr));
		assert(!MSR_TM_SUSPENDED(msr));
#endif
	}
}

void fixup_regs_on_hv_exit(struct refl_state *r_state)
{
	struct stack_frame *excpf;

	restore_masked_sprs(r_state);

	/*
	 * when restoring SPR_IC, *update* the count with # of
	 * instructions executed in HV
	 */
	mtspr(SPR_IC, r_state->ic + mfspr(SPR_IC));

	excpf = &r_state->excp_frame;

	/* Ensure HV has not changed LPIDR */
	if (mfspr(SPR_LPIDR) != excpf->lpidr) {
		pr_warn_once("HV changed LPIDR: 0x%llx -> 0x%lx\n",
			     excpf->lpidr, mfspr(SPR_LPIDR));
		svm_abort(r_state);
	}

	/* Ensure HV has not changed PIDR */
	if (mfspr(SPR_PIDR) != excpf->pidr) {
		pr_warn_once("HV changed PIDR: 0x%llx -> 0x%lx\n",
			     excpf->pidr, mfspr(SPR_PIDR));
		svm_abort(r_state);
	}

	/*
	 * NOTE:
	 * UV does not use FPU/VSX/VEC registers so we can restore them
	 * before returning to VM. Restoring them here is wasteful if
	 * we are going to reflect other hcalls before eventually
	 * returning to VM (like we do with UV_ESM).
	 */

	check_ebb_tm_status(excpf);
}

static void enable_msr_fp(uint64_t msr, bool vsx, bool vec)
{
	msr |= MSR_FP;
	if (vsx)
		msr |= MSR_VSX;
	if (vec)
		msr |= MSR_VEC;

	/*
	 * We want the mtmsr to be context-synchronizing so that the FP/
	 * VSX instructions that follow the mtmsr will execute with the
	 * FP|VSX enabled, otherwise they could get an FPU exception.
	 */
	mtmsrd(msr, 0);
}

static void restore_msr_fp(uint64_t msr)
{
	/*
	 * Restore MSR -  we may have set FP|VSX above. This can be
	 * "execution synchronized" since we won't issue any FP|VSX
	 * instructions after this.
	 */
	mtmsrd(msr, 1);
}

/* prototypes of asm functions */
extern void __save_fp_state(struct stack_frame *sf);
extern void __save_vr_state(struct vr_state *fp);
extern void __save_vsx_state(struct fp_state *fp);
extern void __restore_fp_state(struct stack_frame *sf);
extern void __restore_vr_state(struct vr_state *fp);
extern void __restore_vsx_state(struct fp_state *fp);

static struct vr_state zero_vr;
static struct stack_frame zero_frame;

/* see load_vr_state() and store_vr_state() for MSR_VEC */
static void save_clear_fp_state(struct stack_frame *stack)
{
	bool vec, vsx;
	uint64_t saved_msr;
	struct fp_state zero_fp;

	/*
	 * @todo: Applications may use the FPU/VEC/VSX registers even
	 * 	  if the MSR bits don't indicate that they are. Save
	 * 	  (and later restore) these registers unconditionally.
	 */
	if (!(stack->usrr1 & (MSR_FP|MSR_VSX|MSR_VEC)))
		return;

	vsx = stack->usrr1 & MSR_VSX;
	vec = stack->usrr1 & MSR_VEC;

	/*
	 * Most interrupts disable FP/VSX/VEC access. Temporarily
	 * reenable them before accessing those registers.
	 */
	saved_msr = mfmsr();
	enable_msr_fp(saved_msr, vsx, vec);

	memset(&zero_fp, 0, sizeof(zero_fp));

	if (vsx) {
		__save_vsx_state(&stack->fp_state);
		__restore_vsx_state(&zero_fp);
	} else if (vec) {
		__save_vr_state(&stack->vr_state);
		__restore_vr_state(&zero_vr);
	} else {
		__save_fp_state(stack);
		__restore_fp_state(&zero_frame);
	}
	/* Restore saved MSR state - we may have set FP/VSX/VEC above */
	restore_msr_fp(saved_msr);
}

void restore_fp_state(struct stack_frame *stack)
{
	bool fp, vec, vsx;
	uint64_t saved_msr;

	/*
	 * Check if SVM had FP/VSX/VEC enabled at the time of exception.
	 * Note that for synthesized interrupts the guest MSR at the
	 * time of exception will be in SRR1 rather than USRR1. See
	 * exception_svm_reflect_prep().
	 *
	 * @todo: Applications may use the FPU/VEC/VSX registers even
	 * 	  if the MSR bits don't indicate that they are. Save
	 * 	  (and restore) these registers unconditionally.
	 */
	if (stack->flags & STACK_FLAGS_SYNTH_INTR) {
		fp = stack->srr1 & MSR_FP;
		vsx = stack->srr1 & MSR_VSX;
		vec = stack->srr1 & MSR_VEC;
	} else {
		fp = stack->usrr1 & MSR_FP;
		vsx = stack->usrr1 & MSR_VSX;
		vec = stack->usrr1 & MSR_VEC;
	}

	/* if it didn't, nothing to restore */
	if (!fp && !vsx && !vec)
		return;

	/* temporarily enable FP/VSX/VEC access before restoring */
	saved_msr = mfmsr();
	enable_msr_fp(saved_msr, vsx, vec);

	if (vsx)
		__restore_vsx_state(&stack->fp_state);
	else if (vec)
		__restore_vr_state(&stack->vr_state);
	else
		__restore_fp_state(stack);

	/* restore saved MSR state - we may have set FP/VSX/VEC above */
	restore_msr_fp(saved_msr);
}

/*
 * Fix up registers in preparation for returning to SVM.
 */
void fixup_regs_for_svm_entry(struct stack_frame *stack)
{
	uint64_t hfscr;

	/*
	 * NOTE: Not disabling the following, since we plan to zero them
	 * 	 when entering HV and restore them when entering SVM
	 * 	 	TAR, DSCR
	 */
	hfscr = mfspr(SPR_HFSCR);
	hfscr &= ~HFSCR_TM;
	hfscr |= HFSCR_MSGP;
	mtspr(SPR_HFSCR, hfscr);

	mtspr(SPR_TRACE, 0ULL);
	mtspr(SPR_DPDES, 0ULL);

	/*
	 * Update the decrementer, taking into account the new TB.
	 * This can cause decr to go negative in which case the guest
	 * will handle it soon after entry into the guest.
	 */
	stack->dec = stack->dec_expiry - mfspr(SPR_TBRL);

	/*
	 * We could possibly allow PURR/SPURR to count in SVM and just
	 * mask them on HV entry to prevent information leak. But when
	 * we restore on return from HV, the values will be inconsistent?
	 * Disable PURR/SPURR in SVMs for now.
	 */
	stack->lpcr = mfspr(SPR_LPCR) & ~(SPR_LPCR_ONL);

	/*
	 * Freeze counters in HV mode since the counts will be unreliable.
	 * SVM could override this change but only thing we can do is
	 * warn about it (in check_regs_on_svm_exit()).
	 */
	stack->mmcr0 |= (MMCR0_FCH);

	restore_fp_state(stack);
}

/*
 * Reflect the exception r_state->vector to the HV.
 */
static void do_reflect(struct refl_state *r_state)
{
	int rc;
	u64 cookie;
	struct stack_frame *frame = &r_state->hv_frame;

	cookie = svm_generate_cookie(r_state->svm, r_state,
			HSRR0_MASK, MAX_EXCEPTION);
	log_do_reflect(r_state, cookie);

	rc = refl_state_save_regs(&r_state->saved_regs);

	if (rc == 0) {
		struct svm *svm = r_state->svm;

		/* Save cookie so we can retrieve state in uv_return */
		frame->gpr[31] = cookie;

		/*
		 * Save vcpu so that we can tell on the way back if we changed
		 * the physical CPU we're running on.
		 */
		if (svm->vcpus.tracking) {
			/*
			 * We're not running the guest vcpu anymore when
			 * reflecting to the hypervisor.
			 */
			r_state->vcpu = this_cpu()->vcpu;
			invalidate_vcpuid(&this_cpu()->vcpu);

			/* Sanity check */
			if (r_state->vcpu.vcpuid >= svm->vcpus.max ||
			    r_state->vcpu.lpid != svm->lpid) {
				pr_error("%s: Reflecting from unknown vcpu %u (lpid %llx)\n",
					 __func__, r_state->vcpu.vcpuid,
					 svm->lpid);
				/*
				 * svm_abort() calls do_reflect() so we need to
				 * avoid infinite recursion.
				 */
				svm->vcpus.tracking = false;
				svm_abort(r_state);
				/* NOTREACHED */
			}
		} else
			invalidate_vcpuid(&r_state->vcpu);

		/* Initialize SPRs for the reflection */
		fixup_regs_for_hv_entry(r_state);

		/* do this just before urfid */
		check_cleared_regs(r_state);

		/* enter HV */
		urfid_return(frame);

		/* @todo: abort here? kill svm? */
		pr_error("%s() ***** urfid_return FAILED ??? *****\n", __func__);
	} else {
		/*
		 * Results from the hcall are in r_state->hv_frame.
		 * Clear the cookie.
		 */
		frame->gpr[31] = 0;
	}
}

/**
 * get_next_random64()
 * Use bytes in @buf, starting at @start, to extract and return a 64-bit
 * number. If we don't have enough random bytes in @buf, fill in @buf with
 * a fresh set of random bytes and update @start accordingly. Assume that
 * the buffer is @len in size.
 */
static uint64_t get_next_random64(char *buf, int len, int *start)
{
	int i;
	uint64_t num;

	assert(len >= 64);	/* rand_bytes() requires 64+ bytes? */

	if (*start == -1 || ((len - *start) < 8)) {
		uv_crypto_rand_bytes(buf, len);
		*start = 0;
	}

	num = 0ULL;
	for (i = *start; i < 8; i++)
		num = (num << 8) | buf[i];

	*start += 8;

	return num;
}

/*
 * If we just returned from a reflected hcall, load its results
 * into the exception frame.
 */
static void load_hcall_results(struct refl_state *r_state)
{
	int i;

	if (r_state->excp_frame.type != 0xc00)
		return;

	/* hcall results start at R3 - hence the +3 below */
	for (i = 0; i < r_state->n_output_regs; i++)
		r_state->excp_frame.gpr[i+3] = r_state->hv_frame.gpr[i+3];
}

/*
 * Reflect an exception to the hypervisor other than a hcall.
 */
void __noreturn exception_reflect(struct refl_state *r_state, void *UNUSED(arg))
{
	assert(!(r_state->excp_frame.hsrr1 & MSR_HV));

	memset(&r_state->hv_frame, 0, sizeof(struct stack_frame));

	if (!is_frequent_exception(r_state->excp_frame.type))
		pr_info("reflect intr %llx to HV from %llx %llx\n",
			r_state->excp_frame.type, r_state->excp_frame.usrr0,
			r_state->excp_frame.usrr1);

	r_state->vector = r_state->excp_frame.type;
	do_reflect(r_state);

	ctx_end_context(r_state);

	/* NOTREACHED */
}

/**
 * Initialize the hcall frame:
 * 	- Copy hcall input registers into hcall frame
 * 	- Make a note of # of output registers for hcall
 * 	- Randomize the other GPR, FPR and SPRs
 */
static void init_hcall_frame(struct refl_state *r_state)
{
	int i;
	int len;
	int start;
	int n_gprs;
	char buf[256];			/* for 32 uint64_t random numbers */
	int16_t n_in, n_out;
	struct stack_frame *hvf;
	struct stack_frame *excpf;

	len = sizeof(buf);
	hvf = &r_state->hv_frame;
	excpf = &r_state->excp_frame;

	/*
	 * Copy the hcall input registers from the exception frame
	 * and zero the remaining.
	 */
	memset(&r_state->hv_frame, 0, sizeof(struct stack_frame));

	/* R3 has the hcall number */
	get_n_hcall_regs(excpf->gpr[3], &n_in, &n_out);

	n_gprs = sizeof(hvf->gpr) / sizeof(hvf->gpr[0]);

	/* hcall registers start with R3 - hence the '3's below */
	start = -1;
	for (i = 0; i < n_gprs; i++) {
		if (i >= 3 && i < n_in + 3)
			hvf->gpr[i] = excpf->gpr[i];
		else
			hvf->gpr[i] = get_next_random64(buf, len, &start);
	}

	/*
	 * @todo: Randomize FPRs and other registers
	 */

	r_state->hcall = excpf->gpr[3];
	r_state->n_input_regs = n_in;
	r_state->n_output_regs = n_out;
}

static void __noreturn reflect_rtas_hcall(struct refl_state *r_state)
{
	int rc;
	uint64_t retbuf[1];

	rc = svm_rtas(r_state);
	if (rc)
		pr_error("%s: svm_rtas, rc [%d]\n", __func__, rc);

	retbuf[0] = 0xdeadbead;
	rc = do_hcall(r_state, H_RTAS, 1, retbuf, 1, r_state->rtas_bb_args_gpa);
	if (rc) {
		pr_error("%s() EXID 0x%llx, H_RTAS hcall token 0x%llx failed, "
			 "rc %d, retbuf 0x%llx\n", __func__,
			 r_state->excp_frame.excp_id, r_state->token,
			 rc, retbuf[0]);
	}

	svm_rtas_return(r_state);

	ctx_end_context(r_state);
	/* NOTREACHED */
}

void __noreturn hcall_reflect(struct refl_state *r_state, void *UNUSED(arg))
{
	assert(!(r_state->excp_frame.srr1 & MSR_HV));

	if (r_state->excp_frame.gpr[3] == H_RTAS) {
		reflect_rtas_hcall(r_state);
		/* NOTREACHED */
	}

	init_hcall_frame(r_state);

	r_state->vector = r_state->excp_frame.type;
	do_reflect(r_state);

	load_hcall_results(r_state);

	ctx_end_context(r_state);

	/* NOTREACHED */
}

/*
 * This is called when the ultravisor needs to do a hcall to the
 * hypervisor as part of processing an interrupt (including a syscall)
 * from a secure guest.  To the hypervisor it appears that the hcall
 * is coming from the point in the secure guest where the original
 * interrupt happened.
 *
 * The differences between this call and hcall_reflect() are:
 *	- this call gets the hcall input and output parameters in its
 *	  arguments list while hcall_reflect() gets them in exception
 *	  frame.
 *	- hcall_reflect has to deal with setting up a bounce buffer for
 *	  some hcalls
 */
int64_t do_hcall(struct refl_state *r_state, uint64_t opcode,
		uint8_t arg_cnt, uint64_t *retbuf, uint8_t ret_cnt, ...)
{
	int i;
	struct stack_frame *hvf;
	va_list args;

	hvf = &r_state->hv_frame;

	/*
	 * @NOTE: We don't need to clear the hv_frame. We started with a
	 *        zeroed buffer when we allocated r_state, so the first
	 *        hcall we issued would have had 0s in unused registers.
	 *        If we are issuing more than one hcalls for the same UV
	 *        exception (eg: in case of UV_ESM), the second hcall
	 *        would just have "left-over" values in the registers
	 *        from the previous hcall. The HV has seen or may even
	 *        have loaded them. There is no security risk/leak in
	 *        letting them be and skipping the memset() could save
	 *        a few cycles. However check_cleared_regs() has asserts
	 *        that no information is leaking in registers we expect
	 *        to be cleared. So, leave this memset() for now.
	 */
	memset(hvf, 0, sizeof(*hvf));

	hvf->gpr[3] = opcode;

	va_start(args, ret_cnt);

	for (i = 0; i < arg_cnt; i++)
		hvf->gpr[i+4] = va_arg(args, u64);

	va_end(args);

	r_state->vector = 0xc00;
	(void)do_reflect(r_state);

	if (ret_cnt) {
		for (i = 0; i < ret_cnt; i++) {
			retbuf[i] = hvf->gpr[i+4];
		}
	}

	return (int)hvf->gpr[3];
}

static void __noreturn syscall_entry(struct stack_frame *stack)
{
	int rc = 0;
	switch(ssr1_sc_level(stack)) {
	case SSR1_SC_LEV2:
		rc = syscall_ultracall(stack->gpr[3], stack);
		break;
	case SSR1_SC_LEV1:
		svm_task(stack);
		rc = syscall_hypercall(stack->gpr[3], stack);
		break;
	case SSR1_SC_LEV0:
		pr_error("Unsupported System Call (Lev=0) function:%lld\n", stack->gpr[0]);
		break;
	default:
		pr_error("Unsupported System Call Level\n");
	}

	stack->gpr[3] = rc;
	urfid_return(stack);
}

/*
 * Hack to deal with mess of ultra log wrapping without marker.
 * Assign an unique id to each exception and use the id when logging.
 * Recommend format with "EXID %lld" so we can use a script to find the
 * last exception id quickly.
 *
 * Note that each uv_return() gets a new id so we need something else
 * to associate it with its original call.
 */
struct lock excp_counter_lock = LOCK_UNLOCKED;
u64 excp_counter;
static u64 assign_excp_id(void)
{
	u64 rc;

	lock(&excp_counter_lock);
	rc = excp_counter++;
	unlock(&excp_counter_lock);

	return rc;
}

int log_all;
#ifdef LOG_EXCEPTIONS	/* log interesting exceptions */
/*
 * Skip logging expected/success messages by default.
 * Log space is scarce :-(
 */
static void log_exception(struct stack_frame *stack)
{
	uint64_t func;
	int level;

	func = 0;
	level = ssr1_sc_level(stack);
	if (level == SSR1_SC_LEV1)
		func = stack->gpr[3];
	else if (level == SSR1_SC_LEV2)
		func = stack->gpr[3];

	if (log_all)
		goto log_it;

	if (stack->type != 0xC00) {
		if (!is_frequent_exception(stack->type))
			pr_debug("EXID %lld: type 0x%llX\n", stack->excp_id,
				 stack->type);
		return;
	}

	switch(func) {
		case H_CEDE:
		case H_CONFER:
		case H_EOI:
		case H_IPI:
		case H_RTAS:
		case H_XIRR:
		case UV_RETURN:
		case UV_PAGE_IN:
		case UV_PAGE_OUT:
		case UV_READ_SCOM:
		case UV_WRITE_SCOM:
		case UV_PAGE_INVAL:
		case H_GET_TERM_CHAR:
		case H_PUT_TERM_CHAR:
		case UV_RESTRICTED_SPR_READ:
		case UV_RESTRICTED_SPR_WRITE:
			return;
		default:
			break;
	}

log_it:
	pr_debug("EXID %lld: type 0x%llX, lev %d, func 0x%llX\n",
		 stack->excp_id, stack->type, level, func);
}
#else /* LOG_EXCEPTIONS	*/
#define log_exception(x)
#endif /* LOG_EXCEPTIONS */

/*
 * These xSRR1 bits are used for reporting status on interrupts.
 */
#define SRR1_INTR_STATUS	0x783f0000ul
void exception_svm_reflect_prep(struct stack_frame *stack,
				uint64_t intr_status,
				uint64_t exception,
				uint64_t msr)
{
	stack->srr0 = stack->usrr0;
	stack->srr1 = (stack->usrr1 & ~SRR1_INTR_STATUS) |
			(intr_status & SRR1_INTR_STATUS);

	stack->usrr0 = exception;
	stack->usrr1 = MSR_SF | MSR_S | MSR_ME |
			(msr & MSR_LE);
}

/*
 * @stack:  pointer to the reflection stack.
 * @intr_status:  intr flags when program resumes execution at @ret_addr
 * @exception: exception to reflect to the SVM.
 * @msr: msr value when exception is reflected into the SVM.
 */
static void __noreturn exception_svm_reflect(struct stack_frame *stack,
				uint64_t intr_status,
				uint64_t exception,
				uint64_t msr)
{
	exception_svm_reflect_prep(stack, intr_status, exception, msr);
	urfid_return(stack);
}

static void check_regs_on_svm_exit(struct stack_frame *stack)
{
	check_ebb_tm_status(stack);

	/*
	 * If for some reason, PURR/SPURR are counting, print a
	 * warning. We will clear the counters before HV-entry
	 * and will disable counting before SVM-entry.
	 */
	if (mfspr(SPR_LPCR) & SPR_LPCR_ONL) {
		pr_debug_once("PURR/SPURR enabled in SVM? LPCR 0x%016lx\n",
			     mfspr(SPR_LPCR));
	}

	if (!(stack->mmcr0 & MMCR0_FCH)) {
		pr_debug_once("PMU counts in HV mode unreliable in SVMs\n");
	}
}

/* Called from exceptions.S, thus no prototype */
void __noreturn exception_entry(struct stack_frame *stack);

void __noreturn exception_entry(struct stack_frame *stack)
{
	uint64_t pc, msr;

	/*
	 * First work out which of SRR0/1, HSRR0/1 or USRR0/1
	 * tells us where we came from.
	 */
	if (is_hv_interrupt(stack->type, stack->lpcr)) {
		pc = stack->hsrr0;
		msr = stack->hsrr1;
	} else {
		pc = stack->srr0;
		msr = stack->srr1;
	}

	/* Put those into stack->usrr0/1 ready for a possible return. */
	stack->usrr0 = pc;
	stack->usrr1 = msr;
	stack->flags = 0ULL;
	stack->excp_id = assign_excp_id();

	disable_pmu();

	if (stack->usrr1 & MSR_S) {
		check_regs_on_svm_exit(stack);
		save_clear_fp_state(stack);
	}

	stack->dec_expiry = stack->dec + mfspr(SPR_TBRL);

	log_exception(stack);

	/* If we got an interrupt in the ultravisor itself, that's bad */
	if ((msr & (MSR_HV | MSR_PR | MSR_S)) == (MSR_HV | MSR_S)) {
		pr_error("EXID 0x%llx Exception Type=0x%llx\n",
			 stack->excp_id, stack->type);
		dump_regs("Bad interrupt in ultravisor", stack, 1);
		_abort("panic");
	}

	switch(stack->type) {
	case 0xc00:
		syscall_entry(stack);
		break;

	case 0xe40:
		if (svm_e40_handle(stack, stack->heir))
			pr_error("e40 exception HANDLING failed "
				 "hsrr0=%llx heir=%llx\n",
				 stack->hsrr0,stack->heir);
		break;
	case 0x100:
	case 0x200:
	case 0x980:
		/* Hypervisor Decrementer */
		svm_task(stack);
		/* FALL THROUGH */
	case 0xe60:
	case 0xe80:
	case 0xea0:
		ctx_new_context_svm(stack->lpidr, stack, exception_reflect, 0);
		break;

	case 0xf80:
		svm_f80_handle(stack);
		break;

	case 0x500:
#if 0
		pr_error("EXPECTED 0x500 exception HANDLING %llx hsrr0=%llx "
			 "hsrr1=%llx usrr0=%llx, usrr1=%llx!\n",
			 stack->type, stack->hsrr0, stack->hsrr1,
			 stack->usrr0, stack->usrr1);
#endif
		/*
		 * u-turn the exception to the guest.
		 *
		 * @todo: ideally -- if LPCR[LPES]=0, Uturn to SVM
		 *        and if LPCR[LPES]=1, reflect to HV
		 *
		 * LPES=1 implies, no Hypervisor exists. The kernel runs in
		 * Supervisor mode.
		 * Current assumption is -- No Hypervisor means no Ultravisor.
		 * LPES checking will be needed the day the above assumption
		 * turns false.
		 */
		exception_svm_reflect(stack, 0, stack->type, stack->usrr1);
		break;

	case 0xe20:
#if 0
		pr_error("EXPECTED e20 exception HANDLING %llx hsrr0=%llx "
			 "hsrr1=%llx hdar=%llx, asdr=%llx!\n",
			 stack->type, stack->hsrr0, stack->hsrr1, stack->hdar,
			 stack->asdr);
#endif
		if (svm_e20_handle(stack, stack->asdr))
			pr_error("e20 exception HANDLING failed hsrr0=%llx\n",
				 stack->hsrr0);
		break;

	case 0xe00:
#if 0
		pr_error("EXPECTED e00 exception HANDLING %llx "
			 "hdar=%llx asdr=%llx!\n",
			 stack->type, stack->hdar, stack->asdr);
		pr_error(" at PC=%llx MSR=%llx\n", stack->usrr0, stack->usrr1);
#endif
		if (svm_e00_handle(stack, stack->asdr))
			pr_error("e00 exception HANDLING failed hdar=%llx\n",
				 stack->asdr);
		break;

	default:
		pr_error("***********************************************\n");
		pr_error("Unexpected exception %llx !\n", stack->type);
	}

	dump_regs("Unexpected exception", stack, 1);
	urfid_return(stack);
}
