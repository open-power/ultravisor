// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright 2018 IBM Corp.  */
#ifndef CONTEXT_H
#define CONTEXT_H
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <stack.h>
#include <core/masked-sprs.h>
#include <cpu.h>

#define ULTRA_COOKIE_MAGIC	0xabcddcbaabcddcbaULL

/*
 * excp_frame:	state of registers when UV got the exception/hcall.
 *
 * saved_regs:	state of UV registers just before reflecting exception/
 * 		hcall to HV (different from excp_frame!).
 *
 * vector	Reflected vector and...
 *
 * hcall	reflected hcall. This value may differ from the one in
 *		excp_frame.gpr[3] because we maybe issuing an hcall in
 *		response to an ucall (eg: UV_ESM).
 *
 * hv_frame:	State with which we enter HV when issuing/reflecting an
 * 		exception/hcall. Also used to store hcall results from HV.
 *
 * masked_regs:	Saved state of registers that are masked before entering
 * 		HV (to prevent information leak). Used to save/restore
 * 		state when transitioning between UV and HV. These are
 * 		registers that maybe used by SVM but are not used by UV
 * 		itself. We could add them to stack frame, but we don't
 * 		need to save/restore these when transitioning between UV
 * 		and SVM. Besides, separating them out keeps stack_frame
 * 		smaller.
 *
 * ic:		When reflecting exceptions to HV, we must clear SPR_IC
 *		and upon return, increment the SPR_IC by # of instructions
 *		executed in HV. We don't need to save/restore when
 *		transitioning between UV/SVM.
 */
struct refl_state {
	char stack_buffer[STACK_SIZE];	/* align to 16 bytes */
	struct stack_frame saved_regs;	/* regs at getcontext */
	struct stack_frame hv_frame;	/* regs for hv entry */
	struct stack_frame excp_frame;	/* regs at exception */

	struct svm *svm;

	uint64_t masked_regs[MASKED_SPR_LAST];
	uint64_t ic;
	uint64_t hcall;
	uint64_t vector;
	int16_t  n_input_regs;		/* # of hcall input regs, incl r3 */
	int16_t  n_output_regs;		/* # of hcall output regs, incl r3 */

	int	id;
	uint64_t token;

	bool active;
	bool skip_debug_checks;		/* skip debug checks on abort */

	uint64_t rtas_bb_args_gpa;

	struct vcpu vcpu;		/* SVM vcpu we're serving */

	uint64_t magic;
	struct list_node link;
} __attribute__((aligned(16)));

extern void __noreturn ctx_end_context(struct refl_state *r_state);
extern u64 ctx_new_context_svm(u64 lpid, struct stack_frame *frame,
		void (*func)(struct refl_state *r_state, void *data),
		void *data);
extern void __noreturn ctx_switch_context(struct refl_state *r_state, void *data,
		void (*func)(struct refl_state *r_state, void *data),
		void *stack);
#endif
