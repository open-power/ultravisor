// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright 2018 IBM Corp.  */

#define pr_fmt(fmt) "CTX: " fmt

#include <inttypes.h>
#include <stdlib.h>
#include <logging.h>
#include <compiler.h>
#include <stack.h>
#include <processor.h>
#include <cpu.h>
#include <exceptions.h>
#include <context.h>
#include <svm_host.h>
#include <uvcall.h>

static void __noreturn ctx_start_context(struct refl_state *r_state,
		void (*func)(struct refl_state *r_state, void *data),
		void *data);

void __noreturn ctx_end_context(struct refl_state *r_state)
{
	struct stack_frame *excp_frame;

	excp_frame = get_exception_frame();

	memcpy(excp_frame, &r_state->excp_frame, sizeof(*excp_frame));

	if (excp_frame->usrr1 & MSR_S)
		fixup_regs_for_svm_entry(excp_frame);

	put_rstate_urfid_return(r_state, excp_frame);
}

static void __noreturn ctx_new_context(struct refl_state *r_state,
			struct stack_frame *frame,
			void (*func)(struct refl_state *r_state, void *data),
			void *data)
{
	r_state->magic = ULTRA_COOKIE_MAGIC;

	memcpy(&r_state->excp_frame, frame, sizeof(*frame));

	ctx_start_context(r_state, func, data);
}

u64 ctx_new_context_svm(u64 lpid, struct stack_frame *frame,
			void (*func)(struct refl_state *r_state, void *data),
			void *data)
{
	struct refl_state *r_state;

	r_state = get_reflect_state_svm(lpid);
	if (!r_state)
		return U_FUNCTION;

	ctx_new_context(r_state, frame, func, data);
}

static void __noreturn ctx_start_context(struct refl_state *r_state,
		void (*func)(struct refl_state *r_state, void *data),
		void *data)
{
	struct stack_frame *tos;

	/*
	 * Switch to new context
	 */
	tos = (struct stack_frame *)(r_state->stack_buffer + STACK_SIZE);
	ctx_switch_context(r_state, data, func, tos);
}
