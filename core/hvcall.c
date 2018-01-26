// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright 2018 IBM Corp.  */

#include <inttypes.h>
#include <console.h>
#include <stdlib.h>
#include <logging.h>
#include <compiler.h>
#include <stack.h>
#include <processor.h>
#include <cpu.h>
#include <exceptions.h>
#include <hvcall.h>
#include <uvcall.h>
#include <context.h>
#include <svm/svm-rtas.h>

int syscall_hypercall(uint64_t function, struct stack_frame *stack)
{
	if (!(stack->usrr1 & MSR_S)) {
		pr_error("Unsupported Hypercall (Lev=1) function:%llx\n",
			 function);
		pr_error("called from PC=%llx MSR=%llx\n",
			 stack->srr0, stack->srr1);
		return H_HARDWARE;
	}

	if (stack->gpr[3] == H_CEDE)
		stack->usrr1 |= MSR_EE;

	if (stack->gpr[3] == H_RANDOM) {
		/*
		 * @todo: handle H_RANDOM locally.
		 *
		 * This could be a 'security risk' and must be handled as
		 * soon as possible.
		 */
		return H_FUNCTION;
	}

	return ctx_new_context_svm(stack->lpidr, stack, hcall_reflect, 0);
}
