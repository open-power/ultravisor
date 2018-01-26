// SPDX-License-Identifier: GPL-2.0+
/*
 * POWER instruction analyser.
 * Based on Linux' arch/powerpc/lib/sstep.c.
 *
 * Copyright (C) 2004 Paul Mackerras <paulus@au.ibm.com>, IBM
 * Copyright 2018 IBM Corp.
 */

#include <instr.h>
#include <stack.h>

#ifdef DEBUG
#include <logging.h>
#endif

/*
 * Calculate effective address for a D-form instruction
 */
static unsigned long dform_ea(unsigned int instr,
			      const struct stack_frame *stack)
{
	int ra;
	unsigned long ea;

	ra = (instr >> 16) & 0x1f;
	ea = (signed short) instr;		/* sign-extend */
	if (ra)
		ea += stack->gpr[ra];

	return ea;
}

/*
 * Calculate effective address for a DS-form instruction
 */
static unsigned long dsform_ea(unsigned int instr,
			       const struct stack_frame *stack)
{
	int ra;
	unsigned long ea;

	ra = (instr >> 16) & 0x1f;
	ea = (signed short) (instr & ~3);	/* sign-extend */
	if (ra)
		ea += stack->gpr[ra];

	return ea;
}

/*
 * Calculate effective address for a DQ-form instruction
 */
static unsigned long dqform_ea(unsigned int instr,
			       const struct stack_frame *stack)
{
	int ra;
	unsigned long ea;

	ra = (instr >> 16) & 0x1f;
	ea = (signed short) (instr & ~0xf);	/* sign-extend */
	if (ra)
		ea += stack->gpr[ra];

	return ea;
}

/*
 * Calculate effective address for an X-form instruction
 */
static unsigned long xform_ea(unsigned int instr,
			      const struct stack_frame *stack)
{
	int ra, rb;
	unsigned long ea;

	ra = (instr >> 16) & 0x1f;
	rb = (instr >> 11) & 0x1f;
	ea = stack->gpr[rb];
	if (ra)
		ea += stack->gpr[ra];

	return ea;
}

static unsigned long byterev_2(unsigned long x)
{
	return ((x >> 8) & 0xff) | ((x & 0xff) << 8);
}

static unsigned long byterev_4(unsigned long x)
{
	return ((x >> 24) & 0xff) | ((x >> 8) & 0xff00) |
		((x & 0xff00) << 8) | ((x & 0xff) << 24);
}

static unsigned long byterev_8(unsigned long x)
{
	return (byterev_4(x) << 32) | byterev_4(x >> 32);
}

/*
 * Decode an instruction, and return information about it in *op
 * without changing *regs.
 * Integer arithmetic and logical instructions, branches, and barrier
 * instructions can be emulated just using the information in *op.
 *
 * Return value is 1 if the instruction can be emulated just by
 * updating *regs with the information in *op, -1 if we need the
 * GPRs but *regs doesn't contain the full register set, or 0
 * otherwise.
 */
int analyse_instr(struct instruction_op *op, const struct stack_frame *stack,
		  unsigned int instr)
{
	unsigned int opcode, ra, rd, u;

	opcode = instr >> 26;

	rd = (instr >> 21) & 0x1f;
	ra = (instr >> 16) & 0x1f;

	switch (opcode) {
	case 31:
		/* isel occupies 32 minor opcodes */
		if (((instr >> 1) & 0x1f) == 15) {
			op->type = UNKNOWN;
			goto out;
		}

		switch ((instr >> 1) & 0x3ff) {
		/*
		 * Cache instructions
		 */
		case 54:	/* dcbst */
			op->type = MKOP(CACHEOP, DCBST, 0);
			op->ea = xform_ea(instr, stack);
			return 0;

		case 86:	/* dcbf */
			op->type = MKOP(CACHEOP, DCBF, 0);
			op->ea = xform_ea(instr, stack);
			return 0;

		case 246:	/* dcbtst */
			op->type = MKOP(CACHEOP, DCBTST, 0);
			op->ea = xform_ea(instr, stack);
			op->reg = rd;
			return 0;

		case 278:	/* dcbt */
			op->type = MKOP(CACHEOP, DCBTST, 0);
			op->ea = xform_ea(instr, stack);
			op->reg = rd;
			return 0;

		case 982:	/* icbi */
			op->type = MKOP(CACHEOP, ICBI, 0);
			op->ea = xform_ea(instr, stack);
			return 0;

		case 1014:	/* dcbz */
			op->type = MKOP(CACHEOP, DCBZ, 0);
			op->ea = xform_ea(instr, stack);
			return 0;
		}
		break;
	}

	/*
	 * Loads and stores.
	 */
	op->type = UNKNOWN;
	op->update_reg = ra;
	op->reg = rd;
	op->val = stack->gpr[rd];
	u = (instr >> 20) & UPDATE;

	switch (opcode) {
	case 31:
		u = instr & UPDATE;
		op->ea = xform_ea(instr, stack);
		switch ((instr >> 1) & 0x3ff) {
		case 23:	/* lwzx */
		case 55:	/* lwzux */
			op->type = MKOP(LOAD, u, 4);
			break;

		case 87:	/* lbzx */
		case 119:	/* lbzux */
			op->type = MKOP(LOAD, u, 1);
			break;

		case 21:	/* ldx */
		case 53:	/* ldux */
			op->type = MKOP(LOAD, u, 8);
			break;

		case 149:	/* stdx */
		case 181:	/* stdux */
			op->type = MKOP(STORE, u, 8);
			break;

		case 151:	/* stwx */
		case 183:	/* stwux */
			op->type = MKOP(STORE, u, 4);
			break;

		case 215:	/* stbx */
		case 247:	/* stbux */
			op->type = MKOP(STORE, u, 1);
			break;

		case 279:	/* lhzx */
		case 311:	/* lhzux */
			op->type = MKOP(LOAD, u, 2);
			break;

		case 341:	/* lwax */
		case 373:	/* lwaux */
			op->type = MKOP(LOAD, SIGNEXT | u, 4);
			break;

		case 343:	/* lhax */
		case 375:	/* lhaux */
			op->type = MKOP(LOAD, SIGNEXT | u, 2);
			break;

		case 407:	/* sthx */
		case 439:	/* sthux */
			op->type = MKOP(STORE, u, 2);
			break;

		case 532:	/* ldbrx */
			op->type = MKOP(LOAD, BYTEREV, 8);
			break;

		case 534:	/* lwbrx */
			op->type = MKOP(LOAD, BYTEREV, 4);
			break;

		case 660:	/* stdbrx */
			op->type = MKOP(STORE, BYTEREV, 8);
			op->val = byterev_8(stack->gpr[rd]);
			break;

		case 662:	/* stwbrx */
			op->type = MKOP(STORE, BYTEREV, 4);
			op->val = byterev_4(stack->gpr[rd]);
			break;

		case 790:	/* lhbrx */
			op->type = MKOP(LOAD, BYTEREV, 2);
			break;

		case 918:	/* sthbrx */
			op->type = MKOP(STORE, BYTEREV, 2);
			op->val = byterev_2(stack->gpr[rd]);
			break;
		}
		break;

	case 32:	/* lwz */
	case 33:	/* lwzu */
		op->type = MKOP(LOAD, u, 4);
		op->ea = dform_ea(instr, stack);
		break;

	case 34:	/* lbz */
	case 35:	/* lbzu */
		op->type = MKOP(LOAD, u, 1);
		op->ea = dform_ea(instr, stack);
		break;

	case 36:	/* stw */
	case 37:	/* stwu */
		op->type = MKOP(STORE, u, 4);
		op->ea = dform_ea(instr, stack);
		break;

	case 38:	/* stb */
	case 39:	/* stbu */
		op->type = MKOP(STORE, u, 1);
		op->ea = dform_ea(instr, stack);
		break;

	case 40:	/* lhz */
	case 41:	/* lhzu */
		op->type = MKOP(LOAD, u, 2);
		op->ea = dform_ea(instr, stack);
		break;

	case 42:	/* lha */
	case 43:	/* lhau */
		op->type = MKOP(LOAD, SIGNEXT | u, 2);
		op->ea = dform_ea(instr, stack);
		break;

	case 44:	/* sth */
	case 45:	/* sthu */
		op->type = MKOP(STORE, u, 2);
		op->ea = dform_ea(instr, stack);
		break;

	case 56:	/* lq */
		if (!((rd & 1) || (rd == ra)))
			op->type = MKOP(LOAD, 0, 16);
		op->ea = dqform_ea(instr, stack);
		break;

	case 58:	/* ld[u], lwa */
		op->ea = dsform_ea(instr, stack);
		switch (instr & 3) {
		case 0:		/* ld */
			op->type = MKOP(LOAD, 0, 8);
			break;
		case 1:		/* ldu */
			op->type = MKOP(LOAD, UPDATE, 8);
			break;
		case 2:		/* lwa */
			op->type = MKOP(LOAD, SIGNEXT, 4);
			break;
		}
		break;

	case 62:	/* std[u] */
		op->ea = dsform_ea(instr, stack);
		switch (instr & 3) {
		case 0:		/* std */
			op->type = MKOP(STORE, 0, 8);
			break;
		case 1:		/* stdu */
			op->type = MKOP(STORE, UPDATE, 8);
			break;
		case 2:		/* stq */
			if (!(rd & 1))
				op->type = MKOP(STORE, 0, 16);
			break;
		}
		break;
	}

out:
#ifdef DEBUG
	if (op->type == UNKNOWN)
		pr_error("Unknown instruction\n");
#endif

	return op->type == UNKNOWN ? -1 : 0;
}
