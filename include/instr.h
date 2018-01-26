/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * POWER instruction analyser.
 * Based on Linux' arch/powerpc/include/asm/sstep.h.
 *
 * Copyright (C) 2004 Paul Mackerras <paulus@au.ibm.com>, IBM
 * Copyright 2018 IBM Corp.
 */

#ifndef __SSTEP_H
#define __SSTEP_H

struct stack_frame;

enum instruction_type {
	LOAD,			/* load and store types need to be contiguous */
	STORE,
	CACHEOP,
	UNKNOWN
};

#define INSTR_TYPE_MASK	0x1f

/* Load/store flags, ORed in with type */
#define SIGNEXT		0x20
#define UPDATE		0x40	/* matches bit in opcode 31 instructions */
#define BYTEREV		0x80

/* Cacheop values, ORed in with type */
#define DCBST		0
#define DCBF		0x100
#define DCBTST		0x200
#define DCBT		0x300
#define ICBI		0x400
#define DCBZ		0x500

/* Size field in type word */
#define SIZE(n)		((n) << 12)
#define GETSIZE(w)	((w) >> 12)

#define MKOP(t, f, s)	((t) | (f) | SIZE(s))

struct instruction_op {
	int type;
	int reg;
	unsigned long val;
	/* For LOAD/STORE/LARX/STCX */
	unsigned long ea;
	int update_reg;
};

/*
 * Decode an instruction, and return information about it in *op
 * without changing *regs.
 *
 * Return value is 1 if the instruction can be emulated just by
 * updating *regs with the information in *op, -1 if we need the
 * GPRs but *regs doesn't contain the full register set, or 0
 * otherwise.
 */
int analyse_instr(struct instruction_op *op, const struct stack_frame *stack,
		  unsigned int instr);

#endif /* __SSTEP_H */
