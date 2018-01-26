// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp.  */

#ifndef __ASM_UTILS_H
#define __ASM_UTILS_H

/*
 * Do NOT use the immediate load helpers with symbols
 * only with constants. Symbols will _not_ be resolved
 * by the linker since we are building -pie, and will
 * instead generate relocs of a type our little built-in
 * relocator can't handle
 */

/* Load an immediate 64-bit value into a register */
#define LOAD_IMM64(r, e)			\
	lis	r,(e)@highest;			\
	ori	r,r,(e)@higher;			\
	rldicr	r,r, 32, 31;			\
	oris	r,r, (e)@h;			\
	ori	r,r, (e)@l;

/* Load an immediate 32-bit value into a register */
#define LOAD_IMM32(r, e)			\
	lis	r,(e)@h;			\
	ori	r,r,(e)@l;

/* Load an address via the TOC */
#define LOAD_ADDR_FROM_TOC(r, e)	ld r,e@got(%r2)

#define GET_STACK(stack_reg,pir_reg,scr_reg)		\
	LOAD_IMM32(stack_reg,CPU_STACKS_OFFSET)		\
	LOAD_IMM32(scr_reg,ULTRA_SIZE)			\
	add	stack_reg,stack_reg,scr_reg;		\
	mfspr	scr_reg,SPRG_UVSCRATCH0;		\
	add	stack_reg,stack_reg,scr_reg;		\
	sldi	pir_reg,pir_reg,STACK_SHIFT;		\
	add	stack_reg,stack_reg,pir_reg;

#define GET_CPU()						\
	clrrdi	%r13,%r1,STACK_SHIFT

#define FIXUP_ENDIAN							\
	tdi	0,0,0x48;	/* Reverse endian of b . + 8	*/	\
	b	$+36;		/* Skip trampoline if endian ok	*/	\
	.long	0x05009f42;	/* bcl 20,31,$+4		*/	\
	.long	0xa602487d;	/* mflr r10			*/	\
	.long	0x1c004a39;	/* addi r10,r10,28		*/	\
	.long	0xa600607d;	/* mfmsr r11			*/	\
	.long	0x01006b69;	/* xori r11,r11,1		*/	\
	.long	0xa6035a7d;	/* mtsrr0 r10			*/	\
	.long	0xa6037b7d;	/* mtsrr1 r11			*/	\
	.long	0x2400004c	/* rfid				*/



#define SAVE_GPR(reg,sp)	std %r##reg,STACK_GPR##reg(sp)
#define REST_GPR(reg,sp)       	ld %r##reg,STACK_GPR##reg(sp)
#define SAVE_FPR(reg,sp)	stfd %f##reg,STACK_FPR##reg(sp)
#define REST_FPR(reg,sp)	lfd %f##reg,STACK_FPR##reg(sp)

/*
 * Following macros are based on Linux kernel (v5.2). Unlike Linux,
 * we assume VSX is on and allocate sufficient space on stack_frame
 *
 * Note: Linux also uses 'xxswapd vs0,vs0' to allow for LE kernels.
 * 	 (See STXVD2X_ROT in Linux kernel v5.2). We run in BE mode,
 * 	 so we don't need that right?
 */

#define SAVE_VSR(reg,sp)	li %r4,16*reg; stxvd2x %vs##reg,sp,%r4
#define REST_VSR(reg,sp)	li %r4,16*reg; lxvd2x %vs##reg,sp,%r4

#define SAVE_VR(reg,sp)		li %r4,16*reg; stvx %v##reg,%r4,sp
#define REST_VR(reg,sp)		li %r4,16*reg; lvx %v##reg,%r4,sp

#endif /* __ASM_UTILS_H */
