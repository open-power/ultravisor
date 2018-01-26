// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __STACKFRAME_H
#define __STACKFRAME_H

#include <mem-map.h>

#define STACK_ENTRY_HMI		0x0e60	/* Hypervisor maintenance */
#define STACK_ENTRY_RESET	0x0100	/* System reset */
#define STACK_ENTRY_SOFTPATCH	0x1500	/* Soft patch (denorm emulation) */

/* Safety/ABI gap at top of stack */
#define STACK_TOP_GAP		0x100

/* Remaining stack space (gap included) */
#define NORMAL_STACK_SIZE	STACK_SIZE

/* Offset to get to normal CPU stacks */
#define CPU_STACKS_OFFSET	(NORMAL_STACK_SIZE - STACK_TOP_GAP)

/* Gap below the stack. If our stack checker sees the stack below that
 * gap, it will flag a stack overflow
 */
#define STACK_SAFETY_GAP	512

/* Warning threshold, if stack goes below that on mcount, print a
 * warning.
 */
#define STACK_WARNING_GAP	2048

#define STACK_CHECK_GUARD_BASE	0xdeadf00dbaad300

#ifndef __ASSEMBLY__

#include <stdint.h>
#include <stdbool.h>

/*
 * Allow for 64 (quad-word) VSR registers. See also TS_FPRWIDTH in
 * v5.2 Linux kernel.
 *
 * If VSX is enabled in the VM, use VSX instructions to save/restore
 * state. Otherwise use normal FP instructions.
 *
 * This does increase the stack_frame size by 512 bytes but we don't
 * have to deal with allocation failures when handling exceptions.
 */
struct fp_state {
	uint64_t fpr[32][2] __attribute__((aligned(16)));
	uint64_t fpscr;
};

typedef struct {
	        uint32_t u[4];
} __attribute__((aligned(16))) __vector128;

typedef __vector128 vector128;

struct vr_state {
	vector128 vr[32] __attribute__((aligned(16)));
	vector128 vscr __attribute__((aligned(16)));
};

#define	STACK_FLAGS_SYNTH_INTR	0x1	/* HV sending synthesized intr to SVM */

/* This is the struct used to save GPRs etc.. on Ultravisor entry
 * and from some exceptions. It is not always entirely populated
 * depending on the entry type
 *
 * @todo: Consider dropping ->lpidr, ->pidr and ->lpcr fields from this
 * 	  stack frame structure. Those fields are under the control of
 * 	  the HV and UV does not change them and neither can the SVM.
 *
 */
struct stack_frame {
	/* Standard 112-byte stack frame header (the minimum size required,
	 * using an 8-doubleword param save area). The callee (in C) may use
	 * lrsave; we declare these here so we don't get our own save area
	 * overwritten */
	uint64_t	backchain;
	uint64_t	crsave;
	uint64_t	lrsave;
	uint64_t	compiler_dw;
	uint64_t	linker_dw;
	uint64_t	tocsave;
	uint64_t	paramsave[8];
	uint64_t	flags;

	/* Space for stack-local vars used by asm. At present we only use
	 * one doubleword. */
	uint64_t	locals[1];

	/* Entry type */
	uint64_t	type;

	/* GPR save area
	 *
	 * We don't necessarily save everything in here
	 */
	uint64_t	gpr[32];

	/* Other SPR saved
	 *
	 * Only for some exceptions.
	 */
	uint64_t	cr;
	uint64_t	xer;
	uint64_t	dsisr;
	uint64_t	ctr;
	uint64_t	lr;
	uint64_t	cfar;
	uint64_t	pidr;
	uint64_t	lpcr;
	uint64_t	lpidr;
	uint64_t	srr0;
	uint64_t	srr1;
	uint64_t	sprg0;
	uint64_t	sprg1;
	uint64_t	sprg2;
	uint64_t	sprg3;
	uint64_t	hsrr0;
	uint64_t	hsrr1;
	uint64_t	hsprg0;
	uint64_t	hsprg1;
	uint64_t	usrr0;
	uint64_t	usrr1;
	uint64_t	dar;
	uint64_t	hdar;
	uint64_t	hdsisr;
	uint64_t	asdr;
	uint64_t	heir;
	uint64_t	excp_id;
	uint64_t	dec;
	uint64_t	dec_expiry;
	/*
	 * HV saves/restores VRSAVE independent of CONFIG_ALTIVEC and
	 * keeps it separate from "vr_state". Lets do the same.
	 */
	uint64_t	vrsave;
	uint64_t	mmcr0;
	uint64_t	mmcra;
	struct fp_state fp_state;
	struct vr_state vr_state;
} __attribute__((aligned(16)));

/* Backtrace */
struct bt_entry {
	unsigned long	sp;
	unsigned long	pc;
};

/* Boot stack top */
extern void *boot_stack_top;

/* Create a backtrace */
extern void __backtrace(struct bt_entry *entries, unsigned int *count);

/* Convert a backtrace to ASCII */
extern void __print_backtrace(unsigned int pir, struct bt_entry *entries,
			      unsigned int count, char *out_buf,
			      unsigned int *len, bool symbols);

/* For use by debug code, create and print backtrace, uses a static buffer */
extern void backtrace(void);

#ifdef STACK_CHECK_ENABLED
extern void check_stacks(void);
#else
static inline void check_stacks(void) { }
#endif

#endif /* __ASSEMBLY__ */
#endif /* __STACKFRAME_H */

