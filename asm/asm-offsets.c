// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp.
 */

#include <stddef.h>
#include <types.h>
#include <processor.h>
#include <cpu.h>
#include <stack.h>

#define DEFINE(sym, val) \
        asm volatile("\n#define " #sym " %0 /* " #val " */" : : "i" (val))

#define OFFSET(sym, str, mem) \
	DEFINE(sym, offsetof(struct str, mem))

int main(void);

int main(void)
{
#if 0
	OFFSET(SPIRA_ACTUAL_SIZE, spira, reserved);

#endif
	OFFSET(CPUTHREAD_PIR, cpu_thread, pir);
	OFFSET(CPUTHREAD_SAVE_R1, cpu_thread, save_r1);
	OFFSET(CPUTHREAD_SAVE_R2, cpu_thread, save_r2);
	OFFSET(CPUTHREAD_SAVE_MSR, cpu_thread, save_msr);
	OFFSET(CPUTHREAD_STATE, cpu_thread, state);
	OFFSET(CPUTHREAD_URMOR_UP, cpu_thread, in_urmor_update);
	OFFSET(CPUTHREAD_CUR_TOKEN, cpu_thread, current_token);
	DEFINE(CPUTHREAD_GAP, sizeof(struct cpu_thread) + STACK_SAFETY_GAP);
#ifdef STACK_CHECK_ENABLED
	OFFSET(CPUTHREAD_STACK_BOT_MARK, cpu_thread, stack_bot_mark);
	OFFSET(CPUTHREAD_STACK_BOT_PC, cpu_thread, stack_bot_pc);
	OFFSET(CPUTHREAD_STACK_BOT_TOK, cpu_thread, stack_bot_tok);
#endif
	OFFSET(STACK_TYPE,	stack_frame, type);
	OFFSET(STACK_LOCALS,	stack_frame, locals);
	OFFSET(STACK_GPR0,	stack_frame, gpr[0]);
	OFFSET(STACK_GPR1,	stack_frame, gpr[1]);
	OFFSET(STACK_GPR2,	stack_frame, gpr[2]);
	OFFSET(STACK_GPR3,	stack_frame, gpr[3]);
	OFFSET(STACK_GPR4,	stack_frame, gpr[4]);
	OFFSET(STACK_GPR5,	stack_frame, gpr[5]);
	OFFSET(STACK_GPR6,	stack_frame, gpr[6]);
	OFFSET(STACK_GPR7,	stack_frame, gpr[7]);
	OFFSET(STACK_GPR8,	stack_frame, gpr[8]);
	OFFSET(STACK_GPR9,	stack_frame, gpr[9]);
	OFFSET(STACK_GPR10,	stack_frame, gpr[10]);
	OFFSET(STACK_GPR11,	stack_frame, gpr[11]);
	OFFSET(STACK_GPR12,	stack_frame, gpr[12]);
	OFFSET(STACK_GPR13,	stack_frame, gpr[13]);
	OFFSET(STACK_GPR14,	stack_frame, gpr[14]);
	OFFSET(STACK_GPR15,	stack_frame, gpr[15]);
	OFFSET(STACK_GPR16,	stack_frame, gpr[16]);
	OFFSET(STACK_GPR17,	stack_frame, gpr[17]);
	OFFSET(STACK_GPR18,	stack_frame, gpr[18]);
	OFFSET(STACK_GPR19,	stack_frame, gpr[19]);
	OFFSET(STACK_GPR20,	stack_frame, gpr[20]);
	OFFSET(STACK_GPR21,	stack_frame, gpr[21]);
	OFFSET(STACK_GPR22,	stack_frame, gpr[22]);
	OFFSET(STACK_GPR23,	stack_frame, gpr[23]);
	OFFSET(STACK_GPR24,	stack_frame, gpr[24]);
	OFFSET(STACK_GPR25,	stack_frame, gpr[25]);
	OFFSET(STACK_GPR26,	stack_frame, gpr[26]);
	OFFSET(STACK_GPR27,	stack_frame, gpr[27]);
	OFFSET(STACK_GPR28,	stack_frame, gpr[28]);
	OFFSET(STACK_GPR29,	stack_frame, gpr[29]);
	OFFSET(STACK_GPR30,	stack_frame, gpr[30]);
	OFFSET(STACK_GPR31,	stack_frame, gpr[31]);

	OFFSET(STACK_HDAR,	stack_frame, hdar);
	OFFSET(STACK_HDSISR,	stack_frame, hdsisr);
	OFFSET(STACK_ASDR,	stack_frame, asdr);
	OFFSET(STACK_HEIR,	stack_frame, heir);
	OFFSET(STACK_CR,	stack_frame, cr);
	OFFSET(STACK_XER,	stack_frame, xer);
	OFFSET(STACK_DSISR,	stack_frame, dsisr);
	OFFSET(STACK_CTR,	stack_frame, ctr);
	OFFSET(STACK_LR,	stack_frame, lr);
	OFFSET(STACK_CFAR,	stack_frame, cfar);
	OFFSET(STACK_PIDR,	stack_frame, pidr);
	OFFSET(STACK_LPCR,	stack_frame, lpcr);
	OFFSET(STACK_LPIDR,	stack_frame, lpidr);
	OFFSET(STACK_SRR0,	stack_frame, srr0);
	OFFSET(STACK_SRR1,	stack_frame, srr1);
	OFFSET(STACK_SPRG0,	stack_frame, sprg0);
	OFFSET(STACK_SPRG1,	stack_frame, sprg1);
	OFFSET(STACK_SPRG2,	stack_frame, sprg2);
	OFFSET(STACK_SPRG3,	stack_frame, sprg3);
	OFFSET(STACK_HSRR0,	stack_frame, hsrr0);
	OFFSET(STACK_HSRR1,	stack_frame, hsrr1);
	OFFSET(STACK_HSPRG0,	stack_frame, hsprg0);
	OFFSET(STACK_HSPRG1,	stack_frame, hsprg1);
	OFFSET(STACK_USRR0,	stack_frame, usrr0);
	OFFSET(STACK_USRR1,	stack_frame, usrr1);
	OFFSET(STACK_DAR,	stack_frame, dar);
	OFFSET(STACK_DEC,	stack_frame, dec);
	OFFSET(STACK_VRSAVE,	stack_frame, vrsave);
	OFFSET(STACK_MMCR0,	stack_frame, mmcr0);
	OFFSET(STACK_MMCRA,	stack_frame, mmcra);
	OFFSET(STACK_FPR0,	stack_frame, fp_state.fpr[0]);
	OFFSET(STACK_FPR1,	stack_frame, fp_state.fpr[1]);
	OFFSET(STACK_FPR2,	stack_frame, fp_state.fpr[2]);
	OFFSET(STACK_FPR3,	stack_frame, fp_state.fpr[3]);
	OFFSET(STACK_FPR4,	stack_frame, fp_state.fpr[4]);
	OFFSET(STACK_FPR5,	stack_frame, fp_state.fpr[5]);
	OFFSET(STACK_FPR6,	stack_frame, fp_state.fpr[6]);
	OFFSET(STACK_FPR7,	stack_frame, fp_state.fpr[7]);
	OFFSET(STACK_FPR8,	stack_frame, fp_state.fpr[8]);
	OFFSET(STACK_FPR9,	stack_frame, fp_state.fpr[9]);
	OFFSET(STACK_FPR10,	stack_frame, fp_state.fpr[10]);
	OFFSET(STACK_FPR11,	stack_frame, fp_state.fpr[11]);
	OFFSET(STACK_FPR12,	stack_frame, fp_state.fpr[12]);
	OFFSET(STACK_FPR13,	stack_frame, fp_state.fpr[13]);
	OFFSET(STACK_FPR14,	stack_frame, fp_state.fpr[14]);
	OFFSET(STACK_FPR15,	stack_frame, fp_state.fpr[15]);
	OFFSET(STACK_FPR16,	stack_frame, fp_state.fpr[16]);
	OFFSET(STACK_FPR17,	stack_frame, fp_state.fpr[17]);
	OFFSET(STACK_FPR18,	stack_frame, fp_state.fpr[18]);
	OFFSET(STACK_FPR19,	stack_frame, fp_state.fpr[19]);
	OFFSET(STACK_FPR20,	stack_frame, fp_state.fpr[20]);
	OFFSET(STACK_FPR21,	stack_frame, fp_state.fpr[21]);
	OFFSET(STACK_FPR22,	stack_frame, fp_state.fpr[22]);
	OFFSET(STACK_FPR23,	stack_frame, fp_state.fpr[23]);
	OFFSET(STACK_FPR24,	stack_frame, fp_state.fpr[24]);
	OFFSET(STACK_FPR25,	stack_frame, fp_state.fpr[25]);
	OFFSET(STACK_FPR26,	stack_frame, fp_state.fpr[26]);
	OFFSET(STACK_FPR27,	stack_frame, fp_state.fpr[27]);
	OFFSET(STACK_FPR28,	stack_frame, fp_state.fpr[28]);
	OFFSET(STACK_FPR29,	stack_frame, fp_state.fpr[29]);
	OFFSET(STACK_FPR30,	stack_frame, fp_state.fpr[30]);
	OFFSET(STACK_FPR31,	stack_frame, fp_state.fpr[31]);
	OFFSET(STACK_FPSCR,	stack_frame, fp_state.fpscr);
	DEFINE(STACK_FRAMESIZE,	sizeof(struct stack_frame));
	OFFSET(FP_STATE_FPSCR,  fp_state, fpscr);
	OFFSET(VR_STATE_VSCR ,  vr_state, vscr);

	return 0;
}
