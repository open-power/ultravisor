#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <context.h>
#include <processor.h>
#include <logging.h>

extern int log_all; /* start logging all exceptions - after a certain event */
extern void dump_regs(const char *msg, struct stack_frame *stack, int gprs);
extern void __noreturn _urfid_return (struct stack_frame *stack);
extern void __noreturn put_rstate_urfid_return (struct refl_state *r_state,
						struct stack_frame *stack);
extern int refl_state_save_regs(struct stack_frame *stack);
extern int refl_state_restore_regs(struct stack_frame *stack);
extern void fixup_regs_on_hv_exit(struct refl_state *r_state);
extern void __noreturn exception_reflect(struct refl_state *r_state, void *arg);
extern void __noreturn hcall_reflect(struct refl_state *r_state, void *arg);
extern void exception_svm_reflect_prep(struct stack_frame *stack,
		uint64_t intr_status, uint64_t exception, uint64_t msr);
extern __attribute__((const)) int get_masked_sprs_size(void);
extern void fixup_regs_for_svm_entry(struct stack_frame *stack);
extern void restore_fp_state(struct stack_frame *stack);

#define REG "%016llx"

static inline void __noreturn urfid_return(struct stack_frame *stack)
{
	if (stack->usrr1 & MSR_S)
		fixup_regs_for_svm_entry(stack);

	_urfid_return(stack);
}

/*
 * Synthesize Program Interrupt to SVM. This is based on the
 * kvmppc_inject_interrupt() in Linux kernel v5.2.
 */
static inline void __noreturn synthesize_prog_intr(struct stack_frame *stack,
			uint64_t flags)
{
	stack->srr0 = stack->usrr0;	/* save location of interrupt */
	stack->usrr0 = 0x700;		/* Program Interrupt */
	stack->usrr1 = (stack->usrr1 & ~0x783f0000ul) | flags;
	urfid_return(stack);
}

#ifndef __TEST__
static inline struct stack_frame *get_exception_frame(void)
{
	u64 _tos;

	_tos = mfspr(SPRG_UVSTACK);
	_tos = _tos - sizeof(struct stack_frame);

	return (struct stack_frame *)_tos;
}
#endif

#define MAX_EXCEPTION 0x2000
#define HSRR0_MASK (((0x1ULL<<52)-1) & ~0x3) /* lowest 2bits are always zero,
					 and the value is < 2^52 */

static inline bool is_frequent_exception(uint64_t type)
{
	switch (type) {
	case 0x980:
	case 0xC00:
	case 0xE00:
	case 0xE20:
	case 0xEA0:
	case 0xE80:
		return true;
	}
	return false;
}
#endif /* ifndef EXCEPTIONS_H */
