// SPDX-License-Identifier: GPL-2.0
/*
 * Guest MMIO support
 * Based on Linux' arch/powerpc/kvm/emulate_loadstore.c.
 *
 * Copyright IBM Corp. 2007
 * Copyright 2011 Freescale Semiconductor, Inc.
 * Copyright 2018 IBM Corp.
 */

#include <svm_host.h>
#include <uvcall.h>
#include <hvcall.h>
#include <instr.h>

#ifdef DEBUG
#include <logging.h>
#endif

enum emulation_result {
	EMULATE_DONE,         /* no further processing */
	EMULATE_FAIL,         /* can't emulate this instruction */
};

static enum emulation_result handle_load(struct refl_state *rstate, gpa_t addr,
					 u64 *_val, unsigned int bytes,
					 bool is_default_endian,
					 bool sign_extend)
{
	bool host_bswapped;
	u64 val;
	u64 ret_buf[1];
	int rc;

	assert(bytes <= 8);

	host_bswapped = rstate->excp_frame.usrr1 & MSR_LE ? is_default_endian :
							   !is_default_endian;

	rc = do_hcall(rstate, H_LOGICAL_CI_LOAD, 2, ret_buf, 1, bytes, addr);
	if (rc != H_SUCCESS)
		return EMULATE_FAIL;

	val = ret_buf[0];

	if (host_bswapped)
		switch (bytes) {
		case 8: val = bswap_64(val); break;
		case 4: val = bswap_32((u32) val); break;
		case 2: val = bswap_16((u16) val); break;
		}

	if (sign_extend)
		switch (bytes) {
		case 4: val = (s64) (s32) val; break;
		case 2: val = (s64) (s16) val; break;
		case 1: val = (s64) (s8) val; break;
		}

	*_val = val;

	return EMULATE_DONE;
}

static enum emulation_result handle_store(struct refl_state *rstate, gpa_t addr,
					  u64 val, unsigned int bytes,
					  bool is_default_endian)
{
	int rc;
	bool host_bswapped;

	assert(bytes <= 8);

	host_bswapped = rstate->excp_frame.usrr1 & MSR_LE ? is_default_endian :
							   !is_default_endian;

	if (host_bswapped)
		switch (bytes) {
		case 8: val = bswap_64(val); break;
		case 4: val = bswap_32(val); break;
		case 2: val = bswap_16(val); break;
		}

	rc = do_hcall(rstate, H_LOGICAL_CI_STORE, 3, NULL, 0, bytes, addr, val);

	return rc == H_SUCCESS ? EMULATE_DONE : EMULATE_FAIL;
}

void __noreturn emulate_mmio(struct refl_state *r_state, void *UNUSED(arg))
{
	struct svm *svm = r_state->svm;
	struct stack_frame *stack = &r_state->excp_frame;
	enum emulation_result emulated = EMULATE_FAIL;
	struct instruction_op op;
	unsigned int instr;
	int rc, size, type;
	gpa_t addr;

	assert(!(stack->usrr1 & MSR_HV));

	instr = *((unsigned int *) gpa_to_addr(&svm->mm, stack->usrr0, NULL));
	if (stack->usrr1 & MSR_LE)
		instr = bswap_32(instr);

	rc = analyse_instr(&op, stack, instr);
	if (rc)
		goto out;

	type = op.type & INSTR_TYPE_MASK;
	size = GETSIZE(op.type);

	/*
	 * ASDR contains the GPA of the memory location that caused the
	 * exception, but without the offset into the page while HDAR contains
	 * the GVA with the page offset. We have to combine both.
	 */
	addr = stack->asdr | (stack->hdar & PAGE_OFFSET_MASK);

	switch (type) {
	case LOAD: {
		bool instr_byte_swap = op.type & BYTEREV;
		u64 val;

		emulated = handle_load(r_state, addr, &val, size,
				       !instr_byte_swap, op.type & SIGNEXT);

		if (emulated != EMULATE_FAIL) {
			stack->gpr[op.reg] = val;

			if (op.type & UPDATE)
				stack->gpr[op.update_reg] = op.ea;
		}

		break;
	}
	case STORE:
		/*
		 * If need byte reverse, op.val has been reversed by
		 * analyse_instr().
		 */
		emulated = handle_store(r_state, addr, op.val, size, true);

		if ((op.type & UPDATE) && (emulated != EMULATE_FAIL))
			stack->gpr[op.update_reg] = op.ea;

		break;
	case CACHEOP:
		/*
		 * Do nothing. The guest is performing dcbi because
		 * hardware DMA is not snooped by the dcache, but
		 * emulated DMA either goes through the dcache as
		 * normal writes, or the host kernel has handled dcache
		 * coherence.
		 */
		emulated = EMULATE_DONE;
		break;
#ifdef DEBUG
	default:
		pr_error("Instruction not supported for MMIO\n");
#endif
	}

out:
	if (emulated == EMULATE_DONE)
		/* Advance the guest's PC. */
		stack->usrr0 += 4;

#ifdef DEBUG
	assert(emulated == EMULATE_DONE);
#endif

	ctx_end_context(r_state);
}
