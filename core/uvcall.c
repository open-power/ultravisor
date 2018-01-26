// SPDX-License-Identifier: GPL-2.0
/*
 * Ultravisor calls
 *
 * Copyright 2018 IBM Corp.
 *
 */

#define pr_fmt(fmt) "UVCALL: " fmt

#include <inttypes.h>
#include <console.h>
#include <stdlib.h>
#include <logging.h>
#include <compiler.h>
#include <stack.h>
#include <processor.h>
#include <cpu.h>
#include <exceptions.h>
#include <context.h>
#include <uvcall.h>
#include <mmu.h>
#include <xscom.h>
#include <svm_host.h>
#include <hvcall.h>
#include <svm/svm-esm.h>
#include <svm/svm-rtas.h>
#include <ppc-opcode.h>
#include <svm/svm-pagemap.h>
#include <stdio.h>
#include <mem_region.h>
#include <string.h>
#include <uv/uv-xscom-bwlist.h>
#include <sbe-chipops.h>
#include <pagein_track.h>

/*
 * Return TRUE if HV set TM state now (i.e in live MSR) or is attempting
 * to set TM in the SVM, to Transactional or Suspended state. Return false
 * otherwise. If the SVM attempts to use TM, SVM will get a HV Facility
 * Unavailable (HFU) exception that will be handled by the UV.
 */
static inline bool hv_activating_tm(struct stack_frame *stack)
{
	if ((mfmsr() & (MSR_TS_T|MSR_TS_S)) ||
				(stack->usrr1 & (MSR_TS_S|MSR_TS_T)))
		return true;

	return false;
}

/*
 * Do some security checks on the registers upon return from HV.
 */
static int check_regs_on_hv_exit(u64 function, struct stack_frame *stack)
{
	/* if ucall from SVM, nothing to do here */
	if (!(stack->usrr1 & MSR_HV))
		return 0;

	/*
	 * If MSR indicates that TM is active/suspended, fail the ucall
	 * unless the ucall is UV_RETURN in which case send a Program
	 * Interrupt to the SVM (we cannot return an error to the SVM
	 * since this UV_RETURN could be in response to the reflection
	 * of non-hcall exception).
	 *
	 * If HV is trying to activate TM for the SVM (i.e in USRR1)
	 * ignore - we will disable TM before returning to the SVM
	 *
	 * @todo: Try to 'treclaim' the transaction and recover before
	 * 	  sending the Program Interrupt.
	 */
	if (hv_activating_tm(stack)) {

		if (function != UV_RETURN)
			return U_BAD_MODE;

		pr_warn("HV activating TM on UV_RETURN from excp "
			"0x%llx (0x%llx) MSR 0x%lx USRR1 0x%llx\n",
			stack->type, stack->gpr[3], mfmsr(),
			stack->usrr1);
		synthesize_prog_intr(stack, SRR1_PROGTM);
	}

	return 0;
}

static bool valid_vector(struct refl_state *r_state, u64 hsrr0, u64 r31)
{
	/* HV would change HSRR0 value when synthesizing interrupt. */
	if (hsrr0 == r31)
		return false;

	/*
	 * For machine check interrupt guest OS would have registered fwnmi
	 * handler with hypervisor. fwnmi handler may not be defined below
	 * 0x2000. Hence add an explicit address check for it. Also, Linux OS
	 * uses IFETCH cache align which is 16 bytes for fwnmi handler, hence
	 * check for 16 bytes alignement instead of 32 bytes.
	 */
	if (r_state->vector == 0x200) {
		u64 fwnmi_addr = r_state->svm->fwnmi_machine_check_addr;

		return ((hsrr0 == fwnmi_addr) && !(hsrr0 & 0xf));
	}

	/* For all other interrupts... */
	return ((hsrr0 < MAX_EXCEPTION) && !(hsrr0 & 0x1f));
}

/*
 * We are returning from a reflected hcall. Switch back to the original
 * context stack (after verfying that HV did not mess with the cookie
 * and retrieving hcall results).
 */
static u64 uv_return(u64 UNUSED(arg), struct  stack_frame *stack)
{
	int i;
	struct refl_state *r_state;
	struct stack_frame *guest_regs;
	struct svm *svm;

	svm = get_svm(stack->lpidr);
	assert(svm);	/* @todo refcount svm? */

#if 0
	pr_error("%s() EXID %lld: cookie 0x%llx\n", __func__, stack->excp_id,
		 stack->gpr[31]);
#endif

	/*
	 * We could be returning from:
	 *
	 * 	a. start-cpu RTAS call for a *new* CPU
	 * 	b. stop-self RTAS call for a cpu that was offlined earlier
	 * 	   and was onlined by a "recent" start-cpu call.
	 * 	c. some other hcall/exception.
	 *
	 * In case of 'a' the cookie we want is in R3 and in case 'c' it
	 * is in R31. In case of 'b' there is a valid cookie in both R3
	 * and R31. The R3 cookie is from the recent 'start-cpu' call to
	 * online the cpu and the R31 cookie is from the prior 'stop-self'
	 * call that was used to offline the cpu and which did not return
	 * until now.
	 *
	 * If there is a valid cookie in R3, rtas_start_cpu_end() handles
	 * both 'a' and 'c' and returns to the SVM directly. Otherwise
	 * it returns here and we handle 'c'.
	 */
	r_state = NULL;
	if (rtas_start_cpu_end(svm, stack))
		r_state = svm_find_del_cookie(svm, stack->gpr[31]);

	if (!r_state) {
		/*
		 * We don't have a good way of handling a bad cookie
		 * from the HV. Be paranoid of the HV and crash for now.
		 */
		assert(0);
	}

	/*
	 * This is a reflected ucall, switch stack back to the original
	 * (after verifying that the HV did not mess with it)
	 */
	if (r_state->magic != ULTRA_COOKIE_MAGIC) {
		pr_error("%s(): Cookie mismatch!!! exp 0x%llx, act 0x%llx\n",
			 __func__, ULTRA_COOKIE_MAGIC, r_state->magic);
		abort();	/* @todo terminate just the SVM? */
	}

	/* Find out the physical CPU where the SVM vcpu is running on now. */
	if (svm->vcpus.tracking) {
		this_cpu()->vcpu = r_state->vcpu;

		/* Sanity check */
		if (this_cpu()->vcpu.vcpuid >= svm->vcpus.max ||
		    this_cpu()->vcpu.lpid != svm->lpid) {
			invalidate_vcpuid(&this_cpu()->vcpu);
			pr_error("%s: Coming back from reflection with "
				 "unknown vcpu %u (lpid %llx)\n",
				 __func__, r_state->vcpu.vcpuid, svm->lpid);
			/*
			 * svm_abort() calls do_reflect() so stop tracking vcpu.
			 */
			svm->vcpus.tracking = false;
			svm_abort(r_state);
			/* NOTREACHED */
		}
	} else
		invalidate_vcpuid(&this_cpu()->vcpu);

	/*
	 * Detect when the hypervisor has synthesized an interrupt for
	 * the guest, and update the guest's PC, MSR, SRR0/1. We put
	 * a random value (basically the cookie from R31) in HSRR0 in
	 * fixup_regs_for_hv_entry(). HV would change that value when
	 * synthesizing interrupt.
	 *
	 * Note that SRR0/1 in *stack will reflect the point in the
	 * hypervisor where it did the UV_RETURN ucall, so we have to
	 * synthesize those.  The hypervisor passed in the SRR1 value
	 * in R2 so we can get status bits for the interrupt.
	 */
	guest_regs = &r_state->excp_frame;
	if (valid_vector(r_state, stack->hsrr0, stack->gpr[31])) {
		/* Redirect guest to synthesized interrupt vector */
		exception_svm_reflect_prep(guest_regs,
			stack->gpr[2], stack->hsrr0, stack->hsrr1);
		guest_regs->flags |= STACK_FLAGS_SYNTH_INTR;
	}

	/*
	 * If it was an hcall, retreive results from the exception stack
	 * before we restore context. Note that when we restore context
	 * (specifically R1), we switch over to the context stack and
	 * resume from the refl_state_save_regs().
         */
	if (r_state->vector == 0xc00) {
		for (i = 3; i <= 12; i++)
			r_state->hv_frame.gpr[i] = stack->gpr[i];
	}

	if (r_state->vector == 0x200) {
		svm_fixup_rtas_area(stack->gpr[3], r_state);
	}

	/*
	 * In do_reflect() we saved the context, then fixed-up several
	 * SPRs. For symmetry, restore the fixed-up SPRs first and then
	 * restore rest of the context.
	 */
	fixup_regs_on_hv_exit(r_state);

	(void)refl_state_restore_regs(&r_state->saved_regs);

	pr_error("%s(): ***** Restore context FAILED??? *****\n", __func__);

	return 0;
}

static u64 uv_write_pate(u64 lpid, u64 dw0, u64 dw1)
{
	pr_info("%s Called with lpid: 0x%llx, dw0: 0x%llx, dw1: 0x%llx\n",
		__func__, lpid, dw0, dw1);
	if (svm_setup_partition_table(lpid, dw0, dw1))
		return U_PERMISSION;
	return U_SUCCESS;
}

static int uv_restricted_spr_write(u64 regs, u64 value)
{
	switch (regs) {
	case SPRN_DAWR:
		mtspr(SPRN_DAWR, value);
		break;
	case SPRN_DAWRX:
		mtspr(SPRN_DAWRX, value);
		break;
	case SPRN_CIABR:
		mtspr(SPRN_CIABR, value);
		break;
	case SPRN_LDBAR:
		mtspr(SPRN_LDBAR, value);
		break;
	case SPRN_IMC:
		mtspr(SPRN_IMC, value);
		break;
	default:
		return U_PARAMETER;
	}
	return U_SUCCESS;
}

static int uv_restricted_spr_read(u64 regs, u64 *val)
{
	switch (regs) {
	case SPRN_DAWR:
		*val = mfspr(SPRN_DAWR);
		return U_SUCCESS;
	case SPRN_DAWRX:
		*val = mfspr(SPRN_DAWRX);
		return U_SUCCESS;
	case SPRN_CIABR:
		*val = mfspr(SPRN_CIABR);
		return U_SUCCESS;
	}
	return U_PARAMETER;
}

static u64 uv_register_mem_slot(u64 lpid, gpa_t start_gpa,
		u64 nbytes, u64 flags, u16 slotid)
{
	pr_info("%s lpid=%llx start_gpa=0x%llx nbytes=0x%llx, "
		"flags=0x%llx, slotid=0x%x\n",
		__func__, (u64) lpid, (u64) start_gpa, (u64) nbytes,
		(u64) flags, (u16) slotid);
	return create_memslot(get_svm(lpid), start_gpa, nbytes, flags, slotid);
}

static u64 uv_unregister_mem_slot(u64 lpid, u16 slotid)
{
	pr_info("%s lpid=%llx slotid=0x%x\n",
		__func__, (u64) lpid, (u16) slotid);
	return free_memslot(get_svm(lpid), slotid);
}

static u64 uv_page_in(u64 lpid, u64 hv_page, gpa_t gpa, u64 flags, u64 order)
{
	/*@todo validate that the hv_page is a valid hypervisor page */
	return handle_page_in(lpid, hv_page, gpa, flags, order);
}

static u64 uv_page_out(u64 lpid, u64 hv_page, gpa_t gpa, u64 flags, u64 order)
{
	/*@todo validate that the hv_page is a valid hypervisor page */
	return handle_page_out(lpid, hv_page, gpa, flags, order);
}

static u64 uv_page_inval(u64 lpid, gpa_t gpa, u64 order)
{
	return handle_page_inval(lpid, gpa, order);
}

static u64 uv_svm_terminate(u64 lpid)
{
	destroy_svm(lpid);
	return 0;
}

struct uv_esm_data {
	u64 kbase;
	u64 fdt;
};

/*
 * We expect to be called when the UV_ESM call is about to fail after
 * H_SVM_INIT_START hcall succeeded (meaning HV/UV have some partial
 * state associated with the VM that needs to be cleaned up).
 *
 * Rather than fail UV_ESM call directly, we issue the H_SVM_INIT_ABORT
 * hcall and forward to HV, the register state VM had at the time of
 * call to UV_ESM. The HV will drive the cleanup of the partial secure
 * state we have (eg: page-out any pages that we paged in), will issue
 * UV_SVM_TERMINATE ucall and return to the VM as if UV_ESM failed.
 *
 * To forward the VM's register state to HV:
 * 	- pass the USRR0/USRR1 values at UV_ESM in SRR0/SRR1
 * 	- restore non-volatile GPRs/FPRs to values at UV_ESM
 *
 * Adjust a few SPRs like in fixup_regs_for_hv_entry() (since we are
 * issuing a hcall), but unlike that function, we don't need to mask
 * any registers since the VM is not secure.
 */
static void fixup_uv_esm_excp_frame(struct refl_state *r_state)
{
	u64 saved;
	struct stack_frame *excpf;

	excpf = &r_state->excp_frame;

	/*
	 * VM did not go secure, so ensure we don't return to VM
	 * with MSR_S set. Hmm, only UV can set the MSR_S bit and
	 * since we will be returning to the VM through the HV,
	 * MSR_S be set in the VM? So can we drop this assert?
	 */
	assert((excpf->usrr1 & MSR_S) == 0);

	/*
	 * Have SRR0/1 point to the USRR0/1 values at UV_ESM
	 * so HV can directly return to VM after cleaning up.
	 * Not sure it is important, but change syscall level
	 * from 2 (due to UV_ESM) to 1 so HV is not confused.
	 */
	excpf->srr0 = excpf->usrr0;
	excpf->srr1 = excpf->usrr1;
	excpf->srr1 |= ((excpf->srr1 & ~SRR1_SC_MASK) |
			(SSR1_SC_LEV1 << PPC_BITLSHIFT(43)));

	saved = excpf->usrr1;

	/* set up R3/USRR0/1 to issue the hcall */
	excpf->gpr[3] = H_SVM_INIT_ABORT;
	excpf->usrr0 = 0xc00;
	excpf->usrr1 = MSR_SF|MSR_HV|MSR_ME;
	excpf->usrr1 |= (saved & ((MSR_FP|MSR_VSX|MSR_VEC)));
	if (hv_is_LE)
		excpf->usrr1 |= MSR_LE;

	/*
	 * @todo: UV_ESM is not an HV interrupt, so don't need
	 * MSR_RI right?
	 */

	/*
	 * Unlikely that FP state was set on UV_ESM but we have
	 * to check. We also should not have synthesized interrupt
	 * but since restore_fp_state() behavior depends on it,
	 * ensure it is not.
	 */
	assert((excpf->flags & STACK_FLAGS_SYNTH_INTR) == 0);
	restore_fp_state(excpf);
}

static int find_boot_vcpu(struct svm *svm)
{
	uint32_t boot_cpu;
	void *fdt;

	if (svm->vcpus.max == 0)
		return U_PARAMETER;

	fdt = (void *)svm_fdt_get_fdt_hpa(svm);
	boot_cpu = fdt_boot_cpuid_phys(fdt);
	if (boot_cpu >= svm->vcpus.max)
		return U_PARAMETER;

	this_cpu()->vcpu.vcpuid = boot_cpu;
	this_cpu()->vcpu.lpid = svm->lpid;
	svm->vcpus.tracking = true;

	return 0;
}

static void __noreturn uv_esm_svm(struct refl_state *r_state, void *data)
{
	struct uv_esm_data *esm_data = (struct uv_esm_data *)data;
	int rc = U_RETRY;
	pgd_t *pgd;
	bool abort = false;

	pr_info("%s r_state=%llx, stack=%llx, esm_data=%llx,"
		" kbase=0x%llx, fdt=0x%llx\n", __func__,
		(u64) r_state, (u64) &r_state->excp_frame, (u64) esm_data,
		(u64) esm_data->kbase, (u64) esm_data->fdt);

	pgd = pgd_alloc(&r_state->svm->mm);
	if (!pgd)
		goto out;

	if (init_pagein_tracking(r_state->svm))
		goto out;

	/* We need to abort if errors encountered beyond this point */
	abort = true;

	rc = do_hcall(r_state, H_SVM_INIT_START, 0, NULL, 0);
	pr_info("%s(): H_SVM_INIT_START returned [%d]\n", __func__, rc);
	if (rc)
		goto out;

	rc = svm_fdt_init(r_state, esm_data->fdt);
	if (rc) {
		pr_error("%s: svm_fdt_init rc [%d]\n", __func__, rc);
		goto out;
	}

	rc = svm_esm_blob_chk(r_state, esm_data->kbase);
	if (rc) {
		pr_error("%s: svm_esm_blob_chk rc [%d]\n", __func__, rc);
#ifdef ESM_BLOB_CHK_WARN_ONLY
		/*
		 * WARNING: This code can execute only on Development systems.
		 * Since we have decided to continue even after failure,
		 * ensure that the kernel pages are brought in.
		 */
		if (svm_populate_kernel(r_state, esm_data->kbase))
			goto out;
		pr_warn("CONTINUING INSPITE OF ESM CHECK FAILURE.\n");
	        pr_warn("MAKE SURE THIS IS NOT RUNNING ON A PRODUCTION SYSTEM\n");
#else
		goto out;
#endif
	}

	/* finish the INIT_END */
	rc = do_hcall(r_state, H_SVM_INIT_DONE, 0, NULL, 0);
	if (rc) {
		pr_info("%s(): H_SVM_INIT_DONE returned [%d]\n", __func__, rc);
		goto out;
	}

	rc = find_boot_vcpu(r_state->svm);
	if (rc) {
		pr_info("%s(): find_boot_vcpu() returned [%d]\n", __func__, rc);
		goto out;
	}

	/* commit the partition scoped page table */
	svm_esm_commit(r_state->svm);
	pr_info("%s(): commit returned\n", __func__);

	svm_pagemap_test();

	r_state->excp_frame.srr1 |= MSR_S; /* switch to secure VM mode */
	r_state->excp_frame.srr1 &= ~(MSR_HV); /* Turn off HV*/
	/*
	 * Turn off EE. This will stop asynchronous interrups hitting
	 * the SVM and switching the endian mode to BE. The endian mode
	 * for exceptions will be set by the H_SET_MODE hcall. Till that
	 * point block async interrupts.
	 */
	r_state->excp_frame.srr1 &= ~(MSR_EE);
	r_state->excp_frame.usrr0 = esm_data->kbase;
	r_state->excp_frame.usrr1 = r_state->excp_frame.srr1;
	r_state->excp_frame.gpr[3] = esm_data->fdt;
	r_state->excp_frame.gpr[4] = esm_data->kbase;
	/* inform the kernel that it is kexec style entry */
	r_state->excp_frame.gpr[5] = 0x0UL;

	abort = false;

out:
	/* the page-in tracking is not needed anymore */
	destroy_pagein_tracking(r_state->svm);

	rc = svm_fdt_finalize(r_state, rc);
	if (rc) {
		pr_error("%s: svm_fdt_finalize rc [%d]\n", __func__, rc);
		abort = true;
	}

	free(data);

	if (abort) {
		/*
		 * If we encounter an error and SVM has gone secure, terminate
		 * the SVM. Otherwise send a H_SVM_INIT_ABORT to the
		 * hypervisor.
		 *
		 * The ultravisor log will contain relevent message explaining
		 * what exactly fail.
		 *
		 * @todo: send the reason for the abort/terminate.
		 * H_SVM_INIT_ABORT API does not have a way to convey that
		 * information.  Enhance the API?
		 */
		if (IS_SVM_SECURE(r_state->svm)) {
			pr_error("UV_ESM: terminating the VM\n");
			svm_initiate_kill(r_state, "Cannot secure VM!");
		} else {
			pr_error("UV_ESM: issuing H_SVM_INIT_ABORT\n");
			SET_SVM_ABORT(r_state->svm);
			fixup_uv_esm_excp_frame(r_state);
		}
		/* NOT REACHED */
	}

	ctx_end_context(r_state);
}

static u64 uv_read_scom(u64 target_id, u64 scom_addr, u64 *scom_value)
{
	if (!isAccessAllowed(scom_addr, 0, READ_ACCESS)) {
#ifdef XSCOM_BWLIST_ENFORCE
		return U_PERMISSION;
#endif /* XSCOM_BWLIST_ENFORCE */
	}

	return xscom_read((u32)target_id, scom_addr, scom_value);
}

static u64 uv_write_scom(u64 target_id, u64 scom_addr, u64 scom_value)
{
	if (!isAccessAllowed(scom_addr, 0, WRITE_ACCESS)) {
#ifdef XSCOM_BWLIST_ENFORCE
		return U_PERMISSION;
#endif /* XSCOM_BWLIST_ENFORCE */
	}

	return xscom_write((u32)target_id, scom_addr, scom_value);
}

struct uv_page_data {
	gfn_t gfn;  /* guest physical frame number */
	u64 npages; /* contiguous number of pages to share */
	bool share; /* share or unshare */
};

static void __noreturn uv_switch_page(struct refl_state *r_state, void *data)
{
	struct uv_page_data *page_data = (struct uv_page_data *)data;
	int rc;

	if (page_data->share)
		rc = page_share_with_hv(r_state, SVM_GFN_TO_GPA(page_data->gfn),
					page_data->npages, SHARE_EXPLICIT);
	else
		rc = page_unshare_with_hv(r_state, SVM_GFN_TO_GPA(page_data->gfn),
					page_data->npages);
	if (rc)
		goto error;

	r_state->excp_frame.srr1 &= ~(MSR_HV); /* Turn off HV*/
	r_state->excp_frame.usrr0 = r_state->excp_frame.srr0;
	r_state->excp_frame.usrr1 = r_state->excp_frame.srr1;
error:
	free(data);
	ctx_end_context(r_state);
}

static void __noreturn uv_unshare_all_pages(struct refl_state *r_state,
					    void *data)
{
	if (page_unshare_all_with_hv(r_state))
		goto error;

	r_state->excp_frame.srr1 &= ~(MSR_HV); /* Turn off HV*/
	r_state->excp_frame.usrr0 = r_state->excp_frame.srr0;
	r_state->excp_frame.usrr1 = r_state->excp_frame.srr1;
error:
	free(data);

	ctx_end_context(r_state);
}

static int memory_read(void *buffer, u64 rhandle, u64 offset, u32 size)
{
	struct mem_whitelist *mem;
	u32 rtype, rid;

	rid = rhandle >> 32;
	rtype = rhandle & 0xF;

	if (!buffer || !size)
		return U_PARAMETER;

	/* 
	 * @todo : ensure that buffer is a valid address. It should
	 * not be pointing to secure memory
	 */

	pr_info("Reading offset = 0x%llx, size = 0x%x, buffer = %p\n",
		offset, size, buffer);

	if (!(mem = mem_wl_range_allowed(rtype, rid, offset, size, false)))
		return U_PERMISSION;

	memcpy(buffer, (void *)(mem->start + offset), size);

	pr_info("OPAL Buffer Data (%016llx) = %016llx\n", (u64)buffer,
		*(u64 *)buffer);
	pr_info("MEM RSRC Data (%016llx) = %016llx\n",
		(u64)(mem->start + offset), *(u64 *)(mem->start + offset));

	return U_SUCCESS;
}


static int memory_write(void *buffer, u64 rhandle, u64 offset, u32 size)
{
	struct mem_whitelist *mem;
	u32 rtype, rid;

	rtype = rhandle >> 32;
	rid = rhandle & 0xFFFFFFFF;

	if (!buffer || !size)
		return U_PARAMETER;

	/* 
	 * @todo : ensure that buffer is a valid address. It should
	 * not be pointing to secure memory
	 */

	if (!(mem = mem_wl_range_allowed(rtype, rid, offset, size, true)))
		return U_PERMISSION;

	memcpy((void *)(mem->start + offset), buffer, size);
	return U_SUCCESS;
}

/*
 * Encode the bytes in @data into the double-word array @dwords. @data
 * can include NULL characters which must be preserved - no strlen()!.
 * Assume that the array has @ndw dwords. Note that all @ndw dwords are
 * initialized - even if @data requires fewer than @ndw double words.
 */
static int bytes_to_dwords(const char *data, int dlen, uint64_t *dwords,
			int ndw)
{
	int i, j, shift;

	assert(ndw <= 8);
	if (dlen > ndw * 8) {
		pr_error("%s: dlen %d, ndw, %d\n", __func__, dlen, ndw);
		return -1;
	}

	memset(dwords, 0, ndw * 8);
	for (i = 0, j = 0, shift = 56; i < dlen; i++) {
		dwords[j] |= ((u64) data[i] << shift);
		shift -= 8;
		if (shift < 0) {
			j++;
			shift = 56;
		}
	}

	return 0;
}

/*
 * Convert the dwords into a string of bytes. Assumes that the @data
 * buffer is large enough for the ndw*8 bytes plus a terminating NULL.
 */
static void dwords_to_bytes(uint64_t *dwords, int ndw, char *data)
{
	int i, j, shift;

	assert(ndw <= 8);

	memset(data, 0, ndw*8+1);
	for (i = 0, j = 0, shift = 56; i < ndw; j++) {
		data[j] = (char) ((dwords[i] >> shift) & 0xFF);
		shift -= 8;
		if (shift < 0) {
			shift = 56;
			i++;
		}
	}
}

#define ESMB_AES_KEY_LEN	32

/*
 * Encode the file @fname's data starting at offset @offset into a set
 * of double-words and copy the set to @dwords. Limit to @ndw double-words
 */
static int get_file_data(struct svm *svm, char *fname, uint64_t offset,
			uint64_t *dwords, int ndw)
{
	int rc;
	char *data;
	size_t data_len;
	void *files_fdt;
	uint8_t *key_buf;
	uint16_t key_len;
	struct svm_esmb *svm_esmb;
	char path[72];

	/*
	 * User files are under "/files" in the blob, so prefix the
	 * pathname. We assume max length of path is 64 bytes. If not
	 * its a bug in the caller!
	 */
	assert(strlen(fname) <= 64);
	assert(offset < SVM_PAGESIZE);

	memset(path, 0, sizeof(path));
	strcpy(path, "/files/");
	strcat(path, fname);

	data = malloc(SVM_PAGESIZE);
	if (!data) {
		pr_error("%s() Unable to alloc %ld bytes\n",
			 __func__, SVM_PAGESIZE);
		return U_RETRY;
	}

	memset(data, 0, SVM_PAGESIZE);
	data_len = SVM_PAGESIZE;

	svm_esmb = gpa_to_addr(&svm->mm, svm->svm_esmb, NULL);
	files_fdt = gpa_to_addr(&svm->mm, svm->esmb_files_fdt, NULL);

	pr_debug("%s(%s) dumping files_fdt\n", __func__, path);
	dump_fdt(files_fdt);

	key_len = ESMB_AES_KEY_LEN;
	key_buf = svm_esmb->buf_key;

	rc = svm_esmb_file_get((hpa_t)files_fdt, path, key_buf, key_len,
			       data, &data_len);

	pr_debug("%s() file_get rc %d, data %.16s, len 0x%lx\n",
		 __func__, rc, data, data_len);
	if (rc)
		goto out;

	if (offset >= data_len)
		return 0;

	data_len -= offset;

	if (data_len > (ndw * sizeof(uint64_t)))
		data_len = (ndw * sizeof(uint64_t));

	if (bytes_to_dwords(&data[offset], data_len, dwords, ndw) < 0) {
		pr_error("%s() bytes_to_dwords failed\n", __func__);
		goto out;
	}

	rc = data_len;

out:
	free(data);
	return rc;
}

/*
 * ESM blob includes encrypted versions of files that the user attached
 * to the blob. User is attempting to retrieve their original (decrypted)
 * file from the blob.
 *
 * Retrieve the encrypted file, decrypt it and return upto 64 bytes of
 * the file's data, starting at offset specified in R4 (offset is w.r.t
 * their original data which was decrypted). File name is in R5:R12.
 * Copy the file data into R4:R11 and return number of bytes (which will
 * be copied into R3 by caller).
 *
 * For security reasons, the contents of a file may only be read once
 * per boot, in a sequential manner. If the file has more than 64 bytes,
 * subsequent UV_ESMB_GET_FILE calls must also be by the same process as
 * the first ucall and at an offset higher than the previously read bytes.
 *
 * Since only one process should read the entire contents of a file,
 * we don't need any locks around reading/updating ->last_byte_read
 * below. @todo: Is PID wrap a concern?
 */
static int uv_esmb_get_file(struct stack_frame *stack)
{
	int rc;
	char fname[65];
	struct svm *svm;
	uint64_t offset;
	struct esmb_file_ctx *ctx;

	offset = stack->gpr[4];
	dwords_to_bytes(&stack->gpr[5], 8, fname);

	pr_debug("%s(0x%llx, %s): LPID 0x%llx, PID 0x%llx\n",
		 __func__, offset, fname, stack->lpidr, stack->pidr);

	svm = get_svm(stack->lpidr);
	if (!svm) {
		rc = U_PARAMETER;
		goto out;
	}

	ctx = find_esmb_file_ctx(svm, fname);
	if (!ctx) {
		ctx = malloc(sizeof(struct esmb_file_ctx));
		if (!ctx) {
			rc = U_RETRY;
			goto out;
		}

		memset(ctx, 0, sizeof(struct esmb_file_ctx));
		strcpy(ctx->filename, fname);
		ctx->pid = stack->pidr;
		ctx->last_byte_read = 0;
		list_add_tail(&svm->esmb_file_ctx, &ctx->link);
	}

	if (ctx->pid != stack->pidr || offset < ctx->last_byte_read) {
		rc = U_PARAMETER;
		goto out;
	}

	/* get upto 64-bytes of data from the file, starting at @offset */
	rc = get_file_data(svm, fname, offset, &stack->gpr[4], 8);
	if (rc < 0)
		goto out;

	ctx->last_byte_read = offset + rc;

out:
	return rc;
}

static int syscall_ultracall_esm_svm(struct stack_frame *stack)
{
	int rc;
	struct uv_esm_data *esm_data;
	u64 kbase = stack->gpr[4];
	u64 fdt   = stack->gpr[5];

	pr_debug("%s stack=0x%llx, kbase=0x%llx, fdt=0x%llx\n",
		__func__, (u64) stack, kbase, fdt);

	if (!kbase)
		return U_P2;
	if (!fdt)
		return U_P3;

	if (!stack->lpidr) {
		pr_error("UV_ESM called by an unauthorized lpid(0)\n");
		return U_PERMISSION;
	}

	if (stack->srr1 & (MSR_HV|MSR_PR)) {
		pr_error("UV_ESM called in non-supervisor mode (MSR=0x%llx)\n",
			 stack->srr1);
		return U_PERMISSION;
	}

	esm_data = zalloc(sizeof(*esm_data));
	if (!esm_data)
		return U_RETRY;
	esm_data->kbase = kbase;
	esm_data->fdt   = fdt;

	rc = create_svm(stack->lpidr);
	if (rc) {
		rc = U_RETRY;
		goto out;
	}

	rc = ctx_new_context_svm(stack->lpidr, stack, uv_esm_svm, esm_data);
	if (rc) {
		rc = U_RETRY;
		pr_error("%s: new_context returned %d\n", __func__, rc);
		destroy_svm(stack->lpidr);
	}

out:
	free(esm_data);
	return rc;
}

/* handle all the ucalls from the hypervisor */
static int ucall_from_hypervisor(u64 function, struct stack_frame *stack)
{
	u64 value;
	int rc = U_FUNCTION;

	switch (function) {

	case UV_WRITE_PATE:
		rc = uv_write_pate(stack->gpr[4], stack->gpr[5],
					stack->gpr[6]);
		break;

	case UV_RETURN:
		/*
		 * When making an ucall, R3 must have the ucall number. So
		 * HV sets R3 to UV_RETURN and saves the return value of the
		 * reflected hcall in R0. Move the return value back into R3
		 * where it usually belongs.
		 */
		stack->gpr[3] = stack->gpr[0];
		rc = uv_return(stack->gpr[3], stack);
		break;

	case UV_RESTRICTED_SPR_WRITE:
		rc = uv_restricted_spr_write(stack->gpr[4], stack->gpr[5]);
		break;

	case UV_RESTRICTED_SPR_READ:
		rc =  uv_restricted_spr_read(stack->gpr[4], &(stack->gpr[5]));
		break;

	case UV_READ_SCOM:
		rc =  uv_read_scom(stack->gpr[4], stack->gpr[5], &value);
		if (!rc)
			stack->gpr[4] = value;
		break;

	case UV_WRITE_SCOM:
		rc =  uv_write_scom(stack->gpr[4], stack->gpr[5],
				stack->gpr[6]);
		break;

	case UV_REGISTER_MEM_SLOT:
		{
			u64 lpid = stack->gpr[4];
			gpa_t start_gpa = stack->gpr[5];
			u64 nbytes = stack->gpr[6];
			u64 flags = stack->gpr[7];
			u16 slotid = stack->gpr[8];

			rc =  uv_register_mem_slot(lpid, start_gpa, nbytes,
						   flags, slotid);
			break;
		}

	case UV_UNREGISTER_MEM_SLOT:
		{
			u64 lpid = stack->gpr[4];
			u16 slotid = stack->gpr[5];

			rc =  uv_unregister_mem_slot(lpid, slotid);
			break;
		}

	case UV_PAGE_IN:
	case UV_PAGE_OUT:
		{
			u64 lpid = stack->gpr[4];
			u64 hv_page = stack->gpr[5];
			gpa_t gpa = stack->gpr[6];
			u64 flag = stack->gpr[7];
			u64 order = stack->gpr[8];

			if (function == UV_PAGE_IN)
				rc =  uv_page_in(lpid, hv_page, gpa,
						 flag, order);
			else
				rc =  uv_page_out(lpid, hv_page, gpa,
						  flag, order);
			break;
		}

	case UV_PAGE_INVAL:
		{
			u64 lpid = stack->gpr[4];
			gpa_t gpa = stack->gpr[5];
			u64 order = stack->gpr[6];

			rc =  uv_page_inval(lpid, gpa, order);
			break;
		}

	case UV_SVM_TERMINATE:
		rc =  uv_svm_terminate(stack->gpr[4]);
		break;

	case UV_READ_MEM:
	case UV_WRITE_MEM:
		{
			void *buffer  = (void *)stack->gpr[4];
			u64 rhandle = (u64) stack->gpr[5];
			u64 offset  = (u64) stack->gpr[6];
			u32 size    = (u32) stack->gpr[7];

			if (function == UV_READ_MEM)
				rc = memory_read(buffer, rhandle, offset, size);
			else
				rc = memory_write(buffer, rhandle, offset, size);
		}
		break;

	case UV_SEND_SBE_COMMAND:
		rc = send_sbe_command(stack->gpr[4], stack->gpr[5],
					stack->gpr[6], &stack->gpr[4]);
		break;

	default:
		pr_error("Unsupported Ultracall (Lev=2) function:%lld\n",
			 function);
	}

	return rc;
}

/* handle all the ucalls from the supervisor */
static int ucall_from_supervisor(u64 function, struct stack_frame *stack)
{
	int rc = U_FUNCTION;

	switch (function) {

	case UV_ESM:
		rc = syscall_ultracall_esm_svm(stack);
		break;

	case UV_SHARE_PAGE:
	case UV_UNSHARE_PAGE:
		{
			struct uv_page_data *page_data =
				zalloc(sizeof(*page_data));

			if (!page_data) {
				rc = U_RETRY;
				break;
			}
			page_data->gfn = stack->gpr[4];
			page_data->npages = stack->gpr[5];
			page_data->share = (function == UV_SHARE_PAGE);
			rc = ctx_new_context_svm(stack->lpidr, stack,
						 uv_switch_page, page_data);
			if (rc)
				pr_error("%s: new_context returned %d\n",
					 __func__, rc);

			free(page_data);
			break;
		}

	case UV_UNSHARE_ALL_PAGES:
		{
			rc = ctx_new_context_svm(stack->lpidr, stack,
						 uv_unshare_all_pages, NULL);
			if (rc)
				pr_error("%s: new_context returned %d\n",
					 __func__, rc);
			break;
		}

	default:
		pr_error("Unsupported Ultracall (Lev=2) function:%lld\n",
			 function);
	}

	return rc;
}

/*
 * Enter to perform an ultracall requested by the hypervisor or a guest.
 * We are still on the per-CPU stack at this point, and `stack' points
 * to the stack frame with the registers as of the ultracall.
 */
int syscall_ultracall(u64 function, struct stack_frame *stack)
{
	int rc = check_regs_on_hv_exit(function, stack);

	if (rc < 0)
		return rc;

	/* @todo: how to stop nested VMs from making this call ? */

	rc = U_FUNCTION;
	switch (function) {
	case UV_WRITE_PATE:
	case UV_RESTRICTED_SPR_WRITE:
	case UV_RETURN:
	case UV_RESTRICTED_SPR_READ:
	case UV_READ_SCOM:
	case UV_WRITE_SCOM:
	case UV_REGISTER_MEM_SLOT:
	case UV_UNREGISTER_MEM_SLOT:
	case UV_PAGE_IN:
	case UV_PAGE_OUT:
	case UV_PAGE_INVAL:
	case UV_SVM_TERMINATE:
	case UV_READ_MEM:
	case UV_WRITE_MEM:
	case UV_SEND_SBE_COMMAND:
		if ((stack->srr1 & (MSR_HV | MSR_PR)) != MSR_HV) {
			pr_error("Illegal %s(Called from non-HV context)\n",
				 stringify(function));
			rc = U_PERMISSION;
			break;
		}
		rc = ucall_from_hypervisor(function, stack);
		break;

	case UV_SHARE_PAGE:
	case UV_UNSHARE_PAGE:
	case UV_UNSHARE_ALL_PAGES:
		if (!(stack->srr1 & MSR_S)) {
			pr_error("Illegal %s(Called from non-Secure context)\n",
				 stringify(function));
			rc = U_PERMISSION;
			break;
		}
		/* FALL THROUGH */
	case UV_ESM:
		if (stack->srr1 & (MSR_HV | MSR_PR)) {
			pr_error("Illegal %s(Called from non-Supervisor context)\n",
				 stringify(function));
			rc = U_PERMISSION;
			break;
		}
		rc = ucall_from_supervisor(function, stack);
		break;

	case UV_ESMB_GET_FILE:
		rc = uv_esmb_get_file(stack);
		break;

	default:
		pr_error("Unsupported Ultracall (Lev=2) function:%lld\n",
			 function);
	}

	return rc;
}
