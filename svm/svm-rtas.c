// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2018 IBM Corp.
 */

#undef DEBUG
#define pr_fmt(fmt) "SVM-RTAS: " fmt

#include <compiler.h>
#include <context.h>
#include <cpu.h>
#include <errno.h>
#include <exceptions.h>
#include <hvcall.h>
#include <inttypes.h>
#include <logging.h>
#include <stack.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <svm/svm-internal.h>
#include <svm/svm-rtas-bbuf.h>
#include <svm/svm-rtas-hdlr.h>
#include <svm/svm-rtas.h>
#include <utils.h>

//#define DEBUG
#ifdef DEBUG
#define svm_rtas_dprintf(fmt...) do { printf(fmt); } while(0)
#else
#define svm_rtas_dprintf(fmt...) do { } while(0)
#endif


#ifdef DEBUG
static void svm_rtas_args_dprintf(struct rtas_args *r_args)
{
       int i;
       int nargs = r_args->nargs;
       int nret = r_args->nret;

       printf("token: %x\n", r_args->token);
       printf("nargs: %x\n", nargs);
       printf("nret: %x\n", nret);

       for (i = 0; i < (nargs + nret); i++)
	       printf("args[%d]: %x\n", i, r_args->args[i]);

       printf("rets: %llx \n", (uint64_t)r_args->rets);
}
#else
#define svm_rtas_args_dprintf(r_args) do {} while(0)
#endif

/**
 * Generate an unique cookie for the SVM @svm and associate it with the data
 * pointer given by @data.  The value of the cookie must have bits in the
 * non-mask locations set to zero, and cannot be lower than the min_value.
 */
uint64_t svm_generate_cookie(struct svm *svm, void *data, uint64_t mask,
		uint64_t minval)
{
	uint64_t cookie;

	lock(&svm->lock);

	cookie = cookie_generate(svm->cookie_table,
	                         COOKIE_HASHBITS, data,
				 mask, minval);

	unlock(&svm->lock);

	return cookie;
}

void *svm_find_del_cookie(struct svm *svm, uint64_t cookie)
{
	void *data;

	lock(&svm->lock);

	data = cookie_find_del(svm->cookie_table, cookie, COOKIE_HASHBITS);

	unlock(&svm->lock);

	return data;
}

void svm_cleanup_cookie(struct svm *svm)
{
	cookie_cleanup(svm->cookie_table, ARRAY_LENGTH(svm->cookie_table));
}

/**
 * Check if we got here due to a recent 'start-cpu' call. Otherwise
 * just return -1 back to caller.
 *
 * If we get here due to a 'start-cpu' RTAS call, finish the process of
 * setting up the new CPU or onlining an offline CPU AND return directly
 * to the SVM. See also function header of rtas_start_cpu_begin() and
 * notes in our caller uv_return()).
 *
 * Use the 'start-cpu cookie' from R3 to retrieve and validate the saved
 * state. Then have the new CPU start executing in secure mode from the
 * 'start_here' address specified in the RTAS call.
 */
int rtas_start_cpu_end(struct svm *svm, struct stack_frame *stack)
{
	struct start_cpu_state *start_cpu;
	struct refl_state *r_state;

	/*
	 * Since we generated a cookie that was >= MAX_EXCEPTION,
	 * short-circuit the common case.
	 */
	if (stack->gpr[3] < MAX_EXCEPTION)
		return -1;

	start_cpu = svm_find_del_cookie(svm, stack->gpr[3]);
	if (!start_cpu)
		return -1;

	/*
	 * @todo Unlikely SVM will disappear while in start-cpu, but
	 * do we need to refcount SVM? Proceed optimistically for now.
	 *
	 * @todo Add a magic field in 'start_cpu' like in refl_state, and
	 * use it check that HV did not tamper with the start_cpu field.
	 */
	if (svm->lpid != start_cpu->svm->lpid) {
		/*
		 * Hmm we found a valid cookie but it belonged to a
		 * different SVM! Is our cookie generator broken?
		 * @todo We have to do some work to to add this cookie back
		 * to the list but bail for now.
		 */
		pr_error("%s(): LPID mismatch [0x%llx v. 0x%llx]\n",
			 __func__, svm->lpid, start_cpu->svm->lpid);
		goto bad_cookie;
	}

	/*
	 * @todo: Any other registers to set/clear? (or copy over from
	 * the boot CPU in rtas_start_cpu_begin() and restore here?)
	 */
	stack->usrr0 = start_cpu->start_here;
	stack->usrr1 = MSR_SF | MSR_ME | MSR_S;
	stack->gpr[3] = start_cpu->r3_contents;

	if (start_cpu->cpu_id >= svm->vcpus.max)
		goto bad_cookie;

	this_cpu()->vcpu.vcpuid = start_cpu->cpu_id;
	this_cpu()->vcpu.lpid = stack->lpidr;

	free(start_cpu);

	/*
	 * If there is a valid cookie in R31 due to a prior stop-self,
	 * find and drop the reference to the associated reflect state.
	 * We used a pre-allocated per-vcpu args buffer for stop-self
	 * in svm_rtas() so we don't need to free it.
	 */
	r_state = svm_find_del_cookie(svm, stack->gpr[31]);
	if (r_state && r_state->magic == ULTRA_COOKIE_MAGIC) {
		svm_rtas_dprintf("%s() EXID 0x%llx stop-self "
				 "cookie 0x%llx / 0x%llx\n",
				 __func__, stack->excp_id, stack->gpr[31],
				 r_state->excp_frame.excp_id);
		put_reflect_state(r_state);
	} else {
		svm_rtas_dprintf("%s(): EXID 0x%llx return from NEW cpu?\n",
				__func__, stack->excp_id);
	}

	urfid_return(stack);

bad_cookie:
	assert(0);	/* @todo terminate just this SVM */
}

static int svm_rtas_pre_hdlr(struct svm *svm, struct rtas_args *guest_args,
			     struct rtas_args *bb_args)
{
	int rc;
	struct svm_rtas_hdlr *rh;

	for (rc = 0, rh = svm_rtas_hdlrs; rh->service; rh++) {
		/* per PAPR, token == 0 is invalid token. Hence ignore it */
		if (rh->token && bb_args->token == rh->token) {
			rc = rh->handler(RTAS_HDLR_PRE, svm, guest_args,
					 bb_args);
			break;
		}
	}

	if (rc)
		pr_error("%s: pre handler for %s failed (%d)\n",
			 __func__, rh->service, rc);

	return rc;
}

static int svm_rtas_post_hdlr(struct svm *svm, struct rtas_args *guest_args,
			      struct rtas_args *bb_args)
{
	int rc;
	struct svm_rtas_hdlr *rh;

	for (rc = 0, rh = svm_rtas_hdlrs; rh->service; rh++) {
		/* per PAPR, token == 0 is invalid token. Hence ignore it */
		if (rh->token && bb_args->token == rh->token) {
			rc = rh->handler(RTAS_HDLR_POST, svm, guest_args,
					 bb_args);
			break;
		}
	}

	if (rc)
		pr_error("%s: post handler for %s failed (%d)\n",
			 __func__, rh->service, rc);

	return rc;
}

static int svm_rtas_token_lookup(struct svm *svm)
{
	int rc;
	hpa_t hpa_fdt = svm_fdt_get_fdt_hpa(svm);
	uint32_t token;
	struct svm_rtas_hdlr *rh;

	rc = svm_fdt_prop_u32_get(hpa_fdt, "/rtas", "stop-self", &token);
	if (rc)
		return rc;

	svm->rtas.stop_self_token = token;

	for (rc = 0, rh = svm_rtas_hdlrs; rh->service; rh++) {
		rc = svm_fdt_prop_u32_get(hpa_fdt, "/rtas", rh->service, &token);
		if (rc) {
			/*
			 * Older QEMU may not support this RTAS token. If it is
			 * an optional RTAS token then don't fail the SVM guest
			 * boot. For all optional RTAS calls, the token number
			 * will remain 0 which is invalid token as per PAPR.
			 * Hence the token number is validated before calling
			 * handler.
			 */
			if (rh->optional) {
				pr_debug("prop_u32_get failed [%d]\n", rc);
				rc = 0;
				continue;
			}
			pr_error("prop_u32_get failed [%d]\n", rc);
			return rc;
		}
		rh->token = token;
	}

	return rc;
}

static inline unsigned int gpa2bit(struct svm *svm, gpa_t gpa)
{
	/*
	 * The RTAS pages are contiguous (see svm_rtas_fdt_upd_hdlr()), and the
	 *  first one is rtas_args_bbuf.
	 */
	return SVM_GPA_TO_GFN(gpa) - SVM_GPA_TO_GFN(svm->rtas.rtas_args_bbuf);
}

static inline bool rtas_is_gpa_present(struct svm *svm, gpa_t gpa)
{
	return (svm->rtas.rtas_buf_present & (0x1 << gpa2bit(svm, gpa)));
}

#define rtas_set_gpa_present(svm, gpa) \
	(svm->rtas.rtas_buf_present |= (0x1 << gpa2bit(svm, gpa)))
#define rtas_set_gpa_notpresent(svm, gpa) \
	(svm->rtas.rtas_buf_present &= ~(0x1 << gpa2bit(svm, gpa)))

static bool is_rtas_buf_gpa(struct svm *svm, gpa_t gpa)
{
	return (gpa >= svm->rtas.rtas_args_bbuf) &&
		(gpa < (svm->rtas.stop_self_args + SVM_PAGESIZE));
}

#define GPA_NOT_PRESENT	0
#define GPA_PRESENT	1
static void __svm_rtas_change_gpa_state(struct svm *svm, gpa_t gpa, int flag)
{
	if (is_rtas_buf_gpa(svm, gpa)) {
		if (flag)
			rtas_set_gpa_present(svm, gpa);
		else
			rtas_set_gpa_notpresent(svm, gpa);
		unlock(&svm->rtas.rtas_gpa_lock);
	}
}

static inline void __svm_rtas_pre_setup(struct svm *svm, gpa_t gpa)
{
	if (is_rtas_buf_gpa(svm, gpa))
		lock(&svm->rtas.rtas_gpa_lock);
}

void svm_rtas_pre_invalidate(struct svm *svm, gpa_t gpa)
{
	__svm_rtas_pre_setup(svm, gpa);
}

void svm_rtas_post_invalidate(struct svm *svm, gpa_t gpa)
{
	__svm_rtas_change_gpa_state(svm, gpa, GPA_NOT_PRESENT);
}

void svm_rtas_pre_shared_pagein(struct svm *svm, gpa_t gpa)
{
	__svm_rtas_pre_setup(svm, gpa);
}

void svm_rtas_post_shared_pagein(struct svm *svm, gpa_t gpa)
{
	__svm_rtas_change_gpa_state(svm, gpa, GPA_PRESENT);
}

/*
 * svm_pin_rtas_buffers() -- block invalidation of pages
 * 			associated with all RTAS GPAs.
 *
 * Returns with svm->rtas.rtas_gpa_lock held.
 * Caller must release the lock.
 */
static void svm_pin_rtas_buffers(struct refl_state *r_state)
{
	struct svm *svm = r_state->svm;

	lock(&svm->rtas.rtas_gpa_lock);

	svm_pin_pages(r_state, svm->rtas.rtas_args_bbuf, 6,
		      &svm->rtas.rtas_gpa_lock, rtas_is_gpa_present);

	/*
	 * Yes we do not unlock the rtas_gpa_lock. Unlocking should be done
	 * in the svm_unpin_rtas_buffers(struct svm *svm)
	 */
}

/*
 * svm_unpin_rtas_buffers() -- unblock invalidation of pages
 * 			associated with all RTAS GPAs.
 */
static void svm_unpin_rtas_buffers(struct refl_state *r_state)
{
	struct svm *svm = r_state->svm;

	unlock(&svm->rtas.rtas_gpa_lock);
}

int svm_rtas(struct refl_state *r_state)
{
	int i, rc;
	gpa_t g_args_gpa;
	hpa_t g_args_hpa;
	gpa_t bb_args_gpa;
	hpa_t bb_args_hpa;
	struct svm *svm;
	struct rtas_args *guest_args;
	struct rtas_args *bb_args;

	/*
	 * Do not allow invalidation of RTAS buffers.
	 */
	svm_pin_rtas_buffers(r_state);

	svm = r_state->svm;

	g_args_gpa = r_state->excp_frame.gpr[4];

	g_args_hpa = (hpa_t)gpa_to_addr(&svm->mm, g_args_gpa, NULL);
	assert(g_args_hpa);
	guest_args = (struct rtas_args *)NO_RMOR(g_args_hpa);

	r_state->token = guest_args->token;

	/* Use a pre-allocated per-vcpu args buffer for stop-self. */
	if (guest_args->token == svm->rtas.stop_self_token) {
		uint32_t vcpu = this_cpu()->vcpu.vcpuid;

		/* If this happens, there's a bug in the Ultravisor. */
		if (vcpu >= svm->vcpus.max ||
		    this_cpu()->vcpu.lpid != svm->lpid) {
			pr_error("%s: Can't call stop-self: "
				 "unknown vcpu %u (lpid %llx)\n",
				 __func__, vcpu, svm->lpid);
			/*
			 * svm_abort() calls do_reflect() so stop tracking vcpu.
			 */
			svm->vcpus.tracking = false;
			svm_abort(r_state);
		}

		bb_args_gpa = svm->rtas.stop_self_args +
			      vcpu * RTAS_STOP_SELF_ARGS_SIZE;
	} else
		bb_args_gpa = svm_rtas_bbuf_alloc(&svm->mm, &svm->rtas);

	assert(bb_args_gpa);
	bb_args_hpa = (hpa_t)gpa_to_addr(&svm->mm, bb_args_gpa, NULL);
	assert(bb_args_hpa);
	bb_args = (struct rtas_args *)NO_RMOR(bb_args_hpa);

	/*
	 * nargs count args only. Handler will copy contents of buffer
	 * if needed.
	 */
	bb_args->token = guest_args->token;
	bb_args->nargs = guest_args->nargs;
	bb_args->nret = guest_args->nret;
	for (i = 0; i < bb_args->nargs; i++) {
		bb_args->args[i] = guest_args->args[i];
	}

	/** @todo should we expose rtas rets */
	bb_args->rets = guest_args->rets;

	svm_rtas_dprintf("%s: bb_args\n", __func__);
	svm_rtas_args_dprintf(bb_args);

	r_state->rtas_bb_args_gpa = (uint64_t)bb_args_gpa;

	rc = svm_rtas_pre_hdlr(svm, guest_args, bb_args);

	/*
	 * OK to invalidate RTAS GPAs now onwards.
	 */
	svm_unpin_rtas_buffers(r_state);

	return rc;
}

int svm_rtas_return(struct refl_state *r_state)
{
	int i, rc;
	gpa_t g_args_gpa;
	hpa_t g_args_hpa;
	gpa_t bb_args_gpa;
	hpa_t bb_args_hpa;
	struct svm *svm;
	struct rtas_args *guest_args;
	struct rtas_args *bb_args;

	/*
	 * Do not allow invalidation of RTAS buffers.
	 */
	svm_pin_rtas_buffers(r_state);

	svm = r_state->svm;

	g_args_gpa = r_state->excp_frame.gpr[4];

	g_args_hpa = (hpa_t)gpa_to_addr(&svm->mm, g_args_gpa, NULL);
	assert(g_args_hpa);
	guest_args = (struct rtas_args *)NO_RMOR(g_args_hpa);

	bb_args_gpa = r_state->rtas_bb_args_gpa;
	bb_args_hpa = (hpa_t)gpa_to_addr(&svm->mm, bb_args_gpa, NULL);
	assert(bb_args_hpa);
	bb_args = (struct rtas_args *)NO_RMOR(bb_args_hpa);

	/*
	 * nret count args only. Handler will copy contents of buffer
	 * if needed.
	 */
	for (i = bb_args->nargs;
	     i < (bb_args->nargs + bb_args->nret); i++) {
		guest_args->args[i] = bb_args->args[i];
	}

	svm_rtas_dprintf("%s: g_args_hpa\n", __func__);
	svm_rtas_args_dprintf(guest_args);

	rc = svm_rtas_post_hdlr(svm, guest_args, bb_args);

	/*
	 * We used a pre-allocated per-vcpu args buffer for stop-self,
	 * so no need to free its per-cpu args buffer.
	 */
	if (guest_args->token != svm->rtas.stop_self_token)
		svm_rtas_bbuf_free(&svm->rtas, bb_args_gpa);

	/*
	 * OK to invalidate RTAS GPAs now onwards.
	 */
	svm_unpin_rtas_buffers(r_state);

	r_state->token = 0;

	return rc;
}

/* Find out from FDT the the maximum number of vcpus in the guest. */
static uint32_t get_max_vcpus(hpa_t fdt)
{
	int rc;
	int cpus_offset;
	uint32_t addr_cells, size_cells, max_cores;
	const struct fdt_property *prop;
	int prop_len;

	rc = svm_fdt_prop_u32_get(fdt, "/", "#address-cells", &addr_cells);
	if (rc)
		return rc;

	rc = svm_fdt_prop_u32_get(fdt, "/", "#size-cells", &size_cells);
	if (rc)
		return rc;

	/*
	 * From in LoPAPR section B.5.3.1 RTAS Node Properties:
	 *
	 * "Property value is a triple consisting of phys, size, and one integer
	 * encoded as with encode-int. [...] The first integer communicates the
	 * maximum number of processors (implied quantum of 1)."
	 */
	rc = svm_fdt_prop_get(fdt, "/rtas", "ibm,lrdr-capacity", &prop,
			      &prop_len);
	if (rc)
		return rc;

	max_cores = svm_fdt_get_cell(prop, addr_cells + size_cells);

	cpus_offset = fdt_node_offset_by_prop_value(
		(void *)fdt, 0, "device_type", "cpu", sizeof("cpu"));
	if (cpus_offset < 0)
		return cpus_offset;

	/*
	 * ibm,ppc-interrupt-server#s contains one element for each hardware
	 * thread in the processor. Each element is 4 bytes wide (see LoPAPR
	 * section B.5.4. Properties of the Node of type cpu).
	 */
	prop = fdt_get_property((void *)fdt, cpus_offset,
				"ibm,ppc-interrupt-server#s", &prop_len);
	if (prop == NULL)
		/* If there's no property, assume 1 thread. */
		prop_len = 4;

	/*
	 * Multiply number of cores by number of threads to get total number of
	 * vcpus.
	 */
	return max_cores * prop_len / 4;
}

static int64_t svm_rtas_fdt_upd_hdlr(struct refl_state *r_state)
{
	int rc;
	gpa_t g_addr;
	hpa_t hpa_fdt;
	struct svm *svm = r_state->svm;

	hpa_fdt = svm_fdt_get_fdt_hpa(svm);

	rc = svm_rtas_token_lookup(svm);
	if (rc) {
		pr_error("%s: svm_rtas_token_lookup [%d]\n", __func__, rc);
		return rc;
	}

	init_lock(&svm->rtas.rtas_gpa_lock);
	svm->rtas.rtas_buf_present = 0x0;

	svm->vcpus.max = get_max_vcpus(hpa_fdt);
	if (svm->vcpus.max > MAX_GUEST_CPUS)
		return U_PARAMETER;

	/*
	 * Reserve some pages hidden from the SVM guest that will be used
	 * by the UV to contain shared buffers with the HV:
	 * 	1 page for rtas_args_bbuf
	 * 	4 pages for rtas_buf_bbuf
	 * 	1 page for stop_self_args buffers
	 *
	 * NB: gpa2bit() depends on these pages being contiguous.
	 */
	rc = svm_fdt_mem_rsv(svm, hpa_fdt, 6*SVM_PAGESIZE, &g_addr);
	if (rc) {
		pr_error("%s: svm_fdt_mem_rsv [%d]\n", __func__, rc);
		return rc;
	}

	/*
	 * Set the GPA of the buffer now. This will ensure
	 * any pageins agains this GPA to be noted accordingly.
	 * page_share_with_hv() can trigger a page-in event against
	 * this GPA.
	 *
	 * @todo: rtas_args_bbuf is only used by svm_initiate_kill(). That
	 * function should be changed to use rtas_buf_bbuf instead and this
	 * buffer should be removed.
	 */
	svm->rtas.rtas_args_bbuf = g_addr;
	rc = page_share_with_hv(r_state, g_addr, 1, SHARE_IMPLICIT);
	if (rc) {
		svm->rtas.rtas_args_bbuf = 0;
		pr_error("%s: page_share_with_hv [%d]\n", __func__, rc);
		return rc;
	}

	svm_rtas_dprintf("%s: page share addr 0x%llx\n", __func__, (u64)g_addr);

	g_addr = g_addr + SVM_PAGESIZE;

	/*
	 * Set the GPA of this buffer now..
	 */
	svm->rtas.rtas_buf_bbuf = g_addr;
	rc = page_share_with_hv(r_state, g_addr, 4, SHARE_IMPLICIT);
	if (rc) {
		svm->rtas.rtas_buf_bbuf = 0;
		pr_error("%s: page_share_with_hv [%d]\n", __func__, rc);
		return rc;
	}
	svm_rtas_dprintf("%s: page share addr 0x%llx\n", __func__, (u64)g_addr);

	/* Setup shared page for per-vcpu stop-self argument buffers. */
	g_addr += 4*SVM_PAGESIZE;
	svm->rtas.stop_self_args = g_addr;
	rc = page_share_with_hv(r_state, g_addr, 1, SHARE_IMPLICIT);
	if (rc) {
		svm->rtas.stop_self_args = 0;
		pr_error("%s: page_share_with_hv [%d]\n", __func__, rc);
		return rc;
	}

	svm_rtas_bbuf_init(&svm->rtas);

	return 0;
}

DECLARE_SVM_OPS(svm_rtas) = {
	.name = "svm_rtas",
	.fdt_upd_hdlr = svm_rtas_fdt_upd_hdlr,
};

/*
 * Initiate the process of terminating the SVM.
 *
 * Use the SVM's bounce-buffer to issue "ibm,os-term" RTAS call.
 */
#define RTAS_IBM_OS_TERM	0x201F	/* From QEMU. @todo: lookup instead? */

void __noreturn svm_initiate_kill(struct refl_state *r_state, const char *msg)
{
	int rc;
	struct rtas_args *rtas_args;
	hpa_t bb_args_hpa;
	gpa_t bb_args_gpa;
	struct svm *svm;

	svm_pin_rtas_buffers(r_state);

	svm = r_state->svm;

	pr_error("SVM %lld: Initiating ibm,os-term ('%s')\n", svm->lpid, msg);

	bb_args_gpa = svm->rtas.rtas_args_bbuf;
	bb_args_hpa = (hpa_t)gpa_to_addr(&svm->mm, bb_args_gpa, NULL);
	assert(bb_args_hpa);

	rtas_args = (struct rtas_args *)NO_RMOR(bb_args_hpa);

	/*
	 * @todo: To forward the "reason" for the os-term, we would need
	 * 	  to copy @msg into the bounce buffer, maybe after the
	 * 	  rtas_args structure below and pass in the gpa of that
	 * 	  address. But since QEMU seems to be ignoring the reason,
	 * 	  pass NULL for now.
	 */
	rtas_args->token = RTAS_IBM_OS_TERM;
	rtas_args->nargs = 1;
	rtas_args->nret = 1;
	rtas_args->args[0] = 0ULL;
	rtas_args->rets = 0ULL;

	svm_unpin_rtas_buffers(r_state);

	rc = do_hcall(r_state, H_RTAS, 1, NULL, 1, bb_args_gpa);

	/*
	 * We may have been asked to terminate the SVM for a security
	 * reason. If we failed to terminate, eg: HV doesn't implement
	 * "ibm,os-term", treat as fatal?
	 */
	pr_error("RTAS(ibm,os-term) failed, rc %d, aborting\n", rc);
	abort();
}

/*
 * never call svm_abort() with any locks held .
 * @todo check all locations where svm_abort() is called.
 */
void __noreturn svm_abort(struct refl_state *r_state)
{

	if (!r_state) {
		r_state = get_reflect_state_svm(mfspr(SPR_LPIDR));
		/*
		 * @todo: Use a statically allocated emergency reflect
		 * 	  state and use it if allocation fails?
		 */
		assert(r_state);
	}

	/*
	 * We have a minimally initialized reflect state, so skip
	 * any debug checks. Feels hacky, but we maybe able to
	 * remove the asserts of registers like hdsisr, hdar later.
	 * See todo in fixup_regs_for_hv_entry().
	 */
	r_state->skip_debug_checks = true;

	svm_initiate_kill(r_state, "Aborting SVM");
}

/**
 * Find a specific pseries error log in an RTAS extended event log.
 * @log: RTAS error/event log
 * @section_id: two character section identifier
 *
 * Returns a pointer to the specified errorlog or NULL if not found.
 */
static struct pseries_errorlog *get_pseries_errorlog(struct rtas_error_log *log,
						     uint16_t section_id)
{
	struct rtas_ext_event_log_v6 *ext_log =
		(struct rtas_ext_event_log_v6 *)log->buffer;
	struct pseries_errorlog *sect;
	unsigned char *p, *log_end;
	uint32_t ext_log_length = log->extended_log_length;

	log_end = log->buffer + ext_log_length;
	p = ext_log->vendor_log;

	while (p < log_end) {
		sect = (struct pseries_errorlog *)p;
		if (sect->id == section_id)
			return sect;
		p += sect->length;
	}

	return NULL;
}

/*
 * Validate rtas extended error log and return size of data that is validated
 * and safe to be copied to secure page.
 */
static size_t validate_extended_errorlog(struct rtas_ext_event_log_v6 *ext_log,
					 size_t ext_log_length)
{
	uint8_t log_format = rtas_ext_event_log_format(ext_log);
	uint32_t company_id = ext_log->company_id;

	/* Check that we understand the format */
	if (ext_log_length < sizeof(struct rtas_ext_event_log_v6) ||
	    log_format != RTAS_V6EXT_LOG_FORMAT_EVENT_LOG ||
	    company_id != RTAS_V6EXT_COMPANY_ID_IBM)
		return 0;

	/*
	 * Return the size of extended v6 log structure excluding
	 * rtas_ext_event_log_v6.vendor_log member size which points
	 * into vender log.
	 */
	return sizeof(*ext_log) - sizeof(ext_log->vendor_log);
}

static void svm_update_mce_log(struct pseries_errorlog *pseries_log,
					struct refl_state *r_state)
{
	struct pseries_mc_errorlog *mce_log;
	struct stack_frame *guest_regs;
	u64 ea;

	guest_regs = &r_state->excp_frame;

	/*
	 * Update MCE rtas event with proper effective address where
	 * MCE ocurred.
	 *
	 * For ifetch MCE errors faulting address is in SRR0
	 * For LOAD/STORE errors faulting address is in DAR
	 *
	 * Both the above special purpose registers aren't exposed to
	 * when MCE interrupr was reflected. Hence fill up that info
	 * now just before we go back to SVM guest.
	 */
	mce_log = (struct pseries_mc_errorlog *)pseries_log->data;
	if (SRR1_MC_LOADSTORE(guest_regs->srr1))
		ea = guest_regs->dar;
	else
		ea = guest_regs->srr0;

	rtas_mc_set_effective_addr(mce_log, ea);
}

static void svm_copy_rtas_error_log(struct rtas_error_log *rtas_log_svm,
		struct rtas_error_log *rtas_log_hv, struct refl_state *r_state)
{
	struct rtas_ext_event_log_v6 *ext_log_hv;
	struct rtas_ext_event_log_v6 *ext_log_svm;
	struct pseries_errorlog *pseries_log_hv;
	struct pseries_errorlog *pseries_log_svm;
	size_t len;

	/*
	 * The error log has two parts 1) first 8 bytes conain fixed portion of
	 * the standard error log structure 2) followed by extended error log
	 * details of variable size if any. Validate each part before copying.
	 */
	if (rtas_log_hv->byte0 != RTAS_LOG_VERSION_6) {
		pr_error("%s(): Unsupported error log version: 0x%x\n",
			 __func__, rtas_log_hv->byte0);
		svm_abort(r_state);
		return;
	}

	/* Fixed portion is valid. copy it to svm page */
	memcpy(rtas_log_svm, rtas_log_hv, sizeof(u64));

	/* Nothing much to do if there is no extended error log. */
	if (!rtas_error_extended(rtas_log_hv))
		return;

	/* Validate extended error log */
	ext_log_hv = (struct rtas_ext_event_log_v6 *)rtas_log_hv->buffer;
	len = validate_extended_errorlog(ext_log_hv,
					rtas_log_hv->extended_log_length);
	if (!len) {
		pr_error("%s(): Invalid rtas extended error log\n", __func__);
		svm_abort(r_state);
		return;
	}

	/* Copy validated portion of extended log */
	ext_log_svm = (struct rtas_ext_event_log_v6 *)rtas_log_svm->buffer;
	memcpy(ext_log_svm, ext_log_hv, len);
	rtas_log_svm->extended_log_length = len;

	/* Now extract mce vendor log and copy it. */
	pseries_log_hv = get_pseries_errorlog(rtas_log_hv,
					      PSERIES_ELOG_SECT_ID_MCE);
	if (pseries_log_hv == NULL) {
		pr_error("%s(): Unable to extract MCE pSeries error log\n",
			 __func__);
		svm_abort(r_state);
		return;
	}
	pseries_log_svm = (struct pseries_errorlog *)ext_log_svm->vendor_log;
	memcpy(pseries_log_svm, pseries_log_hv, pseries_log_hv->length);
	rtas_log_svm->extended_log_length += pseries_log_hv->length;

	/* Update the mce event. */
	svm_update_mce_log(pseries_log_svm, r_state);
}

/*
 * QEMU places MCE event in rtas buffer inside rtas area with a minimum
 * size of 16 bytes.
 */
static inline bool valid_rtas_buffer(gpa_t rgpa, struct svm *svm)
{
	return ((rgpa >= svm->rtas.rtas_base + svm->rtas.text_size) &&
		(rgpa < (svm->rtas.rtas_base + svm->rtas.rtas_size - 16)));
}

/*
 * Copy and update error log in rtas area.
 *
 * This is called from uv_return() path while redirecting HV synthesized
 * interrupt to svm guest. Do this only for machine check interrupt and
 * QEMU/svm guest supports FWNMI capability.
 */
void svm_fixup_rtas_area(u64 rtas_area_gpa, struct refl_state *r_state)
{
	struct stack_frame *guest_regs;
	struct rtas_error_log *rtas_log_hv;
	struct rtas_error_log *rtas_log_svm;
	struct svm *svm;
	void *hv_page;
	u64 *rtas_area_hv;
	u64 *rtas_area_svm;

	guest_regs = &r_state->excp_frame;
	svm = r_state->svm;

	/* Return if FWNMI isn't supported by QEMU */
	if (svm->fwnmi_machine_check_addr == 0x200)
		return;

	/* Validate if rtas_area_gpa points inside rtas region */
	if (!valid_rtas_buffer(rtas_area_gpa, svm)) {
		/*
		 * rtas_area_gpa isn't pointing inside rtas region.
		 * This is very unlikely, but we may be racing with another
		 * cpu in nmi-register and this mce reached QEMU before
		 * fwnmi is tunred on in QEMU. Hence just return from here
		 * so that this mce will be delivered to svm guest at
		 * 0x200 vector and guest will crash.
		 */
		return;
	}

	/*
	 * QEMU has saved MCE rtas event in rtas region at rtas_area_gpa.
	 * rtas area has been shared with HV with SHARE_PSUEDO share type.
	 * Hence the MCE event is present in shared normal page and need to
	 * be copied over to secured page for SVM guest to consume.
	 * Get the rtas area HV page (normal page) and copy MCE event data
	 * to SVM rtas area which is mapped to secure page.
	 */
	hv_page = (u64 *)__va(svm_gfn_get_data(svm,
					       SVM_GPA_TO_GFN(rtas_area_gpa)));
	rtas_area_hv = (u64*)(hv_page + (rtas_area_gpa & ~SVM_PAGEMASK));
	rtas_area_svm = gpa_to_addr(&svm->mm, rtas_area_gpa, NULL);

	/*
	 * The first 8 bytes of this area contains the original contents
	 * of R3 and the second 8 bytes contains the fixed portion of the
	 * standard error log structure. Copy the original r3 value to
	 * rtas area.
	 */
	rtas_area_svm[0] = guest_regs->gpr[3];

	/* Copy the MCE event from normal page to secure page */
	rtas_log_hv = (struct rtas_error_log *)&rtas_area_hv[1];
	rtas_log_svm = (struct rtas_error_log *)&rtas_area_svm[1];
	svm_copy_rtas_error_log(rtas_log_svm, rtas_log_hv, r_state);

	/* Set the guest r3 with pointer to rtas mce event */
	guest_regs->gpr[3] = (u64)rtas_area_gpa;
}
