// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 IBM Corp.
 */

#undef DEBUG
#define pr_fmt(fmt) "SVM-TSS: " fmt

#include <stdio.h>
#include <logging.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <svm/svm-internal.h>
#include <svm/svm-tss.h>
#include <pgtable.h>
#include <hvcall.h>
#include <uvcall.h>
#include <errno.h>
#include <exceptions.h>

#undef DEBUG
#ifdef DEBUG
#define svm_tss_dprintf(fmt...) do { printf(fmt); } while(0)
#else
#define svm_tss_dprintf(fmt...) do { } while(0)
#endif

/** @todo (andmike) Move defines to hcall file when finalized */
#define H_TPM_COMM_OP_EXECUTE 1
#define H_TPM_COMM_OP_CLOSE 2

static inline struct svm_tss *svm_tss_get(struct refl_state *r_state);
static inline struct svm_tss_xfer *svm_tss_xfer_get(void *uv_ctx);

static inline void svm_tss_bbuf_clear(void *uv_ctx)
{
	struct refl_state *r_state;
	struct svm_tss *tss;
	hpa_t bb_hpa;

	r_state = (struct refl_state *)uv_ctx;
	tss = svm_tss_get(r_state);

	bb_hpa = NO_RMOR(gpa_to_addr(&r_state->svm->mm, tss->bbuf, NULL));
	memset((void *)bb_hpa, 0, TPM_SPAPR_BUFSIZE);
}

static inline hpa_t svm_tss_bbuf_get_gpa(void *uv_ctx)
{
	struct refl_state *r_state;
	struct svm_tss *tss;

	r_state = (struct refl_state *)uv_ctx;
	tss = svm_tss_get(r_state);

	return tss->bbuf;
}

static inline hpa_t svm_tss_bbuf_get_hpa(void *uv_ctx)
{
	struct refl_state *r_state;
	struct svm_tss *tss;
	hpa_t bb_hpa;

	r_state = (struct refl_state *)uv_ctx;
	tss = svm_tss_get(r_state);

	bb_hpa = NO_RMOR(gpa_to_addr(&r_state->svm->mm, tss->bbuf, NULL));

	return bb_hpa;
}

static inline void svm_tss_bbuf_set(void *uv_ctx, const uint8_t *buffer,
		uint16_t length)
{
	hpa_t bb_hpa;

	bb_hpa = svm_tss_bbuf_get_hpa(uv_ctx);

	memcpy((void *)bb_hpa, (void *)buffer, length);
	svm_tss_dprintf("%s: bb_hpa 0x%016" PRIx64 "\n", __func__, bb_hpa);

}

static inline struct svm_tss *svm_tss_get(struct refl_state *r_state)
{
	assert(r_state->svm);

	return &r_state->svm->tss;
}

static inline void svm_tss_resp_clear(void *uv_ctx)
{
	struct svm_tss_xfer *xfer;

	xfer = svm_tss_xfer_get(uv_ctx);

	memset((void *)xfer->response, 0, TPM_SPAPR_BUFSIZE);
	xfer->rsp_off_t = 0;
	xfer->rsp_len = 0;
}

static inline void svm_tss_resp_set(void *uv_ctx, uint8_t *buf, size_t rsp_len)
{
	struct svm_tss_xfer *xfer;

	xfer = svm_tss_xfer_get(uv_ctx);

	assert(rsp_len <= sizeof(xfer->response));

	memcpy((void *)xfer->response, buf, rsp_len);
	xfer->rsp_off_t = 0;
	xfer->rsp_len = rsp_len;
}

static inline int32_t svm_tss_to_errno(int64_t hcall_err)
{
	int32_t err = -EIO;

	switch(hcall_err) {
		case H_FUNCTION:
			err = -EINVAL;
			break;
		case H_PARAMETER:
			err = -EFBIG;
			break;
		case H_NOT_AVAILABLE:
			err = -ENODEV;
			break;
		case H_RESOURCE:
			err = -EIO;
			break;
		default:
			pr_error("%s: Unexpected Hcall err code %lld\n",
				 __func__, hcall_err);
	}

	return err;
}

#define GPA_NOT_PRESENT	0
#define GPA_PRESENT	1

/* macros that operate on the rtas_buf_present */
#define TSS_BUF_GPA 0

static inline bool tss_is_gpa_present(struct svm *svm, gpa_t gpa)
{
	(void)gpa;
	return (svm->tss.tss_buf_present & 0x1);
}
#define tss_set_gpa_present(tss, gpa) (tss.tss_buf_present |= 0x1)
#define tss_set_gpa_not_present(tss, gpa) (tss.tss_buf_present &= ~0x1)

static inline void __svm_tss_pre_setup(struct svm *svm, gpa_t gpa)
{
	if (gpa != svm->tss.bbuf)
		return;

	lock(&svm->tss.tss_gpa_lock);
}

static void __svm_tss_change_gpa_state(struct svm *svm, gpa_t gpa, int flag)
{
	if (gpa != svm->tss.bbuf)
		return;

	if (flag)
		tss_set_gpa_present(svm->tss, gpa);
	else
		tss_set_gpa_not_present(svm->tss, gpa);
	unlock(&svm->tss.tss_gpa_lock);
}

void svm_tss_pre_invalidate(struct svm *svm, gpa_t gpa)
{
	__svm_tss_pre_setup(svm, gpa);
}

void svm_tss_post_invalidate(struct svm *svm, gpa_t gpa)
{
	__svm_tss_change_gpa_state(svm, gpa, GPA_NOT_PRESENT);
}

void svm_tss_pre_shared_pagein(struct svm *svm, gpa_t gpa)
{
	__svm_tss_pre_setup(svm, gpa);
}

void svm_tss_post_shared_pagein(struct svm *svm, gpa_t gpa)
{
	__svm_tss_change_gpa_state(svm, gpa, GPA_PRESENT);
}

static void svm_pin_tss_buffer(struct refl_state *r_state)
{
	struct svm *svm = r_state->svm;

	lock(&svm->tss.tss_gpa_lock);
	svm_pin_pages(r_state, svm->tss.bbuf, 1,
			&svm->tss.tss_gpa_lock, tss_is_gpa_present);
}

/*
 * svm_unpin_tss_buffers() -- unblock invalidation of pages
 * 			associated with all RTAS GPAs.
 */
static void svm_unpin_tss_buffer(struct refl_state *r_state)
{
	struct svm *svm = r_state->svm;

	unlock(&svm->tss.tss_gpa_lock);
}

static inline int svm_tss_tpm_comm_close(void *uv_ctx)
{
	int rc;
	struct refl_state *r_state;

	r_state = (struct refl_state *)uv_ctx;

	rc = do_hcall(r_state, H_SVM_TPM_COMM, 1, NULL, 0,
				H_TPM_COMM_OP_CLOSE);

	if (rc != H_SUCCESS) {
		rc = svm_tss_to_errno(rc);
		svm_tss_dprintf("%s: H_SVM_TPM_COMM rc [%d]\n", __func__, rc);
	}

	return rc;
}

static inline ssize_t svm_tss_tpm_comm_write(void *uv_ctx, uint16_t length)
{
	int rc;
	uint64_t ret_buf[1];
	gpa_t bb_gpa;
	hpa_t bb_hpa;
	struct refl_state *r_state;

	r_state = (struct refl_state *)uv_ctx;

	bb_gpa = svm_tss_bbuf_get_gpa(uv_ctx);

	rc = do_hcall(r_state, H_SVM_TPM_COMM, 5, ret_buf, 1,
			H_TPM_COMM_OP_EXECUTE, bb_gpa, length,
			bb_gpa, TPM_SPAPR_BUFSIZE);
	if (rc != H_SUCCESS) {
		rc = svm_tss_to_errno(rc);
	        svm_tss_dprintf("%s: H_SVM_TPM_COMM rc [%d]\n", __func__, rc);
		goto out;
	}

	svm_tss_dprintf("%s: ret_buf %" PRIx64 "\n", __func__, ret_buf[0]);
	bb_hpa = svm_tss_bbuf_get_hpa(uv_ctx);
	svm_tss_resp_set(uv_ctx, (uint8_t *)bb_hpa, (size_t)ret_buf[0]);

out:
	return rc;
}

static inline struct svm_tss_xfer *svm_tss_xfer_get(void *uv_ctx)
{
	struct refl_state *r_state;
	struct svm_tss *tss;
	struct svm_tss_xfer *xfer;

	r_state = (struct refl_state *)uv_ctx;
	tss = svm_tss_get(r_state);
	xfer = (struct svm_tss_xfer *)gpa_to_addr(&r_state->svm->mm,
			tss->xfer, NULL);

	return xfer;
}

int svm_tss_tpm_close(void *uv_ctx)
{
	int rc;

	rc = svm_tss_tpm_comm_close(uv_ctx);

	svm_pin_tss_buffer((struct refl_state *)uv_ctx);
	svm_tss_bbuf_clear(uv_ctx);
	svm_tss_resp_clear(uv_ctx);
	svm_unpin_tss_buffer((struct refl_state *)uv_ctx);

	svm_tss_dprintf("%s: tpm_comm, op: close, rc [%d]\n", __func__, rc);

	return rc;
}

int svm_tss_tpm_open(void *uv_ctx)
{
	svm_pin_tss_buffer((struct refl_state *)uv_ctx);
	svm_tss_resp_clear(uv_ctx);
	svm_unpin_tss_buffer((struct refl_state *)uv_ctx);
	return 0;
}

ssize_t svm_tss_tpm_read(void *uv_ctx, const uint8_t *buffer,
	uint16_t length)
{
	int rc = -EBADF;
	ssize_t copy_len;
	uint8_t *resp;
	struct svm_tss_xfer *xfer;

	svm_pin_tss_buffer((struct refl_state *)uv_ctx);
	xfer = svm_tss_xfer_get(uv_ctx);

	if (!xfer->rsp_len) {
		copy_len = rc;
		goto out;
	}

	copy_len = xfer->rsp_len - xfer->rsp_off_t;

	if (copy_len > length) {
		copy_len = length;
	}

	resp = (uint8_t *)(xfer->response + xfer->rsp_off_t);

	svm_tss_dprintf("%s: resp hpa_t 0x%016" PRIx64 "\n", __func__,
			(hpa_t)resp);

	memcpy((void *)buffer, (void*)resp, copy_len);

	xfer->rsp_off_t += copy_len;

	svm_tss_dprintf("%s: copy_len %ld\n", __func__, copy_len);

out:
	svm_unpin_tss_buffer((struct refl_state *)uv_ctx);
	return copy_len;
}

ssize_t svm_tss_tpm_write(void *uv_ctx, const uint8_t *buffer,
	uint16_t length)
{
	ssize_t rc;

	svm_pin_tss_buffer((struct refl_state *)uv_ctx);
	svm_tss_resp_clear(uv_ctx);

	if (length > TPM_SPAPR_BUFSIZE) {
		rc = -EFBIG;
		goto out;
	}

	svm_tss_bbuf_set(uv_ctx, buffer, length);

	svm_unpin_tss_buffer((struct refl_state *)uv_ctx);
	rc = svm_tss_tpm_comm_write(uv_ctx, length);
	svm_pin_tss_buffer((struct refl_state *)uv_ctx);
	svm_tss_dprintf("%s: tpm_comm_write %ld\n", __func__, rc);

	svm_tss_bbuf_clear(uv_ctx);

out:
	svm_unpin_tss_buffer((struct refl_state *)uv_ctx);
	return rc;
}

static int64_t svm_tss_fdt_upd_hdlr(struct refl_state *r_state)
{
	int rc;
	gpa_t g_addr;
#ifdef DEBUG
	hpa_t g_tss_hpa;
#endif
	hpa_t svm_fdt;
	struct svm *svm = r_state->svm;

	svm_fdt = svm_fdt_get_fdt_hpa(svm);
	if (!svm_fdt) {
		return U_PARAMETER;
	}

	/*
	 * Reserve two pages. One for bounce buffer and the other for decrypted
	 * buffer.
	 */
	rc = svm_fdt_mem_rsv(svm, svm_fdt, 2*SVM_PAGESIZE, &g_addr);
	if (rc) {
		pr_error("%s: svm_fdt_mem_rsv [%d]\n", __func__, rc);
		return rc;
	}

	init_lock(&svm->tss.tss_gpa_lock);
	tss_set_gpa_not_present(svm->tss, g_addr);

	/* Share only bounce buffer with HV */
	svm->tss.bbuf = g_addr;
	page_share_with_hv(r_state, svm->tss.bbuf, 1, SHARE_IMPLICIT);

#ifdef DEBUG
	g_tss_hpa = NO_RMOR(gpa_to_addr(&svm->mm, svm->tss.bbuf, NULL));
	svm_tss_dprintf("%s: tss_bbuf gpa 0x%llx, hpa 0x%llx\n", __func__,
			(u64) svm->tss.bbuf, (u64) g_tss_hpa);
#endif

	assert(sizeof(struct svm_tss_xfer) < SVM_PAGESIZE);
	svm->tss.xfer = (g_addr + SVM_PAGESIZE);

#ifdef DEBUG
	g_tss_hpa = (hpa_t)gpa_to_addr(&svm->mm, svm->tss.xfer, NULL);
	svm_tss_dprintf("%s: svm_tss_xfer gpa 0x%llx, hpa 0x%llx\n", __func__,
			(u64) svm->tss.xfer, (u64) g_tss_hpa);
#endif

	return 0;
}

DECLARE_SVM_OPS(svm_tss) = {
	.name = "svm_tss",
	.fdt_upd_hdlr = svm_tss_fdt_upd_hdlr,
};
