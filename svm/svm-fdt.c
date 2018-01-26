// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2018 IBM Corp.
 */

#define pr_fmt(fmt) "SVM-FDT: " fmt

#include <errno.h>
#include <inttypes.h>
#include <libfdt/libfdt.h>
#include <logging.h>
#include <stack.h>
#include <stdio.h>
#include <stdlib.h>
#include <svm/svm-internal.h>
#include <svm/svm-fdt.h>
#include <pagein_track.h>

#undef DEBUG
#ifdef DEBUG
#define svm_fdt_dprintf(fmt...) do { printf(fmt); } while(0)
#else
#define svm_fdt_dprintf(fmt...) do { } while(0)
#endif

#ifdef DEBUG
#define svm_fdt_print_dbg(fdt) do { svm_fdt_print(fdt); } while(0)
#else
#define svm_fdt_print_dbg(fdt) do { } while(0)
#endif

#ifndef ALIGN_UP
#define ALIGN_UP(_v, _a) (((_v) + (_a)-1) & ~((_a)-1))
#endif

static int svm_fdt_copyin(struct svm *svm, void *dest, gpa_t src,
			  size_t length);
static int svm_fdt_rsv_addr_find(struct svm *svm, struct fdt_header *fdt,
					size_t rsv_size, u64 *rsv_addr);

/**
 * @brief Fetch a copy of svm fdt for updating.
 *
 * @param svm containing fdt.
 *
 * @return 0 or FDT_ERR code if check or fixup fails
 */
static int svm_fdt_fetch(struct svm *svm)
{
	struct fdt_header *fdt;
	int fdt_orig_size;
	int rc;
	int ws_size;

	fdt = (struct fdt_header *)gpa_to_addr(&svm->mm, svm->fdt.gpa_fdt, NULL);
	if (!fdt)
		return -FDT_ERR_NOTFOUND;

	fdt_orig_size = fdt_totalsize(fdt);

	ws_size = ALIGN_UP(fdt_orig_size, SVM_PAGESIZE);
	/* Double the size for a copy of original fdt and open_into space */
	ws_size *= 2;

	if (ws_size > UV_PAGE_SIZE) {
		pr_error("%s: ws_size 0x%x > UV_PAGE_SIZE\n", __func__,
			 ws_size);
		rc = -FDT_ERR_NOSPACE;
		goto out;
	}

	svm->fdt.workspace = alloc_reserved_uv_page();
	if (!svm->fdt.workspace) {
		pr_error("%s: alloc_reserved_uv_page failed\n",
			 __func__);
		rc = -FDT_ERR_NOSPACE;
		goto out;
	}

	rc = svm_fdt_copyin(svm, svm->fdt.workspace, svm->fdt.gpa_fdt,
			    fdt_orig_size);
	if (rc) {
		pr_error("%s: svm_fdt_copyin rc [%d]\n", __func__, rc);
		goto err_out;
	}

	svm->fdt.wc_fdt = (void *)((hpa_t)svm->fdt.workspace + (ws_size / 2));

	svm_fdt_dprintf("%s: ws 0x%" PRIx64 " wc 0x%" PRIx64 ", size 0x%x\n",
			__func__,
			(uint64_t)svm->fdt.workspace,
			(uint64_t)svm->fdt.wc_fdt,
			(ws_size / 2));

	rc = fdt_open_into(svm->fdt.workspace, svm->fdt.wc_fdt, (ws_size / 2));

	if (!rc)
		goto out;

	pr_error("%s: open_into rc [%d]\n", __func__, rc);

err_out:
	free_reserved_uv_page(svm->fdt.workspace);
out:
	return rc;
}

static int svm_fdt_copyin(struct svm *svm, void *dest, gpa_t src, size_t length)
{
	int rc = 0;

	while (length) {
		uint32_t chunk;
		void *src_hpa;

		src_hpa = gpa_to_addr(&svm->mm, src, NULL);
		if (!src_hpa) {
			rc = -EFAULT;
			goto out;
		}

		chunk = (SVM_PAGESIZE - (src % SVM_PAGESIZE));

		if (chunk > length)
			chunk = length;

		svm_fdt_dprintf("%s: dest 0x%" PRIx64
				", src_hpa 0x%" PRIx64 " chunk 0x%x\n",
				__func__, (hpa_t)dest,
				(hpa_t)src_hpa, chunk);

		memcpy(dest, src_hpa, chunk);

		dest = (void *)((hpa_t)dest + chunk);
		src += chunk;
		length -= chunk;
	}

out:
	return rc;
}

static int svm_fdt_copyout(struct svm *svm, gpa_t dest, void *src,
			   size_t length)
{
	int rc = 0;

	while (length) {
		uint32_t chunk;
		void *dest_hpa;

		dest_hpa = gpa_to_addr(&svm->mm, dest, NULL);
		if (!dest_hpa) {
			rc = -EFAULT;
			goto out;
		}

		chunk = (SVM_PAGESIZE - (dest % SVM_PAGESIZE));

		if (chunk > length)
			chunk = length;

		svm_fdt_dprintf("%s: dest 0x%" PRIx64
				", src_hpa 0x%" PRIx64 "\n",
				__func__, (hpa_t)dest_hpa,
				(hpa_t)src);
		memcpy(dest_hpa, src, chunk);

		dest += chunk;
		src = (void *)((hpa_t)src + chunk);
		length -= chunk;
	}

out:
	return rc;
}

u32 svm_fdt_get_cell(const struct fdt_property *prop, u32 index)
{
	assert(prop->len >= (index+1)*sizeof(u32));
	/* Always aligned, so this works. */
	return fdt32_to_cpu(((const u32 *)prop->data)[index]);
}

int svm_fdt_prop_get(hpa_t hpa_fdt, const char *n_name, const char *p_name,
		     const struct fdt_property **prop, int *lenp)
{
	int _offset;
	const struct fdt_property *_prop;
	int _prop_len;

	_offset = fdt_path_offset((void *)hpa_fdt, n_name);
	if (_offset < 0) {
		pr_error("%s: path %s rc [%d]\n", __func__, n_name, _offset);
		return _offset;
	}

	_prop = fdt_get_property((void *)hpa_fdt, _offset, p_name, &_prop_len);
	if (!_prop) {
		pr_error("%s: property %s rc [%d]\n",
			 __func__, p_name, _prop_len);
		return _prop_len;
	}

	*prop = _prop;
	*lenp = _prop_len;

	return 0;
}

/**
 * @brief Check if given range overlaps on existing reserved mem ranges
 * and return the adjusted addr that does not overlap on any of the
 * existing reserved mem ranges. The search logic is independant of
 * whether fdt reservation list is sorted or not.
 *
 * Return:
 *  On error: 0 (NULL)
 *  On success: address to the non-reserved memory range.
 */
static u64 svm_overlaps_fdt_rsv_addr(struct fdt_header *fdt,
					size_t size, u64 addr)
{
	int i, rc;

	for (i = fdt_num_mem_rsv(fdt) - 1, rc = 0; i >= 0; i--) {
		u64 raddr, rsize;

		rc = fdt_get_mem_rsv(fdt, i, &raddr, &rsize);

		if (rc) {
			pr_error(" ERR %s\n", fdt_strerror(rc));
			return 0;
		}

		if (((addr + size) > raddr) &&
				(addr < (raddr + rsize))) {
			/*
			 * Overlap found, adjust rsv_addr and reset the i
			 * and start over again.
			 */
			addr = raddr - size;
			i = fdt_num_mem_rsv(fdt);
		}
	}
	return addr;
}

/**
 * @brief find the highest non-reserved address using fdt mem rsv.
 *
 * Return:
 *  On error: -ve value
 *  On success: 0
 */
static int svm_fdt_rsv_addr_find(struct svm *svm, struct fdt_header *fdt,
					size_t rsv_size, u64 *rsv_addr)
{
	int rc = 0;
	u64 _addr;
	u64 svm_rmo_top = svm_get_rmo_top(svm);

	/*
	 * Start with highest address range and check if it overlaps on
	 * any of the already existing fdt reservation entries.
	 * Use smv rmo top as a limit instead of end of SVM RAM and
	 * search downwards for the free memory range.
	 */
	_addr = svm_rmo_top - rsv_size;
	_addr = svm_overlaps_fdt_rsv_addr(fdt, rsv_size, _addr);

	if (!_addr
#ifndef __TEST__
		|| !svm_valid_gfn_range(svm, SVM_GPA_TO_GFN(_addr),
			SVM_BYTES_TO_PAGES(rsv_size))
#endif
						)
		goto error_out;

	*rsv_addr = _addr;
	return rc;

error_out:
	pr_error("Failed to reserve memory. SVM is very low on memory\n");
	return U_PERMISSION;

}

static int svm_fdt_upd(struct refl_state *r_state)
{
	int i, rc;
	struct svm_ops *svm_ops = &__svm_ops_start;

	for (i = 0, rc = 0; &svm_ops[i] < &__svm_ops_end; i++) {
		if (svm_ops[i].fdt_upd_hdlr) {
			svm_fdt_dprintf("Calling %s\n", svm_ops[i].name);
			rc = svm_ops[i].fdt_upd_hdlr(r_state);
			if (rc) {
				svm_fdt_dprintf("%s returned %d\n",
						svm_ops[i].name, rc);
				goto out;
			}
		}
	}

out:
	return rc;
}

static int svm_fdt_get_rmo_top(struct svm *svm)
{
	gpa_t svm_fdt, base, rmo_top;
	const struct fdt_property *prop;
	int prop_len;
	int rc;

	svm_fdt = svm_fdt_get_fdt_hpa(svm);

	rc = svm_fdt_prop_get(svm_fdt, "/memory@0", "reg", &prop, &prop_len);
	if (rc) {
		pr_error("%s: /memory@0/reg prop get rc [%d]\n", __func__, rc);
		rc = -ENOENT;
		goto out;
	}

	/* memory@0/reg prop contains base/size value pair 2 * 2 cell */
	if (prop_len < (2 * sizeof(u64))) {
		pr_error("%s: /memory@0/reg prop size invalid [%d]\n",
			 __func__, prop_len);
		rc = -ENOENT;
		goto out;
	}

	base = ((gpa_t)svm_fdt_get_cell(prop, 0) << 32)
			| svm_fdt_get_cell(prop, 1);

	/*
	 * memory@0 node that refers to the storage starting at real address
	 * zero (“reg” property starting at the value zero) always remains
	 * allocated to an OS and called as RMA (or RMO) region.
	 */
	if (base) {
#ifndef __TEST__	 /* keeps the make svm-check test happy */
		pr_error("%s: /memory@0/reg non-zero real address [%llx]\n",
			 __func__, base);
#endif
		rc = -ENOENT;
		goto out;
	}

	rmo_top = ((gpa_t)svm_fdt_get_cell(prop, 2) << 32)
			| svm_fdt_get_cell(prop, 3);

	/*
	 * Cap RMO at 768MB
	 * (See comment in arch/powerpc/kernel/prom_init.c:1700)
	 */
	rmo_top = min((gpa_t)(768 * MB), rmo_top);
	svm_set_rmo_top(svm, rmo_top);
out:
	return rc;
}

int svm_fdt_init(struct refl_state *r_state, gpa_t gpfdt)
{
	int rc, remaining;
	hpa_t hpa_fdt;
	struct fdt_header *fdt;
	struct svm *svm = r_state->svm;

	svm->fdt.gpa_fdt = gpfdt;

	hpa_fdt = (hpa_t)get_page_range(r_state, gpfdt, SVM_PAGESIZE);
	if (!hpa_fdt) {
		return U_PARAMETER;
	}

	fdt = (struct fdt_header *) hpa_fdt;

	/*
	 * Check fdt header before fdt header order so we do not
	 * try and fix a invalid tree.
	 */
	rc = fdt_check_header(fdt);
	if (rc) {
		return U_PARAMETER;
	}

	remaining = fdt_totalsize(fdt) - SVM_PAGESIZE;
	/* Copy in the rest of the device tree */
	if ((remaining > 0) &&
		!get_page_range(r_state, (gpfdt + SVM_PAGESIZE), remaining)) {
		 return U_PARAMETER;
	}

	svm_fdt_dprintf("=== fdt before chk_order ===\n");
	svm_fdt_print_dbg(hpa_fdt);

	rc = svm_fdt_fetch(svm);
	if (rc) {
		return U_PARAMETER;
	}

	/*
	 * @todo: Sanitize the FDT before using it or letting the SVM use it.
	 *
	 * The device tree that is passed to the SVM via the ESM ultravisor call
	 * is generated by QEMU, which is an untrusted component. Because of
	 * this, the Ultravisor needs to prune it to ensure it is consistent and
	 * doesn't contain malicious contents before passing it on to the SVM.
	 * This could be done using by creating new "SVM ops" with
	 * fdt_updt_hdlr() operations (see the svm_fdt_upd() function).
	 *
	 * One example is PCI devices. Since they aren't allowed in SVMs, their
	 * device trees should be modified to remove references to any PCI
	 * device. This would prevent the guest kernel from probing them.
	 */

	/* Fetch the svm rmo top value and store in svm structure. */
	rc = svm_fdt_get_rmo_top(svm);
	if (rc) {
		return U_PARAMETER;
	}

	hpa_fdt = svm_fdt_get_fdt_hpa(svm);

	svm_fdt_dprintf("=== fdt after chk_order ===\n");
	svm_fdt_print_dbg(hpa_fdt);

	rc = svm_fdt_upd(r_state);
	if (rc) {
		return U_PARAMETER;
	}

	svm_fdt_dprintf("=== fdt after upd ===\n");
	svm_fdt_print_dbg(hpa_fdt);

	return 0;
}

int svm_fdt_mem_rsv(struct svm *svm, hpa_t hpa_fdt,
		    size_t rsv_size, gpa_t *rsv_gpa)
{
	int rc;
	u64 _addr;
	struct fdt_header *fdt;

	fdt = (struct fdt_header *) hpa_fdt;

	rc = svm_fdt_rsv_addr_find(svm, fdt, rsv_size, &_addr);
	if (rc) {
		pr_error(" ERR %s\n", fdt_strerror(rc));
		goto out;
	}

	svm_fdt_dprintf("=== fdt before add_mem_rsv ===\n");
	svm_fdt_print_dbg(hpa_fdt);

	_addr = ALIGN_UP(_addr, SVM_PAGESIZE);
	svm_fdt_dprintf("Selected address 0x%" PRIx64 " and size 0x%lx\n",
			_addr, rsv_size);

	rc = fdt_add_mem_rsv(fdt, _addr, rsv_size);
	if (rc) {
		pr_error(" ERR %s\n", fdt_strerror(rc));
		goto out;
	}

	*rsv_gpa = (gpa_t) _addr;

	svm_fdt_dprintf("=== fdt after add_mem_rsv ===\n");
	svm_fdt_print_dbg(hpa_fdt);

out:
	return rc;
}

void svm_fdt_print(hpa_t hpfdt)
{
	int i, rc;
	struct fdt_header *fdt;

	fdt = (struct fdt_header *) hpfdt;

	printf("magic 0x%x\n", fdt_magic(fdt));
	printf("totalsize 0x%x\n", fdt_totalsize(fdt));
	printf("off_dt_struct 0x%x\n", fdt_off_dt_struct(fdt));
	printf("off_dt_strings 0x%x\n", fdt_off_dt_strings(fdt));
	printf("off_mem_rsvmap 0x%x\n", fdt_off_mem_rsvmap(fdt));
	printf("version 0x%x\n", fdt_version(fdt));
	printf("last_comp_version 0x%x\n", fdt_last_comp_version(fdt));
	printf("boot_cpuid_phys 0x%x\n", fdt_boot_cpuid_phys(fdt));
	printf("size_dt_strings 0x%x\n", fdt_size_dt_strings(fdt));
	printf("size_dt_struct 0x%x\n", fdt_size_dt_struct(fdt));

	for (i = 0; i < fdt_num_mem_rsv(fdt); i++) {
		u64 addr, size;

		rc = fdt_get_mem_rsv(fdt, i, &addr, &size);
		if (rc) {
			pr_error(" ERR %s\n", fdt_strerror(rc));
			return;
		}
		printf("  mem_rsv[%i] = %lx@%#lx\n",
				i, (long)addr, (long)size);
	}

	if (fdt_off_mem_rsvmap(fdt) < ALIGN_UP(sizeof(struct fdt_header), 8)) {
		printf("rsvmap not aligned\n");
	}

	if (fdt_off_dt_struct(fdt) <
			(fdt_off_mem_rsvmap(fdt) +
			 sizeof(struct fdt_reserve_entry))) {
		printf("dt_struct before rsvmap\n");
	}

	if (fdt_off_dt_strings(fdt) < (fdt_off_dt_struct(fdt) +
				fdt_size_dt_struct(fdt))) {
		printf("dt_strings before dt_struct\n");
	}

	if (fdt_totalsize(fdt) <
			(fdt_off_dt_strings(fdt) + fdt_size_dt_strings(fdt))) {
		printf("totalsize < size of dt_strings\n");
	}
}

int svm_fdt_prop_gpa_get(hpa_t hpa_fdt, const char *n_name,
		const char *p_name, gpa_t *prop_gpa)
{
	int rc;
	const struct fdt_property *_prop;
	int _prop_len;

	rc = svm_fdt_prop_get(hpa_fdt, n_name, p_name, &_prop, &_prop_len);
	if (rc) {
		return rc;
	}

	if (_prop_len >= sizeof(u64)) {
		*prop_gpa = ((gpa_t)svm_fdt_get_cell(_prop, 0) << 32)
				| svm_fdt_get_cell(_prop, 1);
	} else {
		*prop_gpa = (gpa_t)svm_fdt_get_cell(_prop, 0);
	}

	return 0;
}

int svm_fdt_prop_u32_get(hpa_t hpa_fdt, const char *n_name,
		const char *p_name, uint32_t *prop_cell)
{
	int rc;
	const struct fdt_property *_prop;
	int _prop_len;

	rc = svm_fdt_prop_get(hpa_fdt, n_name, p_name, &_prop, &_prop_len);
	if (rc) {
		return rc;
	}

	*prop_cell = svm_fdt_get_cell(_prop, 0);

	return 0;
}

int svm_fdt_finalize(struct refl_state *r_state, int ret_code)
{
	int rc = 0;
	struct svm *svm = r_state->svm;
	int fdt_packed_size;

	if (!svm->fdt.wc_fdt)
		return U_SUCCESS;

	if (ret_code)
		goto out;

	rc = fdt_pack(svm->fdt.wc_fdt);
	if (rc) {
		rc = U_RETRY;
		goto out;
	}

	fdt_packed_size = fdt_totalsize(svm->fdt.wc_fdt);
	svm_fdt_dprintf("%s: fdt_packed_size: 0x%x\n", __func__,
			fdt_packed_size);

	rc = svm_fdt_copyout(svm, svm->fdt.gpa_fdt, svm->fdt.wc_fdt,
			     fdt_packed_size);
	if (rc)
		rc = U_RETRY;

out:
	free_reserved_uv_page(svm->fdt.workspace);

	svm->fdt.gpa_fdt = 0;
	svm->fdt.wc_fdt = NULL;

	return rc;
}
