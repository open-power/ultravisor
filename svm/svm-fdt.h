/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM FDT
 *
 * Copyright 2018, IBM Corporation.
 *
 */

#ifndef SVM_SVM_FDT_H
#define SVM_SVM_FDT_H

#include <svm_host.h>
#include <libfdt/libfdt.h>

extern int svm_fdt_init(struct refl_state *r_state, gpa_t gpfdt);

extern int svm_fdt_finalize(struct refl_state *r_state, int ret_code);

extern int svm_fdt_prop_get(hpa_t hpa_fdt, const char *n_name,
			    const char *p_name,
			    const struct fdt_property **prop, int *lenp);

extern u32 svm_fdt_get_cell(const struct fdt_property *prop, u32 index);

extern int svm_fdt_prop_u32_get(hpa_t hpa_fdt, const char *n_name,
                  const char *p_name, uint32_t *prop_cell);

extern int svm_fdt_prop_gpa_get(hpa_t hpa_fdt, const char *n_name,
		const char *p_name, gpa_t *prop_gpa);

extern int svm_fdt_mem_rsv(struct svm *svm, hpa_t hpa_fdt, size_t rsv_size,
		gpa_t *rsv_gpa);

extern void svm_fdt_print(hpa_t hpa_fdt);

/**
 * @brief Get guest physical address of a SVM FDT.
 *
 * @param svm.
 */
static inline gpa_t svm_fdt_get_fdt_gpa(const struct svm *svm)
{
	assert(svm->fdt.gpa_fdt);
        return svm->fdt.gpa_fdt;
}

/**
 * @brief Get host physical address of a SVM FDT.
 *
 * @param r_state reflection state.
 */
static inline hpa_t svm_fdt_get_fdt_hpa(struct svm *svm)
{
	return (hpa_t)svm->fdt.wc_fdt;
}

#endif /* SVM_SVM_FDT_H */
