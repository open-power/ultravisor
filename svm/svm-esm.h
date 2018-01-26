/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM ESM Support
 *
 * Copyright 2018, IBM Corporation.
 *
 */

#ifndef SVM_SVM_ESM_H
#define SVM_SVM_ESM_H

#include <svm/svm-internal.h>

extern int svm_esm_blob_chk(struct refl_state *r_state, gpa_t kbase);
extern struct svm_ops __svm_ops_end;
#ifdef ESM_BLOB_CHK_WARN_ONLY
extern int svm_populate_kernel(struct refl_state *r_state, u64 kbase);
#endif

#endif /* SVM_SVM_ESM_H */
