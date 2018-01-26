/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM ESM BLOB Support
 *
 * Copyright 2018, IBM Corporation.
 *
 */

#ifndef SVM_SVM_ESMB_H
#define SVM_SVM_ESMB_H

#include <stdint.h>
#include <unistd.h>
#include <svm/svm-internal.h>


extern int svm_esmb_digest_chk(struct refl_state *r_state, hpa_t esmb,
			       gpa_t rtas, size_t rtas_len,
			       gpa_t kbase,
			       char *bootargs, size_t bootargs_len,
			       gpa_t initrd, size_t initrd_len);

extern int svm_esmb_get_files_fdt(struct refl_state *r_state, hpa_t esmb);

#endif /* SVM_SVM_ESMB_H */
