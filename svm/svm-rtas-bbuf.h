/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM RTAS Bounce Buffers
 *
 * Copyright 2019, IBM Corporation.
 *
 */

#ifndef SVM_RTAS_BBUF_H
#define SVM_RTAS_BBUF_H

#include <svm_host.h>
#include <compiler.h>

#define RTAS_BUF_BBUF_SZ 4096

/**
 * @brief Maximum number of concurrent rtas bounce buffers for this svm. We
 * should normally see single locked rtas calls per SVM. There are cases of
 * unlocked rtas calls.  This count should allow multiple locked and unlocked
 * rtas calls. Use MAX_BBUF_CNT to limit the size of allocations and detect
 * change in assumptions on buffer usage.
 */
#define MAX_BBUF_CNT (4 * SVM_PAGESIZE / RTAS_BUF_BBUF_SZ)
#define WARN_BBUF_USE_CNT (MAX_BBUF_CNT / 2)

/**
 * @brief Alloc a bounce buffer of size RTAS_BUF_BBUF_SZ from the
 * pool of rtas bounce buffers allocated for this svm.
 *
 * @param mm a memory context.
 *
 * @return Non-zero gpa_t on success, else 0.
 */
gpa_t svm_rtas_bbuf_alloc(struct mm_struct *mm, struct svm_rtas *rtas);

/**
 * @brief Free a allocated bounce buffer back to the
 * pool of rtas bounce buffers allocated for this svm.
 *
 * @param rtas a descriptor of rtas reflection.
 * @param Gpa of bounce buffer.
 *
 */
void svm_rtas_bbuf_free(struct svm_rtas *rtas, gpa_t bbuf_addr);

/**
 * @brief Copy contents between gpa buffers.
 *
 * @param mm a memory context.
 * @param dest gpa to copy to.
 * @param src gpa to copy from.
 * @param length Length of copy.
 *
 * Returns the number of copied bytes.
 *
 */
size_t svm_rtas_bbuf_memcpy(struct mm_struct *mm, gpa_t dest, gpa_t src,
			    size_t length);

/**
 * @brief Initialize the gpa buffer subsystem
 *
 * @param rtas a descriptor of rtas reflection.
 *
 */
void svm_rtas_bbuf_init(struct svm_rtas *rtas);
#endif /* SVM_RTAS_BBUF_H */
