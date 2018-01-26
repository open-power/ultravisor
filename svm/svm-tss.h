/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM TSS Support
 *
 * Copyright 2019, IBM Corporation.
 *
 */

#ifndef SVM_SVM_TSS_H
#define SVM_SVM_TSS_H

#include <uv/uv-common.h>

#include <stdint.h>
#include <unistd.h>

#define TPM_SPAPR_BUFSIZE 4096


/** @todo (andmike) Move to errno.h */
#define EFBIG           27      /* File too large */

struct svm_tss_xfer {
	uint8_t payload[TPM_SPAPR_BUFSIZE];	/**< Payload for tss op. */
	uint8_t response[TPM_SPAPR_BUFSIZE];	/**< Response from previous tss
						  op. */
	u32     rsp_off_t;
	size_t  rsp_len;
};

extern int svm_tss_tpm_close(void *uv_ctx);

extern int svm_tss_tpm_open(void *uv_ctx);

extern ssize_t svm_tss_tpm_read(void *uv_ctx, const uint8_t *buffer,
		uint16_t length);

extern ssize_t svm_tss_tpm_write(void *uv_ctx,
		const uint8_t *buffer, uint16_t length);

#endif /* SVM_SVM_TSS_H */
