/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM Crypto Support
 *
 * Copyright 2019, IBM Corporation.
 *
 */

#ifndef SVM_SVM_CRYPTO_H
#define SVM_SVM_CRYPTO_H

#include <stdint.h>
#include <unistd.h>
#include <svm/svm-internal.h>

struct refl_state;

extern uint32_t svm_crypto_decrypt_lockbox(struct refl_state *r_state,
				uint16_t *dec_length, uint8_t *dec_buffer,
				uint16_t enc_length, const uint8_t *enc_buffer);

extern uint32_t svm_crypto_gcm_decrypt(
			const unsigned char *key, unsigned int key_len,
			const unsigned char *iv, size_t iv_len,
			const unsigned char *tag, size_t tag_len,
			uint8_t *out_buffer, const uint8_t *buffer,
			size_t length);

extern uint32_t svm_crypto_gcm_encrypt(
			const unsigned char *key, unsigned int key_len,
			const unsigned char *iv, size_t iv_len,
			unsigned char *tag, size_t tag_len,
			uint8_t *out_buffer, const uint8_t *buffer,
			size_t length);

extern uint32_t svm_crypto_sha512_chk(struct refl_state *r_state,
				      gpa_t start_addr, uint32_t len,
				      const uint8_t *sum);

extern uint32_t uv_check_sha512_sum(const uint8_t *data, const uint32_t len,
				    const uint8_t *expected);
#endif /* SVM_SVM_CRYPTO_H */
