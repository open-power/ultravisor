// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 IBM Corp.
 */

#define pr_fmt(fmt) "SVM-CRYPTO: " fmt

#include <stdio.h>
#include <logging.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <svm/svm-internal.h>
#include <svm/svm-crypto.h>
#include <pgtable.h>
#include <hvcall.h>
#include <uvcall.h>
#include <errno.h>
#include <exceptions.h>
#include <uv/tssuv.h>
#include <mbedtls/gcm.h>
#include <mbedtls/sha512.h>
#include <uv/uv-crypto.h>

#undef DEBUG
#ifdef DEBUG
#define svm_crypto_dprintf(fmt...) do { printf(fmt); } while(0)

static void dprintf_buf(const uint8_t *buf, uint8_t length)
{
	uint8_t i;
	uint8_t pr_buf[64];
	uint8_t *b = pr_buf, *eb = &pr_buf[64];

	for (i = 0 ; i < length ; i++) {
		b += snprintf(b, eb-b, "%.2x ", buf[i]);
		if (!((i+1) % 16)) {
			printf("%s\n", pr_buf);
			b = pr_buf;
		}
	}

	if (b != pr_buf) {
		printf("%s\n", pr_buf);
	}
}
#else
#define svm_crypto_dprintf(fmt...) do { } while(0)

static void dprintf_buf(const uint8_t *buf __unused, uint8_t length __unused)
{
}
#endif

uint32_t svm_crypto_decrypt_lockbox(struct refl_state *r_state,
				    uint16_t *dec_length, uint8_t *dec_buffer,
				    uint16_t enc_length, const uint8_t *enc_buffer)
{
	int rc;
	uint32_t wrap_key_handle;
	const void *key_pass_prop, *key_pub_prop;
	int key_pass_prop_len, key_pub_prop_len;
	const void *key_pol_a_prop, *key_pol_b_prop;
	int key_pol_a_prop_len, key_pol_b_prop_len;

	rc = uv_crypt_wrap_key_u32_get("wrapping-key-handle",
				       &wrap_key_handle);
	if (rc)
		return rc;

	key_pass_prop = uv_crypt_wrap_key_getprop("wrapping-key-passwd",
						  &key_pass_prop_len);
	if (!key_pass_prop)
		return key_pass_prop_len;

	key_pub_prop = uv_crypt_wrap_key_getprop("wrapping-key-publicname",
						 &key_pub_prop_len);
	if (!key_pub_prop)
		return key_pub_prop_len;

	key_pol_a_prop = uv_crypt_wrap_key_getprop("wrapping-key-policy-a",
						   &key_pol_a_prop_len);
	if (!key_pol_a_prop)
		return key_pol_a_prop_len;

	key_pol_b_prop = uv_crypt_wrap_key_getprop("wrapping-key-policy-b",
						   &key_pol_b_prop_len);
	if (!key_pol_b_prop)
		return key_pol_b_prop_len;

	rc = UV_TSS_Decrypt((void *)r_state, key_pass_prop, dec_length,
			    dec_buffer, enc_length, enc_buffer,
			    wrap_key_handle,
			    key_pub_prop_len, key_pub_prop, key_pol_a_prop_len,
			    key_pol_a_prop, key_pol_b_prop_len, key_pol_b_prop);
	if (rc) {
		pr_error("%s: UV_TSS_Decrypt rc [%d]\n", __func__, rc);
		return rc;
	}

	svm_crypto_dprintf("%s: uv decrypt ret buf len %hu\n", __func__,
			   *dec_length);
	dprintf_buf(dec_buffer, 8);

	return rc;
}

uint32_t svm_crypto_gcm_decrypt(const unsigned char *key, unsigned int key_len,
				const unsigned char *iv, size_t iv_len,
				const unsigned char *tag, size_t tag_len,
				uint8_t *out_buffer, const uint8_t *buffer,
				size_t length)
{
	int rc;
	unsigned int keybits;
	mbedtls_gcm_context ctx;
	mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

	mbedtls_gcm_init(&ctx);

	/* setkey wants key length in bits */
	keybits = key_len*8;
	rc = mbedtls_gcm_setkey(&ctx, cipher, key, keybits);
	if (rc) {
		pr_error("%s: mbedtls_gcm_setkey rc [%d]\n", __func__, rc);
		return rc;
	}

	rc = mbedtls_gcm_auth_decrypt(&ctx, length,
				      iv, iv_len, 0, 0,
				      tag, tag_len,
				      buffer, out_buffer);

	mbedtls_gcm_free(&ctx);

	svm_crypto_dprintf("%s: gcm decrypt \n", __func__);
	dprintf_buf(out_buffer, 8);

	return rc;
}

uint32_t svm_crypto_gcm_encrypt(const unsigned char *key,
				unsigned int key_len,
				const unsigned char *iv, size_t iv_len,
				unsigned char *tag, size_t tag_len,
				uint8_t *out_buffer, const uint8_t *buffer,
				size_t length)
{
	int rc;
	unsigned int keybits;
	mbedtls_gcm_context ctx;
	mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

	mbedtls_gcm_init(&ctx);

	/* setkey wants key length in bits */
	keybits = key_len*8;
	rc = mbedtls_gcm_setkey(&ctx, cipher, key, keybits);
	if (rc) {
		pr_error("%s: mbedtls_gcm_setkey rc [%d]\n", __func__, rc);
		return rc;
	}

	rc = mbedtls_gcm_crypt_and_tag(&ctx,
				       MBEDTLS_GCM_ENCRYPT,
				       length,
				       iv, iv_len,
				       NULL, 0,
				       buffer, out_buffer,
				       tag_len, tag);

	if (rc)
		pr_error("%s: mbedtls_gcm_crypt_and_tag rc [0x%x]\n",
			 __func__, rc);

	mbedtls_gcm_free(&ctx);

	svm_crypto_dprintf("%s: gcm encrypt \n", __func__);
	dprintf_buf(out_buffer, 8);

	return rc;
}

/**
 * Compute the SHA512 sum of @data which is of size @len bytes and compare
 * the sum with @expected. Return 0 if they match and non-zero otherwise
 * (including on errors).
 */
uint32_t uv_check_sha512_sum(const uint8_t *data, const uint32_t len,
			     const uint8_t *expected)
{
	int rc;
	uint8_t actual[64];
	mbedtls_sha512_context ctx;

	mbedtls_sha512_init(&ctx);

	mbedtls_sha512_starts_ret(&ctx, 0);

	mbedtls_sha512_update_ret(&ctx, data, len);

	rc = mbedtls_sha512_finish_ret(&ctx, actual);
	if (rc) {
		pr_error("%s: mbedtls_sha512_finish_ret rc [%d]\n",
			 __func__, rc);
		goto out;
	}

	svm_crypto_dprintf("%s: Actual sha512sum\n", __func__);
	dprintf_buf(actual, 8);

	rc = memcmp(expected, actual, 64);

out:
	mbedtls_sha512_free(&ctx);
	return rc;
}

uint32_t svm_crypto_sha512_chk(struct refl_state *r_state, gpa_t start_addr,
			       uint32_t len, const uint8_t *sum)
{
	int rc;
	uint8_t *buf;
	uint32_t chunk;
	uint8_t sha512sum[64];
	mbedtls_sha512_context ctx;

	assert(sum);

	mbedtls_sha512_init(&ctx);

	mbedtls_sha512_starts_ret(&ctx, 0);

	while (len) {
		buf = (uint8_t *) gpa_to_addr(&r_state->svm->mm,
					      start_addr, NULL);
		chunk = (SVM_PAGESIZE - (start_addr%SVM_PAGESIZE));
		if (chunk > len) {
			chunk = len;
		}

		rc = mbedtls_sha512_update_ret(&ctx, buf, chunk);
		if (rc) {
			pr_error("%s: mbedtls_sha512_update_ret rc [%d]\n",
				 __func__, rc);
			goto out;
		}

		start_addr += chunk;
		len -= chunk;
	}

	rc = mbedtls_sha512_finish_ret(&ctx, sha512sum);
	if (rc) {
		pr_error("%s: mbedtls_sha512_finish_ret rc [%d]\n",
			 __func__, rc);
		goto out;
	}

	svm_crypto_dprintf("%s: sha512sum\n", __func__);
	dprintf_buf(sha512sum, 8);

	rc = memcmp(sha512sum, sum, 64);
out:
	mbedtls_sha512_free(&ctx);
	return rc;
}
