// SPDX-License-Identifier: GPL-2.0
/*
 * PAGE ENCRYPT
 *
 * Copyright 2019 IBM Corp.
 *
 */

#define pr_fmt(fmt) "SVM: " fmt

#include <ccan/str/str.h>
#include <ccan/intmap/intmap.h>
#include <ccan/build_assert/build_assert.h>
#include <svm/svm-crypto.h>
#include <page_encrypt.h>
#include <uv/uv-crypto.h>

#define UINT64_MAX	(~(uint64_t)0)

int page_decrypt(void *dest, void *source,
		u64 page_size, struct encrypt_struct *enc_dec)
{
	int rc;

#ifdef DISABLE_ENCRYPT
	memcpy(dest, source, page_size);
	rc = 0;
#else
	rc = svm_crypto_gcm_decrypt(*enc_dec->key, sizeof(*(enc_dec->key)),
			enc_dec->iv, sizeof(enc_dec->iv),
			enc_dec->tag, sizeof(enc_dec->tag),
			dest, source, page_size);
#endif
	return rc;
}

static void get_next_iv(struct iv_state *iv_state, uv_iv_t *iv)
{
	void *p = iv;

	BUILD_ASSERT(sizeof(*iv) ==
		     sizeof(iv_state->fixed) + sizeof(iv_state->counter));

	memcpy(p, iv_state->fixed, sizeof(iv_state->fixed));
	memcpy(p + sizeof(iv_state->fixed), &iv_state->counter,
	       sizeof(iv_state->counter));

	if (iv_state->counter == UINT64_MAX) {
		uv_crypto_rand_bytes(iv_state->fixed, sizeof(iv_state->fixed));
		iv_state->counter = 0;
	} else
		iv_state->counter++;
}

struct encrypt_struct *page_encrypt(void *dest, void *source, u64 page_size,
		uv_key_t *key, struct iv_state *iv_state)
{
	struct encrypt_struct *enc_dec;

	assert(key != NULL);

	/*
	 * @todo: having a set of preallocated enc_dec structures will
	 * free us up from allocating structures in the critical path
	 */
	enc_dec = (struct encrypt_struct *)zalloc(sizeof(*enc_dec));
	if (!enc_dec) {
		pr_warn("%s encrypt_struct allocation failed\n", __func__);
		return NULL;
	}

	enc_dec->key = key;
	get_next_iv(iv_state, &enc_dec->iv);

#ifdef DISABLE_ENCRYPT
	memcpy(dest, source, page_size);
#else
	if (svm_crypto_gcm_encrypt(*key, sizeof(uv_key_t),
			enc_dec->iv, sizeof(enc_dec->iv),
			enc_dec->tag, sizeof(enc_dec->tag),
			dest, source, page_size))
		return NULL;
#endif

	return enc_dec;
}
