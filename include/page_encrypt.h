// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * page encrypt decrypt
 *
 * Copyright 2019, IBM Corporation.
 *
 */
#ifndef PAGE_ENCRYPT_H
#define PAGE_ENCRYPT_H

typedef unsigned char uv_key_t[16];
typedef unsigned char uv_iv_t[12];

struct encrypt_struct {
	uv_key_t *key; /* pointer to the key variable. That variable is
			  located in a non-dumpable location */
	uv_iv_t iv;
	uint8_t tag[16];
};

/*
 * IV made with the deterministic construction method from NIST Special
 * Publication 800-38D.
 */
struct iv_state {
	uint64_t counter;
	uint8_t fixed[4];
};

extern int page_decrypt(void *hv_page, void *uv_page,
		u64 page_size, struct encrypt_struct *enc_dec);
extern struct encrypt_struct *page_encrypt(void *hv_page, void *uv_page,
		u64 page_size, uv_key_t *key, struct iv_state *iv_state);
#endif /* PAGE_ENCRYPT_H */
