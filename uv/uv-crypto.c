/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UV Crypto
 *
 * Copyright 2019, IBM Corporation.
 *
 */

#undef DEBUG
#define pr_fmt(fmt) "UV-CRYPT: " fmt

#include <lock.h>
#include <ppc-opcode.h>
#include <libfdt/libfdt.h>
#include <mem_region.h>

#include <uv/uv-common.h>
#include <uv/uv-crypto.h>

//#define DEBUG
#ifdef DEBUG
#define uv_crypt_dprintf(fmt...)                                               \
	do {                                                                   \
		printf(fmt);                                                   \
	} while (0)
#else
#define uv_crypt_dprintf(fmt...)                                               \
	do {                                                                   \
	} while (0)
#endif

#ifdef DEBUG
static void uv_crypt_dprintf_buf(const uint8_t *buf, uint8_t length)
{
	uint8_t i;
	uint8_t pr_buf[64];
	uint8_t *b = pr_buf, *eb = &pr_buf[64];

	for (i = 0; i < length; i++) {
		b += snprintf(b, eb - b, "%.2x ", buf[i]);
		if (!((i + 1) % 16)) {
			printf("%s\n", pr_buf);
			b = pr_buf;
		}
	}

	if (b != pr_buf) {
		printf("%s\n", pr_buf);
	}
}
#else
#define uv_crypt_dprintf_buf(buf, length)                                      \
	do {                                                                   \
	} while (0)
#endif

const uint8_t *uv_tpm_compat = "ibm,uv-tpm";
static void *uv_crypto_fdt;
#define UV_CRYPTO_FDT_SIZE 1024

const char *wrap_key_prop_str[] = { "wrapping-key-handle",
				    "wrapping-key-passwd",
				    "wrapping-key-publicname",
				    "wrapping-key-policy-a",
				    "wrapping-key-policy-b", NULL };

static mbedtls_hmac_drbg_context uv_drbg_ctx;
static struct lock drbg_lock = LOCK_UNLOCKED;

#define DARN_ERR	0xFFFFFFFFFFFFFFFFul

static uint64_t uv_crypto_darn_bytes(void)
{
	uint64_t rnum;
	int i;

	/*
	 * Power ISA says 10 attemps should be sufficient for DARN
	 * to succeed. Try upto 64 times before giving up.
	 */
	for (i = 0; i < 64; i++) {
		asm volatile(PPC_DARN(%0, 1) : "=r"(rnum));

		if (rnum != DARN_ERR) {
			break;
		}
	}

	if (rnum == DARN_ERR) {
		/** @todo (andmike) Need policy if darn fails */
		abort();
	}

	return rnum;
}

static int32_t uv_crypto_seed_bytes(void *ctx __unused, unsigned char *buf,
		size_t len)
{
	uint64_t rnum;

	while (len > 0 ) {
		size_t cp_len;

		rnum = uv_crypto_darn_bytes();
		assert(rnum != DARN_ERR);

		cp_len = (len < sizeof(rnum)) ? len : sizeof(rnum);
		memcpy(buf, &rnum, cp_len);

		buf += cp_len;
		len -= cp_len;
	}

	return 0;
}

static int32_t uv_crypto_drbg_init(void)
{
	int32_t rc;
	const mbedtls_md_info_t *md_info;

	mbedtls_hmac_drbg_init(&uv_drbg_ctx);

	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	assert(md_info);

	rc = mbedtls_hmac_drbg_seed(&uv_drbg_ctx, md_info,
			uv_crypto_seed_bytes, NULL, NULL, 0);
	if (rc) {
		return rc;
	}

	mbedtls_hmac_drbg_set_reseed_interval(&uv_drbg_ctx, 1000);

	mbedtls_hmac_drbg_set_prediction_resistance(&uv_drbg_ctx,
			MBEDTLS_HMAC_DRBG_PR_OFF);
	
	return rc;
}

int32_t uv_crypto_init(void)
{
	int32_t rc;

	rc = uv_crypto_drbg_init();

	return rc;
}

int32_t uv_crypto_rand_bytes(unsigned char *output, size_t output_len)
{
	int32_t rc;

	lock(&drbg_lock);
	rc = mbedtls_hmac_drbg_random(&uv_drbg_ctx, output, output_len);
	unlock(&drbg_lock);

	return rc;
}

int32_t uv_crypto_wrap_key_init(void *uv_fdt)
{
	int rc = 0;
	int i;
	int node_offset;
	const void *prop;
	int prop_len;

	/* Check validity of imcomming FDT */
	node_offset = fdt_node_offset_by_compatible(uv_fdt, -1, uv_tpm_compat);
	if (node_offset < 0) {
		pr_error("%s: Find compatible %s failed (%d)\n", __func__,
			 uv_tpm_compat, node_offset);
		return rc;
	}

	/**
	 * Crypto only uses a portion of the uv_fdt.
	 */

	assert(!uv_crypto_fdt); /* Only called once during init. */
	lock(&ultra_stor.free_list_lock);
	uv_crypto_fdt = mem_alloc(&ultra_stor, UV_CRYPTO_FDT_SIZE,
				  __alignof__(long), __location__);
	unlock(&ultra_stor.free_list_lock);
	if (!uv_crypto_fdt) {
		pr_error("%s: mem_alloc failed\n", __func__);
		return -9;
	}

	rc = fdt_create(uv_crypto_fdt, UV_CRYPTO_FDT_SIZE);
	if (rc) {
		pr_error("%s: fdt_create failed (%d)\n", __func__, rc);
		return -9;
	}

	fdt_begin_node(uv_crypto_fdt, "");
	fdt_begin_node(uv_crypto_fdt, "ibm,uv-crypto");
	fdt_property_string(uv_crypto_fdt, "compatible", uv_tpm_compat);

	for (i = 0; wrap_key_prop_str[i] != NULL; i++) {
		prop = fdt_getprop(uv_fdt, node_offset, wrap_key_prop_str[i],
				   &prop_len);
		if (!prop) {
			pr_error("%s: Could not find %s (%d)\n", __func__,
				 wrap_key_prop_str[i], prop_len);
			rc = 0;
			goto out;
		}
		rc = fdt_property(uv_crypto_fdt, wrap_key_prop_str[i], prop,
				  prop_len);
		if (rc) {
			pr_error("%s: Could not add %s prop (%d)\n", __func__,
				 wrap_key_prop_str[i], rc);
			rc = -9;
			goto out;
		}

		uv_crypt_dprintf("%s len %d\n", wrap_key_prop_str[i], prop_len);
		uv_crypt_dprintf_buf((const uint8_t *)prop, 16);
	}

	/* Finish fdt */
	fdt_end_node(uv_crypto_fdt);
	fdt_end_node(uv_crypto_fdt);
	fdt_finish(uv_crypto_fdt);

	uv_crypt_dprintf("uv_crypto_fdt size 0x%x\n",
			 fdt_totalsize(uv_crypto_fdt));
	uv_crypt_dprintf("uv_fdt size 0x%x\n", fdt_totalsize(uv_fdt));

out:
	return rc;
}

const void *uv_crypt_wrap_key_getprop(const char *name, int *prop_len)
{
	int node_offset;
	const void *prop;

	node_offset =
		fdt_node_offset_by_compatible(uv_crypto_fdt, -1, uv_tpm_compat);
	if (node_offset < 0) {
		pr_error("%s: Find compatible %s failed (%d)\n", __func__,
			 uv_tpm_compat, node_offset);
		return NULL;
	}

	prop = fdt_getprop(uv_crypto_fdt, node_offset, name, prop_len);
	if (!prop) {
		pr_error("%s: fdt_getprop failed for %s (%d)\n", __func__, name,
			 *prop_len);
	}

	return prop;
}

int uv_crypt_wrap_key_u32_get(const char *name, uint32_t *val)
{
	int node_offset;
	const uint32_t *prop;
	int prop_len;

	node_offset =
		fdt_node_offset_by_compatible(uv_crypto_fdt, -1, uv_tpm_compat);
	if (node_offset < 0) {
		pr_error("%s: Find compatible %s failed (%d)\n",
			 __func__, uv_tpm_compat, node_offset);
		return node_offset;
	}

	prop = fdt_getprop(uv_crypto_fdt, node_offset, name, &prop_len);
	if (!prop) {
		pr_error("%s: fdt_getprop failed for %s (%d)\n",
			 __func__, name, prop_len);
		return prop_len;
	}

	*val = fdt32_to_cpu(*prop);

	uv_crypt_dprintf("%s() name %s, val 0x%x\n", __func__, name, *val);

	return 0;
}
