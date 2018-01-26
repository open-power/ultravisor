/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UV Crypto
 *
 * Copyright 2019, IBM Corporation.
 *
 */

#ifndef SVM_UV_CRYPTO_H
#define SVM_UV_CRYPTO_H

#include <stdint.h>
#include <mbedtls/hmac_drbg.h>

/**
 * @brief Generate random bytes.
 *
 * @param output Buffer to fill.
 * @param output_len Length of the buffer.
 *
 * @return 0 on success, else 1 on failure.
 */
extern int uv_crypto_rand_bytes(unsigned char *output, size_t output_len);

/**
 * @brief Init crypto context
 *
 * @return 0 on success, else 1 on failure.
 */
extern int32_t uv_crypto_init(void);

/**
 * @brief Copy wrapping key data provided by skiboot. uv_fdt contains wrapping
 *     key password and wrapping key publicname.
 *
 * @param uv_fdt pointer to FDT.
 *
 * @return 0 on success, else 1 on failure.
 */
extern int32_t uv_crypto_wrap_key_init(void *uv_fdt);

/**
 * @brief Retrieve wrapping key propetry value requested.
 *
 * @param name name of the property to find.
 * @param prop_len pointer to an integer variable (will be overwritten) or NULL.
 *
 * @return ptr to fdt_property on success, else NULL on failure.
 */
extern const void *uv_crypt_wrap_key_getprop(const char *name, int *prop_len);

/**
 * @brief Retrieve wrapping key u32 value requested.
 *
 * @param name name of the property to find.
 * @param prop_cell pointer to an integer variable (will be overwritten) or NULL.
 *
 * @return 0 on success, else a negative libfdt FDT_ERR error code on failure.
 */
extern int uv_crypt_wrap_key_u32_get(const char *name, uint32_t *prop_cell);

#endif /* SVM_UV_CRYPTO_H */

