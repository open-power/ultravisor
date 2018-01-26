// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 IBM Corp.
 */

#define pr_fmt(fmt) "SVM-ESMB: " fmt

#include <stdio.h>
#include <logging.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <svm/svm-internal.h>
#include <svm/svm-esmb.h>
#include <svm/svm-crypto.h>
#include <pgtable.h>
#include <uvcall.h>
#include <pagein_track.h>

#include <device.h>

#undef DEBUG
#ifdef DEBUG
#define svm_esmb_dprintf(fmt...) do { printf(fmt); } while(0)
#else
#define svm_esmb_dprintf(fmt...) do { } while(0)
#endif

#ifdef DEBUG
static void svm_esmb_dprintf_buf(const uint8_t *buf, uint8_t length)
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
#define svm_esmb_dprintf_buf(buf, length) 	do {} while (0);
#endif

const uint8_t *lockbox_parent_path="/lockboxes";

const uint8_t *digest_path="/digest/digests-fdt";
const uint8_t *files_fdt_path="/file";

static int svm_esmb_lockbox_get(hpa_t esmb)
{
	int rc;
	int par_offset;

	/* Find lockbox parent node */
	rc = fdt_path_offset((void *)esmb, lockbox_parent_path);
	if (rc < 0) {
		pr_error("%s: lockbox parent fdt_path_offset offset [%d]\n",
			 __func__, rc);
		goto out;
	}

	par_offset = rc;

	rc = fdt_subnode_offset((void *)esmb, par_offset, "lockbox-1");
	if (rc < 0) {
		pr_error("%s: lockbox fdt_path_offset rc [%d]\n", __func__, rc);
		goto out;
	}

out:
	return rc;
}

int svm_esmb_file_get(hpa_t esmb, const char *path,
		      const unsigned char *key, unsigned int key_len,
		      uint8_t *file_buf, size_t *file_len)
{
	int rc;
	int offset;
	const struct fdt_property *prop;
        int prop_len;
	const unsigned char *iv;
	size_t iv_len;
	const unsigned char *tag;
	size_t tag_len;
	const uint8_t *enc_file_buf = NULL;
	uint16_t enc_file_len = 0;

	rc = fdt_path_offset((void *)esmb, path);
	if (rc < 0) {
		pr_error("%s: fdt %p, path %s fdt_path_offset offset [%d]\n",
			 __func__, (void *)esmb, path, rc);
		goto out;
	}

	offset = rc;

	prop = fdt_get_property((void *)esmb, offset, "algorithm", &prop_len);
	if (!prop) {
		pr_error("%s: algorithm property rc [%d]\n",
			 __func__, prop_len);
		rc = U_PARAMETER;
		goto out;
	}
	svm_esmb_dprintf("%s: algorithm len %d\n", __func__, prop_len);
	svm_esmb_dprintf_buf(prop->data, 8);

	prop = fdt_get_property((void *)esmb, offset, "iv", &prop_len);
	if (!prop) {
		pr_error("%s: iv property rc [%d]\n", __func__, prop_len);
		rc = U_PARAMETER;
		goto out;
	}

	iv_len = prop_len;
	iv = prop->data;
	svm_esmb_dprintf("%s: iv len %lu\n", __func__, iv_len);
	svm_esmb_dprintf_buf(iv, 8);

	prop = fdt_get_property((void *)esmb, offset, "mac", &prop_len);
	if (!prop) {
		pr_error("%s: mac property rc [%d]\n", __func__, prop_len);
		rc = U_PARAMETER;
		goto out;
	}

	tag_len = prop_len;
	tag = prop->data;
	svm_esmb_dprintf("%s: tag len %lu\n", __func__, tag_len);
	svm_esmb_dprintf_buf(tag, 8);

	prop = fdt_get_property((void *)esmb, offset, "ciphertext", &prop_len);
	if (!prop) {
		pr_error("%s: ciphertext property rc [%d]\n", __func__, prop_len);
		rc = U_PARAMETER;
		goto out;
	}

	enc_file_len = prop_len;
	*file_len = enc_file_len;
	enc_file_buf = prop->data;

	svm_esmb_dprintf("%s: enc_file_len len %d\n", __func__, enc_file_len);
	svm_esmb_dprintf_buf(enc_file_buf, 8);

	rc = svm_crypto_gcm_decrypt(key, key_len,
				    iv, iv_len,
				    tag, tag_len,
				    file_buf,
				    enc_file_buf, enc_file_len);

	if (rc) {
		pr_error("%s: svm_crypto_gcm_decrypt rc [%d]\n", __func__, rc);
		rc = U_PARAMETER;
		goto out;
	}

	svm_esmb_dprintf("%s: file_buf\n", __func__);
	svm_esmb_dprintf_buf(file_buf, 8);

out:
	return rc;
}

static int svm_esmb_digest_get(hpa_t esmb,
		const unsigned char *key, unsigned int key_len,
		uint8_t *digest_buf, size_t *digest_len)
{
	return svm_esmb_file_get(esmb, digest_path, key, key_len,
				 digest_buf, digest_len);
}

static int svm_esmb_symkey_get(struct refl_state *r_state, hpa_t esmb,
		unsigned char *key, uint16_t *key_len)
{
	const uint8_t *enc_housekey_buf = NULL;
	uint16_t enc_housekey_len = 0;
	int rc, offset;
	const struct fdt_property *prop;
	int prop_len;

	rc = svm_esmb_lockbox_get(esmb);
	if (rc < 0) {
		rc = U_PARAMETER;
		goto out;
	}

	offset = rc;

	prop = fdt_get_property((void *)esmb, offset,
				"encrypted-symkey", &prop_len);
	if (!prop) {
		pr_error("%s: property data rc [%d]\n", __func__, prop_len);
		rc = U_PARAMETER;
		goto out;
	}

	enc_housekey_len = prop_len;
	enc_housekey_buf = prop->data;

	svm_esmb_dprintf("%s: enc_housekey_buf\n", __func__);
	svm_esmb_dprintf_buf(enc_housekey_buf, 8);

	/* Decrypt lockbox */
	rc = svm_crypto_decrypt_lockbox(r_state, key_len, key,
			enc_housekey_len, enc_housekey_buf);
	if (rc) {
		pr_error("%s: svm_crypto_decrypt_lockbox rc [%d]\n",
			 __func__, rc);
		rc = U_PARAMETER;
		goto out;
	}

	svm_esmb_dprintf("%s: key\n", __func__);
	svm_esmb_dprintf_buf(key, 8);
out:
	return rc;
}

/*
 * Check the integrity of all the components captured in the
 * ESM blob.
 *
 * This function assumes that pages corresponding to all the
 * components are already pagedin except the kernel pages.
 * Brings in the kernel pages from the Hypervisor.
 */
int svm_esmb_digest_chk(struct refl_state *r_state, hpa_t esmb,
			gpa_t rtas, size_t rtas_len,
			gpa_t kbase,
			char *bootargs, size_t bootargs_len,
			gpa_t initrd, size_t initrd_len)
{
	struct svm_esmb *svm_esmb;
	uint8_t *housekey_buf;
	uint16_t housekey_len;
	uint8_t *digest_buf;
	size_t digest_len;
	const struct fdt_property *prop;
	int prop_len;
	uint32_t kern_len;
	int rc;
	int failed = 0;

	svm_esmb = (struct svm_esmb *)gpa_to_addr(&r_state->svm->mm,
						  r_state->svm->svm_esmb, NULL);

	housekey_len = FIELD_SIZEOF(struct svm_esmb, buf_key);
	housekey_buf = svm_esmb->buf_key;

	digest_len = FIELD_SIZEOF(struct svm_esmb, buf_digest);
	digest_buf = svm_esmb->buf_digest;

	rc = svm_esmb_symkey_get(r_state, esmb, housekey_buf, &housekey_len);
	if (rc) {
		pr_error("Failed to procure the symmetric key\n");
		goto out;
	}

	rc = svm_esmb_digest_get(esmb, housekey_buf, housekey_len, digest_buf,
				 &digest_len);
	if (rc) {
		pr_error("Failed to procure the esm digest\n");
		goto out;
	}

	svm_esmb_dprintf("%s: digest len %lu\n", __func__, digest_len);
	svm_fdt_print((hpa_t)digest_buf);

	rc = svm_fdt_prop_get((hpa_t)digest_buf, "/digests", "rtas", &prop,
			      &prop_len);
	if (rc) {
		pr_error("Failed to locate /digests/rtas prop [%d]\n", rc);
		goto out;
	}

	svm_esmb_dprintf("%s: RTAS len %d\n", __func__, prop_len);
	svm_esmb_dprintf_buf(prop->data, 8);

	rc = svm_crypto_sha512_chk(r_state, rtas, rtas_len, prop->data);
	if (rc) {
		/* @todo: print the hash value? */
		pr_error("Failed RTAS hash validation\n");
		failed++;
	}

	svm_esmb_dprintf("%s: RTAS sha512sum check rc %d\n", __func__, rc);

	rc = svm_fdt_prop_get((hpa_t)digest_buf, "/digests", "kernel", &prop,
			      &prop_len);
	if (rc) {
		pr_error("Failed to locate /digests/kernel prop [%d]\n", rc);
		goto out;
	}

	svm_esmb_dprintf("%s: kernel prop len %d\n", __func__, prop_len);
	svm_esmb_dprintf_buf(prop->data, 8);

	rc = svm_fdt_prop_u32_get((hpa_t)digest_buf, "/digests", "kernel-size",
				  &kern_len);
	if (rc) {
		pr_error("Failed to locate /digests/kernel-size prop [%d]\n", rc);
		goto out;
	}

	svm_esmb_dprintf("%s: kernel-size %x\n", __func__, kern_len);
	svm_esmb_dprintf_buf(prop->data, 8);

	/* pagein the kernel pages */
	if (!get_page_range(r_state, kbase, kern_len)) {
		pr_error("Failed to page-in kernel pages\n");
		rc = U_PARAMETER;
		goto out;
	}

	rc = svm_crypto_sha512_chk(r_state, kbase, kern_len, prop->data);
	if (rc) {
		/* @todo: print the hash value? */
		pr_error("Failed kernel hash validation\n");
		failed++;
	}

	svm_esmb_dprintf("%s: kernel sha512sum check rc %d\n", __func__, rc);

	rc = svm_fdt_prop_get((hpa_t)digest_buf, "/digests", "initrd", &prop,
			      &prop_len);
	if (rc) {
		pr_error("Failed to locate /digests/initrd prop [%d]\n", rc);
		goto out;
	}

	svm_esmb_dprintf("%s: initrd prop len %d\n", __func__, prop_len);
	svm_esmb_dprintf_buf(prop->data, 8);

	rc = svm_crypto_sha512_chk(r_state, initrd, initrd_len, prop->data);
	if (rc) {
		/* @todo: print the hash value? */
		pr_error("Failed initrd hash validation\n");
		failed++;
	}

	svm_esmb_dprintf("%s: initrd sha512sum check rc %d\n", __func__, rc);

	rc = svm_fdt_prop_get((hpa_t)digest_buf, "/digests", "bootargs", &prop,
			      &prop_len);
	if (rc) {
		pr_error("Failed to locate /digests/bootargs prop [%d]\n", rc);
		goto out;
	}

	svm_esmb_dprintf("%s: bootargs prop len %d\n", __func__, prop_len);
	svm_esmb_dprintf_buf(prop->data, 8);

	bootargs_len = (bootargs_len - 1);
	rc = uv_check_sha512_sum((uint8_t *)bootargs, bootargs_len,
				 prop->data);
	if (rc) {
		/* @todo: print the hash value? */
		pr_error("Failed kernel command line hash validation\n");
		failed++;
	}

	svm_esmb_dprintf("%s: bootargs sha512sum check rc %d\n", __func__, rc);

	rc = U_SUCCESS;

out:
	if (failed) {
		pr_error("Failed %d checks\n", failed);
		rc = U_PARAMETER;
	}
	return rc;
}

void dump_fdt(void *fdt)
{
	int off, len, depth, count;

	off = fdt_next_node(fdt, 0, &depth);
	pr_error("%s() entered for fdt %p\n", __func__, fdt);

	count = 0;
	while(off > 0 && count++ < 20) {
		const char *name;

		name = fdt_get_name(fdt, off, &len);
		if (!name) {
			pr_error("Unable to find name at offset %d\n", off);
			goto out;
		}
		pr_error("name: %s [%d]\n", name, off);

		off = fdt_next_node(fdt, off, &depth);
	}
out:
	pr_error("%s() fdt %p done\n", __func__, fdt);
}

int svm_esmb_get_files_fdt(struct refl_state *r_state, hpa_t esmb)
{
	const struct fdt_property *prop;
	int prop_len;
	int offset;
	int rc;
	void *files_fdt;

	files_fdt = (void *)gpa_to_addr(&r_state->svm->mm,
					r_state->svm->esmb_files_fdt, NULL);

	rc = fdt_path_offset((void *)esmb, files_fdt_path);
	if (rc < 0) {
		pr_error("%s: path %s fdt_path_offset offset [%d]\n",
			 __func__, files_fdt_path, rc);
		return U_PARAMETER;
	}

	offset = rc;

	prop = fdt_get_property((void *)esmb, offset, "files-fdt", &prop_len);
	if (!prop) {
		pr_error("%s: files-fdt property rc [%d]\n",
			 __func__, prop_len);
		return U_PARAMETER;
	}
	svm_esmb_dprintf("%s: files-fdt len %d\n", __func__, prop_len);
	svm_esmb_dprintf_buf(prop->data, 8);

	memcpy(files_fdt, prop->data, prop_len);
	svm_fdt_print((hpa_t)files_fdt);
	dump_fdt(files_fdt);

	return U_SUCCESS;
}

static int64_t svm_esmb_fdt_upd_hdlr(struct refl_state *r_state)
{
	int rc;
	hpa_t svm_fdt;
	gpa_t g_addr;
	struct svm *svm = r_state->svm;
#ifdef DEBUG
	struct svm_esmb_elems *svm_esmb;
#endif

	svm_fdt = svm_fdt_get_fdt_hpa(svm);
	if (!svm_fdt) {
		return U_PARAMETER;
	}

	/*
	 * Reserve one page for SVM esmb use.
	 */
	rc = svm_fdt_mem_rsv(svm, svm_fdt, SVM_PAGESIZE, &g_addr);
	if (rc) {
		pr_error("%s: svm_fdt_mem_rsv [%d]\n", __func__, rc);
		return rc;
	}

	assert(sizeof(struct svm_esmb) < SVM_PAGESIZE);
	svm->svm_esmb = g_addr;

#ifdef DEBUG
	svm_esmb = gpa_to_addr(&svm->mm, svm->svm_esmb, NULL);
	svm_esmb_dprintf("%s: svm_esmb gpa 0x%llx, hpa 0x%llx\n", __func__,
			 (u64) svm->svm_esmb, (u64) svm_esmb);
#endif

	/*
	 * Reserve a page for the files FDT that is nested within
	 * the ESM Blob
	 */
	rc = svm_fdt_mem_rsv(svm, svm_fdt, SVM_PAGESIZE, &g_addr);
	if (rc) {
		pr_error("%s: svm_fdt_mem_rsv [%d]\n", __func__, rc);
		return rc;
	}
	svm->esmb_files_fdt = g_addr;
	pr_error("%s(): files_fdt gpa 0x%llx\n", __func__, g_addr);

	return 0;
}

DECLARE_SVM_OPS(svm_esmb) = {
	.name = "svm_esmb",
	.fdt_upd_hdlr = svm_esmb_fdt_upd_hdlr,
};
