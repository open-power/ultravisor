// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2019 IBM Corp.
 */

#define pr_fmt(fmt) "SVM-ESM: " fmt

#include <stdio.h>
#include <logging.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <svm/svm-internal.h>
#include <svm/svm-esm.h>
#include <svm/svm-esmb.h>
#include <pagein_track.h>
#include <pgtable.h>
#include <uvcall.h>
#include <errno.h>

#include <device.h>

#undef DEBUG
#ifdef DEBUG
#define svm_esm_dprintf(fmt...) do { printf(fmt); } while(0)
#else
#define svm_esm_dprintf(fmt...) do { } while(0)
#endif

#ifdef DEBUG
static void svm_esm_dprintf_buf(const uint8_t *buf, uint8_t length)
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
#define svm_esm_dprintf_buf(buf, length) do {} while(0)
#endif

#ifndef ALIGN_UP
#define ALIGN_UP(_v, _a)        (((_v) + (_a) - 1) & ~((_a) - 1))
#endif

#define CPIO_HDR_MAGIC "070701"
#define CPIO_TRLR_MAGIC "TRAILER!!!"
#define CPIO_PATH_PEF "opt/ibm/pef"
#define CPIO_PATH_PEF_SZ (sizeof(CPIO_PATH_PEF))

struct cpio_newc_hdr {
	char    c_magic[6];
	char    c_ino[8];
	char    c_mode[8];
	char    c_uid[8];
	char    c_gid[8];
	char    c_nlink[8];
	char    c_mtime[8];
	char    c_filesize[8];
	char    c_devmajor[8];
	char    c_devminor[8];
	char    c_rdevmajor[8];
	char    c_rdevminor[8];
	char    c_namesize[8];
	char    c_check[8];
};

#define CPIO_HDR_SZ (sizeof(struct cpio_newc_hdr))

static int svm_esm_esmb_magic_scan(hpa_t *esmb, hpa_t start, size_t file_len)
{
	int rc = -ENOENT;
	uint32_t *fdt_magic;

	/*
	 * To not be restrictied to the filename used just look for FDT_MAGIC
	 * in the cpio archive file.
	 */

	fdt_magic = (uint32_t *)start;

	while (file_len > 0) {
		if (*fdt_magic == FDT_MAGIC) {
			svm_esm_dprintf("%s: Found FDT_MAGIC at 0x%llx\n",
					__func__, (u64)fdt_magic);
			*esmb = (hpa_t)fdt_magic;
			rc = 0;
			break;
		}

		++fdt_magic;
		file_len -= sizeof(uint32_t);
	}

	return rc;
}

/*
 * @brief Locate esmb in cpio archive.
 *
 * @return 0 on success.
 * @return errno on failure.
 */
static int svm_esm_cpio_esmb(struct refl_state *r_state, gpa_t *initrd,
			     size_t *initrd_len, hpa_t *esmb)
{
	int rc = -ENOENT;
	gpa_t _start;
	hpa_t start_hdr, cur_hdr, next_hdr;
	hpa_t file_start;
	size_t cpio_len, offset = 0;
	uint8_t toul_buf[9], *filename;
	size_t namesize, filesize;
	struct cpio_newc_hdr *newc_hdr;

	_start = ALIGN_UP(*initrd, 4);
	cpio_len = *initrd_len;

	/* @todo May need to do this in SVM_PAGESIZE chunks */
	cur_hdr = (hpa_t)gpa_to_addr(&r_state->svm->mm,
				     _start, NULL);
	svm_esm_dprintf("%s: Start cur_hdr 0x%llx\n", __func__, cur_hdr);

	start_hdr = cur_hdr;
	while(cpio_len > 0) {

		newc_hdr = (struct cpio_newc_hdr *)cur_hdr;

		if (!memcmp(newc_hdr->c_magic, CPIO_HDR_MAGIC, 6)) {
			svm_esm_dprintf("%s: newc_hdr magic at 0x%llx\n",
					__func__, cur_hdr);
			svm_esm_dprintf_buf(newc_hdr->c_magic, 8);

			snprintf(toul_buf, 9, "%s", newc_hdr->c_namesize);
			namesize = strtoul(toul_buf, NULL, 16);

			svm_esm_dprintf("%s: namesize 0x%lx\n",
					__func__, namesize);

			snprintf(toul_buf, 9, "%s", newc_hdr->c_filesize);
			filesize = strtoul(toul_buf, NULL, 16);

			svm_esm_dprintf("%s: filesize 0x%lx\n",
					__func__, filesize);

			next_hdr = cur_hdr + CPIO_HDR_SZ + namesize;
			/* Align up to start of file */
			next_hdr = ALIGN_UP(next_hdr, 4);
			next_hdr += filesize;
			/* Align up to EOF */
			next_hdr = ALIGN_UP(next_hdr, 4);

			svm_esm_dprintf("%s: next_hdr 0x%llx\n",
					__func__, next_hdr);

			filename = (uint8_t *)(cur_hdr + CPIO_HDR_SZ);

			if (namesize == 0xB) { /* TRAILER check */

				svm_esm_dprintf("%s: filename %s\n",
						__func__, filename);
				if (!strncmp(CPIO_TRLR_MAGIC, filename,
					     namesize)) {
					next_hdr = ALIGN_UP(next_hdr, 512);
					offset = (int)(next_hdr - start_hdr);
					svm_esm_dprintf("%s: TRAILER found "
							"rc: 0x%x\n",
							__func__, rc);
					break;
				}
			}

			if (filesize && !(*esmb)) {

				/* Verify path contains CPIO_PATH_PEF */

				if (strncmp(CPIO_PATH_PEF, filename,
					    (CPIO_PATH_PEF_SZ - 1))) {
					svm_esm_dprintf("%s: Not a esmb cpio "
							"(%s) %ld\n",
							__func__,
							filename,
							CPIO_PATH_PEF_SZ);
					rc = -ENOENT;
					goto out;
				}

				file_start = cur_hdr + CPIO_HDR_SZ + namesize;
				file_start = ALIGN_UP(file_start, 4);

				rc = svm_esm_esmb_magic_scan(esmb, file_start,
							     filesize);
				if (!rc) {
					svm_esm_dprintf("%s: esmb found "
							"0x%llx\n",
							__func__, *esmb);
				}
			}

		} else {
			goto out;
		}

		cpio_len -= (next_hdr - cur_hdr);
		cur_hdr = next_hdr;
		svm_esm_dprintf("%s: cur_hdr 0x%llx, cpio_len 0x%lx\n",
				__func__, cur_hdr, cpio_len);
	}

	/*
	 * If esmb then adjust for this archive size so cryptographic hash of
	 * the initramfs can be performed.
	 */
	if (*esmb) {
		*initrd = *initrd + offset;
		*initrd_len = *initrd_len - offset;
		svm_esm_dprintf("%s: initrd adjusted 0x%llx, len 0x%lx\n",
				__func__, *initrd, *initrd_len);
		printf("%s: esmb fdt %llx\n", __func__, *esmb);
	}

out:
	return rc;
}

/*
 * NOTE: On success, caller is responsible for freeing buffer in *bootargs.
 */
static int svm_esm_bootargs_get(struct refl_state *r_state, char **bootargs,
		size_t *bootargs_len)
{
	hpa_t svm_fdt;
	gpa_t svm_fdt_gpa;
	const struct fdt_property *prop;
	int prop_len;
	int rc = -ENOENT;

	svm_fdt_gpa = svm_fdt_get_fdt_gpa(r_state->svm);
	if (!svm_fdt_gpa) {
		pr_error("%s: svm_fdt_get_fdt_gpa rc [%d]\n", __func__, rc);
		goto out;
	}

	svm_fdt = svm_fdt_get_fdt_hpa(r_state->svm);
	if (!svm_fdt) {
		pr_error("%s: svm_fdt_get_fdt_hpa rc [%d]\n", __func__, rc);
		goto out;
	}

	rc = svm_fdt_prop_get(svm_fdt, "/chosen", "bootargs", &prop,
				&prop_len);
	if (rc) {
		pr_error("%s: /chosen/bootargs prop get rc [%d]\n",
			 __func__, rc);
		rc = -ENOENT;
		goto out;
	}

	*bootargs = malloc(prop_len);
	if (!*bootargs) {
		rc = -ENOMEM;
		goto out;
	}

	memcpy(*bootargs, prop->data, prop_len);
	*bootargs_len = prop_len;

	svm_esm_dprintf("%s: bootargs(len %zd) '%s'\n",
			__func__, *bootargs_len, *bootargs);

out:
	return rc;
}

/*
 * @brief Locate esmb with wrappper dt entries.
 *
 * @return 0 on success.
 * @return errno on failure.
 */
static int svm_esm_wrapper_esmb(struct refl_state *r_state, hpa_t *esmb)
{
	int rc = -ENOENT;
	gpa_t esmb_start, esmb_end;
	hpa_t svm_fdt;

	svm_fdt = svm_fdt_get_fdt_hpa(r_state->svm);
	if (!svm_fdt) {
		pr_error("%s: svm_fdt_get_fdt_hpa failed\n", __func__);
		goto out;
	}

	rc = svm_fdt_prop_gpa_get(svm_fdt, "/chosen",
			"linux,esm-blob-start", &esmb_start);
	if (rc) {
		pr_error("%s: esm-blob-start prop get rc [%d]\n", __func__, rc);
		rc = -ENOENT;
		goto out;
	}

	rc = (gpa_t)svm_fdt_prop_gpa_get(svm_fdt, "/chosen",
			"linux,esm-blob-end", &esmb_end);
	if (rc) {
		pr_error("%s: esm-blob-end prop get rc [%d]\n", __func__, rc);
		rc = -ENOENT;
		goto out;
	}

	svm_esm_dprintf("%s: esmb start %llx, end %llx\n", __func__,
			esmb_start, esmb_end);

	/* ESM blob FDT */
	*esmb = (hpa_t) get_page_range(r_state,
				       esmb_start, (esmb_end - esmb_start));
	if (!esmb) {
		pr_error("%s: pagein of ESMB pages failed\n", __func__);
		rc = -ENOENT;
	}

out:
	return rc;
}

static int svm_esm_esmb_get(struct refl_state *r_state, hpa_t *esmb,
			    gpa_t *initrd, size_t *initrd_len __unused)
{
	int rc = -ENOENT;
	bool esmb_found = false;
	hpa_t svm_fdt;

	svm_fdt = svm_fdt_get_fdt_hpa(r_state->svm);
	if (!svm_fdt) {
		pr_error("%s: svm_fdt_get_fdt_hpa failed\n", __func__);
		goto out;
	}

	/* Check for esmb added by bootwrapper then cpio */

	rc = svm_esm_wrapper_esmb(r_state, esmb);
	if (!rc) {
		esmb_found = true;
	}

	if (!esmb_found) {
		rc = svm_esm_cpio_esmb(r_state, initrd, initrd_len, esmb);
		if (rc) {
			pr_error("%s: svm_esm_cpio_esmb rc [%d]\n",
				 __func__, rc);
			goto out;
		}
	}

	/* ESM blob */
	if (*esmb) {
		svm_fdt_print(*esmb);
	}
out:
	return rc;
}

static int svm_esm_initrd_gpa_get(struct refl_state *r_state, gpa_t *initrd,
				  size_t *initrd_len)
{
	hpa_t svm_fdt;
	gpa_t _end;
	int rc = -ENOENT;

	svm_fdt = svm_fdt_get_fdt_hpa(r_state->svm);
	if (!svm_fdt) {
		pr_error("%s: svm_fdt_get_fdt_hpa rc [%d]\n", __func__, rc);
		goto out;
	}

	rc = svm_fdt_prop_gpa_get(svm_fdt, "/chosen",
				  "linux,initrd-start", initrd);
	if (rc) {
		pr_error("%s: linux,initrd-start prop get rc [%d]\n",
			 __func__, rc);
		rc = -ENOENT;
		goto out;
	}

	rc = svm_fdt_prop_gpa_get(svm_fdt, "/chosen",
				  "linux,initrd-end", &_end);
	if (rc) {
		pr_error("%s: linux,initrd-end prop get rc [%d]\n",
			 __func__, rc);
		rc = -ENOENT;
		goto out;
	}

	*initrd_len = _end - *initrd;
	if (!get_page_range(r_state, *initrd, *initrd_len)) {
		pr_error("%s: page-in of initrd pages failed\n", __func__);
		rc = -ENOENT;
	}
out:
	return rc;
}

static int svm_esm_rtas_gpa_get(struct refl_state *r_state, gpa_t *rtas,
				size_t *rtas_len, size_t *rtas_text_len)
{
	hpa_t svm_fdt;
	uint32_t _rtas_len, _rtas_text_len;
	int rc = -ENOENT;
	u64 npages;

	svm_fdt = svm_fdt_get_fdt_hpa(r_state->svm);
	if (!svm_fdt) {
		pr_error("%s: svm_fdt_get_fdt_hpa rc [%d]\n", __func__, rc);
		goto out;
	}

	rc = svm_fdt_prop_gpa_get(svm_fdt, "/rtas",
				  "linux,rtas-base", rtas);
	if (rc) {
		pr_error("%s: linux,rtas-base prop get rc [%d]\n",
			 __func__, rc);
		rc = -ENOENT;
		goto out;
	}

	rc = svm_fdt_prop_u32_get(svm_fdt, "/rtas", "rtas-size", &_rtas_len);
	if (rc) {
		pr_error("%s: rtas-size prop get rc [%d]\n", __func__, rc);
		rc = -ENOENT;
		goto out;
	}

	rc = svm_fdt_prop_u32_get(svm_fdt, "/rtas", "slof,rtas-size",
				  &_rtas_text_len);
	if (rc) {
		pr_error("%s: slof,rtas-size prop get rc [%d]\n", __func__, rc);
		rc = -ENOENT;
		goto out;
	}

	*rtas_len = _rtas_len;
	*rtas_text_len = _rtas_text_len;

	npages = ALIGN_UP(_rtas_len, SVM_PAGESIZE) / SVM_PAGESIZE;

	/*
	 * Copyin the RTAS pages first. The content of the RTAS pages are
	 * needed by the SVM for correct execution of the RTAS hcalls.
	 * @todo: This call must be deleted, when ultravisor adds support for
	 * RTAS code generation and copying it into the RTAS page.
	 */
	if (!get_page_range(r_state, *rtas, SVM_PAGES_TO_BYTES(npages))) {
		pr_error("%s: RTAS page does not exist\n", __func__);
		rc = -EINVAL;
		goto out;
	}
	/* Pseudo share the entire RTAS area */
	rc = page_share_with_hv(r_state, *rtas, npages, SHARE_PSEUDO);
	if (rc)
		pr_error("%s: pseudo share rtas base with HV[%d]\n",
			 __func__, rc);
out:
	return rc;
}

#ifdef ESM_BLOB_CHK_WARN_ONLY
/*
 * USE THIS FUNCTION WITH CAUTION. ITS THERE TO FACILITATE DEVELOPMENT.
 * Once ESM blob support is correctly implemented, this function should
 * not be relied upon.
 */
int svm_populate_kernel(struct refl_state *r_state, gpa_t kbase)
{
	int rc = 0;
	(void)kbase;
	rc = page_in_from_hv(r_state);
	pr_info("%s(): page_in_from_hv_one returned [%d]\n", __func__, rc);
	return rc;
}
#endif

int svm_esm_blob_chk(struct refl_state *r_state, gpa_t kbase)
{
	gpa_t rtas, initrd;
	char *bootargs;
	size_t rtas_len, rtas_text_len, initrd_len, bootargs_len;

	hpa_t esmb = 0;
	int rc;

	/*
	 * TODO: As of QEMU commit `qemu-slof-20190703-45-g7c98b3b`, RTAS
	 * 	 code is embedded inside the SLOF binary making it hard to
	 * 	 perform integrity checks on the (few lines of) RTAS code.
	 * 	 Besides, strictly speaking, QEMU and slof.bin are untrusted
	 * 	 code for an SVM so the RTAS code is also untrusted.
	 *
	 * 	 The RTAS code is relatively tiny, consisting of following
	 * 	 instructions (see dis-assembly of hvcall.o from the commit
	 * 	 qemu-slof-20190703-45-g7c98b3b):
	 *
	 * 	 static uint8_t rtas_code[] = {
	 * 	 	0x7c, 0x64, 0x1b, 0x78,		// mr   r4,r3
	 * 	 	0x3c, 0x60, 0x00, 0x00,		// lis  r3,0
	 * 	 	0x60, 0x63, 0xf0, 0x00,		// ori  r3,r3,61440
	 * 	 	0x44, 0x00, 0x00, 0x22,		// sc   1
	 * 	 	0x4e, 0x80, 0x00, 0x20		// blr
	 *	 };
	 *
	 * 	 Once Ultravisor locates the RTAS region in the SVM's memory,
	 * 	 (using slof,rtas-base and slof,rtas-size entries in the
	 * 	 device-tree) it can dynamically patch the region with the
	 * 	 above instructions. This ensure that the RTAS code is secure
	 * 	 and also eliminates the need to check its integrity.
	 */
	rc = svm_esm_rtas_gpa_get(r_state, &rtas, &rtas_len, &rtas_text_len);
	if (rc) {
		pr_error("%s: svm_esm_rtas_gpa_get rc [%d]\n", __func__, rc);
		rc = U_PARAMETER;
		goto out;
	}

	/*
	 * Store rtas base/size in svm for later reference during mce
	 * handling
	 */
	r_state->svm->rtas.rtas_base = rtas;
	r_state->svm->rtas.rtas_size = rtas_len;
	r_state->svm->rtas.text_size = rtas_text_len;

	svm_esm_dprintf("%s: rtas start %llx, len %lx\n",
			__func__, rtas,	rtas_len);

	rc = svm_esm_initrd_gpa_get(r_state, &initrd, &initrd_len);
	if (rc) {
		pr_error("%s: svm_esm_initrd_gpa_get rc [%d]\n", __func__, rc);
		rc = U_PARAMETER;
		goto out;
	}

	svm_esm_dprintf("%s: initrd start %llx, len %lx\n",
			__func__, initrd, initrd_len);

	rc = svm_esm_bootargs_get(r_state, &bootargs, &bootargs_len);
	if (rc) {
		pr_error("%s: svm_esm_bootargs_gpa_get rc [%d]\n", __func__, rc);
		rc = U_PARAMETER;
		goto out;
	}

	rc = svm_esm_esmb_get(r_state, &esmb, &initrd, &initrd_len);
	if (rc) {
		pr_error("%s: svm_esm_esmb_get rc [%d]\n", __func__, rc);
		rc = U_PARAMETER;
		goto out_free;
	}

	svm_esm_dprintf("%s: post esmb_get initrd start %llx, len %lx\n",
			__func__, initrd, initrd_len);

	/*
	 * Get any attachments included in the blob. svm-tool currently
	 * treats attachments to the blob as optional. If there aren't
	 * any attachments, subsequent calls to UV_ESMB_GETFILE will fail
	 * but there is no compromise to integrity, so ignore any errors.
	 */
	rc = svm_esmb_get_files_fdt(r_state, esmb);
	if (rc) {
		pr_notice("%s: error %d getting esmb attachments, ignoring\n",
			  __func__, rc);
	}

	rc = svm_esmb_digest_chk(r_state, esmb,
				 rtas, rtas_text_len,
				 kbase,
				 bootargs, bootargs_len,
				 initrd, initrd_len);
	if (rc) {
		pr_error("%s: svm_esmb_digest_chk rc [%d]\n", __func__, rc);
		rc = U_PARAMETER;
	}

out_free:
	free(bootargs);

out:
	return rc;
}
