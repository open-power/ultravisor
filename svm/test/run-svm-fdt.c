#undef DEBUG

#include <assert.h>
#include <compiler.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "stubs.h"

#undef DEBUG
#ifdef DEBUG
#define tst_dprintf(fmt...)			\
	do {					\
		printf(fmt);			\
	} while (0)
#else
#define tst_dprintf(fmt...)			\
	do {					\
	} while (0)
#endif

#define TEST_CNT 10

const uint8_t *test_name = "svm-fdt-tst";

#define zalloc(bytes) calloc((bytes), 1)

#include "../../ccan/bitops/bitops.c"
#include "../svm-fdt.h"
#undef pr_fmt
#undef __uvpa
#define __uvpa(x) (x)
#include "../svm-fdt.c"

hpa_t fdt_hpa;
#define FDT_GPA 0x2180000

void *__alloc_n_pages(size_t n, size_t *n_alloc)
{
	void *pages;
	size_t alloc_sz;

	alloc_sz = n * UV_PAGE_SIZE;

	pages = malloc(alloc_sz);

	if (pages && n_alloc)
		*n_alloc = n;

	return pages;
}

int _free_pages(void *p)
{
	free(p);
	return 0;
}

void *gpa_to_addr(struct mm_struct *mm, gpa_t gpa, int *present)
{
	off_t fdt_off;
	void *ret;

	(void)mm;
	(void)present;

	tst_dprintf("%s: gpa 0x%" PRIx64 "\n", __func__, gpa);

	fdt_off = gpa - FDT_GPA;
	ret = (void *)(fdt_hpa + fdt_off);
	tst_dprintf("%s: fdt_hpa 0x%" PRIx64 "\n", __func__, (hpa_t)ret);

	return ret;
}

void lock_caller(struct lock *l, const char *caller)
{
	(void)caller;
	assert(!l->lock_val);
	l->lock_val = 1;
}

void unlock(struct lock *l)
{
	assert(l->lock_val);
	l->lock_val = 0;
}

struct svm_ops __svm_ops_start;
struct svm_ops __svm_ops_end;

static int32_t svm_fdt_test(size_t first_mem_block_size)
{
	int32_t ret = 0;
	struct svm *svm;
	struct refl_state *r_state;
	void *fdt = NULL;
	gpa_t rsv_mem_addr1, rsv_mem_addr2;
	gpa_t initrd_start;
	gpa_t rmo_top;

	/* Cap rmo top to 768 MB */
	rmo_top = min(768 * MB, first_mem_block_size);

	printf("%s: Starting test \n", test_name);
	printf("%s: Struct svm size %ld \n", test_name, sizeof(*svm));
	printf("%s: Struct refl_state size %ld \n", test_name,
	       sizeof(struct refl_state));
	printf("%s: First memory block size %d MB (0x%lx)\n", test_name,
		(int)(first_mem_block_size >> 20), first_mem_block_size);
	printf("%s: SVM RMO top 0x%lx\n", test_name, rmo_top);

	ret = alloc_fdt(&fdt, first_mem_block_size);
	if (ret) {
		printf("%s: alloc_fdt failed\n", test_name);
		goto out;
	}

	printf("%s: fdt %p \n", test_name, fdt);

	fdt_hpa = (hpa_t)fdt;

	svm = malloc(sizeof(*svm));
	if (!svm) {
		printf("%s: Alloc of svm failed\n", test_name);
		goto out;
	}

	init_lock(&svm->lock);

	r_state = malloc(sizeof(*r_state));
	if (!r_state) {
		printf("%s: Alloc of r_state failed\n", test_name);
		goto out;
	}

	r_state->svm = svm;

	ret = svm_fdt_init(r_state, FDT_GPA);

	printf("%s: svm_fdt_init returned %d\n", test_name, ret);

	if (ret)
		goto out;

	ret = svm_fdt_mem_rsv(svm, (hpa_t)svm->fdt.wc_fdt, SVM_PAGESIZE,
			      &rsv_mem_addr1);
	printf("%s: svm_fdt_mem_rsv returned %d\n", test_name, ret);

	if (ret)
		goto out;

	if ((rsv_mem_addr1 + SVM_PAGESIZE) > rmo_top) {
		printf("%s: Memory reserved beyond RMO top: %lx\n",
		       test_name, rsv_mem_addr1);
		svm_fdt_print((hpa_t)svm->fdt.wc_fdt);
		ret = -EFAULT;
		goto out;
	}

	/* Try one more reservation */
	ret = svm_fdt_mem_rsv(svm, (hpa_t)svm->fdt.wc_fdt, SVM_PAGESIZE,
			      &rsv_mem_addr2);
	printf("%s: svm_fdt_mem_rsv returned %d\n", test_name, ret);

	if (ret)
		goto out;

	if ((rsv_mem_addr2 + SVM_PAGESIZE) > rmo_top) {
		printf("%s: Memory reserved beyond RMO top: %lx\n",
		       test_name, rsv_mem_addr2);
		svm_fdt_print((hpa_t)svm->fdt.wc_fdt);
		ret = -EFAULT;
		goto out;
	}

	/* Check if it is overlapped with previous one */
	if (((rsv_mem_addr2 + SVM_PAGESIZE) > rsv_mem_addr1) &&
			(rsv_mem_addr2 < (rsv_mem_addr1 + SVM_PAGESIZE))) {
		printf("%s: Overlap detected for "
		       "last two memory reservations\n", test_name);
		svm_fdt_print((hpa_t)svm->fdt.wc_fdt);
		ret = -EFAULT;
		goto out;
	}

	ret = svm_fdt_prop_gpa_get((hpa_t)svm->fdt.wc_fdt, "/chosen",
				   "linux,initrd-start", &initrd_start);

	printf("%s: svm_fdt_prop_gpa_get returned %d\n", test_name, ret);

	if (ret)
		goto out;

	printf("%s: calling svm_fdt_print \n", test_name);
	svm_fdt_print((hpa_t)svm->fdt.wc_fdt);

	ret = svm_fdt_finalize(r_state, 0);

	printf("%s: svm_fdt_finalize returned %d\n", test_name, ret);

out:
	free_fdt(fdt);
	free(r_state);
	free(svm);

	return ret;
}

int main(int argc, char *argv[])
{
	int32_t ret = 0;

	(void)argc;
	(void)argv;

	ret = svm_fdt_test(512 * MB);
	if (ret)
		goto out;

	ret = svm_fdt_test(1024 * MB);
	if (ret)
		goto out;

out:
	return ret;
}
