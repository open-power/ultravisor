#undef DEBUG

#include <assert.h>
#include <compiler.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DEBUG
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

const uint8_t *test_name = "rtas-bbuf-tst";

#define zalloc(bytes) calloc((bytes), 1)

#undef NO_RMOR
#define NO_RMOR(x) (x)

#include "../../ccan/bitops/bitops.c"
#include "../svm-rtas-bbuf.h"
#undef pr_fmt
#include "../svm-rtas-bbuf.c"

#define BBUF_GPA 0xdb20000
#define ORIG_BUF_GPA 0xFb20000

hpa_t bbuf_hpa;
hpa_t orig_buf_hpa;

void *gpa_to_addr(struct mm_struct *mm, gpa_t gpa, int *present)
{
	off_t bbuf_off;
	void *ret;

	(void)mm;
	(void)present;

	tst_dprintf("%s: gpa 0x%" PRIx64 "\n", __func__, gpa);

	if (gpa > (BBUF_GPA + SVM_PAGESIZE)) {
		bbuf_off = gpa - ORIG_BUF_GPA;
		ret = (void *)(orig_buf_hpa + bbuf_off);
		tst_dprintf("%s: orig_buf 0x%" PRIx64 "\n", __func__,
			    (gpa_t)ret);
	} else {
		bbuf_off = gpa - BBUF_GPA;
		ret = (void *)(bbuf_hpa + bbuf_off);
		tst_dprintf("%s: bbuf 0x%" PRIx64 "\n", __func__, (gpa_t)ret);
	}

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

int main(int argc, char *argv[])
{
	int32_t i, ret = 0;
	struct svm *svm;
	struct refl_state *r_state;
	gpa_t bbuf_addr[TEST_CNT];
	gpa_t orig_buf_addr[TEST_CNT];

	(void)argc;
	(void)argv;

	printf("%s: Starting test \n", test_name);
	printf("%s: Struct svm size %ld \n", test_name, sizeof(*svm));
	printf("%s: Struct refl_state size %ld \n", test_name,
	       sizeof(struct refl_state));

	orig_buf_hpa = (hpa_t)malloc(SVM_PAGESIZE);
	if (!orig_buf_hpa) {
		printf("%s: Alloc of orig_buf_hpa failed\n", test_name);
		goto out;
	}

	bbuf_hpa = (hpa_t)malloc(SVM_PAGESIZE);
	if (!bbuf_hpa) {
		printf("%s: Alloc of bbuf_hpa failed\n", test_name);
		goto out;
	}

	svm = malloc(sizeof(*svm));
	if (!svm) {
		printf("%s: Alloc of svm failed\n", test_name);
		goto out;
	}

	init_lock(&svm->lock);
	svm_rtas_bbuf_init(&svm->rtas);
	svm->rtas.rtas_buf_bbuf = BBUF_GPA;
	svm->rtas.bbuf_alloc_map = 0;

	r_state = malloc(sizeof(*r_state));
	if (!r_state) {
		printf("%s: Alloc of r_state failed\n", test_name);
		goto out;
	}

	r_state->svm = svm;

	for (i = 0; i < TEST_CNT; i++) {
		off_t offset;

		offset = i * RTAS_BUF_BBUF_SZ;
		orig_buf_addr[i] = ORIG_BUF_GPA + offset;
		memset((void *)(orig_buf_hpa + offset), i, RTAS_BUF_BBUF_SZ);

		bbuf_addr[i] = (gpa_t)svm_rtas_bbuf_alloc(&r_state->svm->mm,
							  &r_state->svm->rtas);
		if (svm_rtas_bbuf_memcpy(&r_state->svm->mm, bbuf_addr[i],
					orig_buf_addr[i],
					RTAS_BUF_BBUF_SZ) != RTAS_BUF_BBUF_SZ) {
			printf("%s: svm_rtas_bbuf_memcpy failed\n", test_name);
			goto out;
		}
		printf("%s: Buf [%d] orig_buf 0x%" PRIx64 "\n", test_name, i,
		       orig_buf_addr[i]);
		printf("%s: Buf [%d] bbuf 0x%" PRIx64 "\n", test_name, i,
		       bbuf_addr[i]);
		printf("%s: bbuf_alloc_map 0x%lx\n", test_name,
		       svm->rtas.bbuf_alloc_map);
	}

	for (i = 0; i < TEST_CNT; i++) {
		off_t offset;
		offset = i * RTAS_BUF_BBUF_SZ;

		ret = memcmp((void *)(orig_buf_hpa + offset),
			     (void *)(bbuf_hpa + offset), RTAS_BUF_BBUF_SZ);

		printf("%s: memcmp offset %d, ret %d\n", test_name, i, ret);

		assert(!ret);
	}

	for (i = 0; i < TEST_CNT; i++)
		svm_rtas_bbuf_free(&r_state->svm->rtas, bbuf_addr[i]);

	assert(!svm->rtas.bbuf_alloc_map);

	printf("%s: test returned %d\n", test_name, ret);

out:
	free(r_state);
	free(svm);
	free((void *)bbuf_hpa);
	free((void *)orig_buf_hpa);

	return ret;
}
