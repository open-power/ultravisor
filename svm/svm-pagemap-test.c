#include <svm/svm-pagemap.h>
#include <logging.h>
#include <assert.h>
#include <uv/uv-crypto.h>

#ifdef SVM_PAGEMAP_TEST

static svm_pagemap_t svm_pagemap;
static int num_test_entries = 100000;

static uint64_t get_rand64(void)
{
        uint32_t i;
        uint64_t num;
        uint8_t buffer[64];

        /* @todo: not sure if rand() can take a buffer < 64 bytes */
        uv_crypto_rand_bytes(buffer, sizeof(buffer));

        num = 0ULL;
        for (i = 0; i < 8; i++)
                num = (num << 8) | buffer[i];

        return num;
}

void svm_pagemap_test(void)
{
	int i;
	int rc;
	void *pointer;
	uint64_t *indices;
	struct svm_page_info **pointers;

	pr_error("UV-PAGEMAP: Test with %d entries\n", num_test_entries);

	indices = malloc(num_test_entries * sizeof(uint64_t));
	pointers = malloc(num_test_entries * sizeof(void *));
	assert(indices && pointers);

	for (i = 0; i < num_test_entries; i++) {
		indices[i] = get_rand64();
		pointers[i] = (struct svm_page_info *)get_rand64();
	}

	svm_pagemap_init(&svm_pagemap);

	for (i = 0; i < num_test_entries; i++) {
		pointer = svm_pagemap_load(&svm_pagemap, indices[i]);
		assert(pointer == NULL);
	}

	for (i = 0; i < num_test_entries; i++) {
		rc = svm_pagemap_store(&svm_pagemap, indices[i], pointers[i]);
		assert(rc == 0);
	}

	for (i = 0; i < num_test_entries; i++) {
		pointer = svm_pagemap_load(&svm_pagemap, indices[i]);
		assert(pointer == pointers[i]);
	}

	svm_pagemap_clear(&svm_pagemap);

	pr_error("UV-PAGEMAP: Test passed\n");

	free(indices);
	free(pointers);
}
#endif

