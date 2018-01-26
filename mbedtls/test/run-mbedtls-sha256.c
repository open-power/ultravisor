
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MBEDTLS_SELF_TEST

#include <mbedtls/config.h>
#undef MBEDTLS_PLATFORM_C
#undef MBEDTLS_PLATFORM_MEMORY
#include "../platform_util.c"
#include "../sha256.c"

int main(void)
{
	int32_t	ret;

	printf("Calling mbedtls_sha256_self_test \n");

	ret = mbedtls_sha256_self_test(1);

	printf("mbedtls_sha256_self_test returned %d\n", ret);

	return ret;
}
