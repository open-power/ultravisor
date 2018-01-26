
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MBEDTLS_SELF_TEST

#define MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED -0x0072 /**< The requested feature is not supported by the platform */

#include <mbedtls/config.h>
#undef MBEDTLS_PLATFORM_C
#undef MBEDTLS_PLATFORM_MEMORY
#include "../platform_util.c"
#include "../aes.c"

int main(void)
{
	int32_t	ret;

	printf("Calling mbedtls_aes_self_test \n");

	ret = mbedtls_aes_self_test(1);

	printf("mbedtls_aes_self_test returned %d\n", ret);

	return ret;
}
