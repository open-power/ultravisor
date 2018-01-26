
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MBEDTLS_SELF_TEST

#define MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED -0x0072 /**< The requested feature is not supported by the platform */

#define MBEDTLS_SHA1_C
#include <mbedtls/config.h>
#undef MBEDTLS_PLATFORM_C
#undef MBEDTLS_PLATFORM_MEMORY
#include "../platform_util.c"
#include "../sha1.h"
#include "../md.c"
#include "../md_wrap.c"
#include "../pkcs5.c"

int main(void)
{
	int32_t	ret;

	printf("Calling mbedtls_pkcs5_self_test \n");

	ret = mbedtls_pkcs5_self_test(1);

	printf("mbedtls_pkcs5_self_test returned %d\n", ret);

	return ret;
}
