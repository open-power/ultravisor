
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
#include "../cipher_wrap.c"
#include "../cipher.c"
#include "../aes.c"
#include "../gcm.c"

int main(void)
{
	int32_t	ret;

	printf("Calling mbedtls_gcm_self_test \n");

	ret = mbedtls_gcm_self_test(1);

	printf("mbedtls_gcm_self_test returned %d\n", ret);

	return ret;
}
