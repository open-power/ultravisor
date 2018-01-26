
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MBEDTLS_SELF_TEST

#include <mbedtls/config.h>
#undef MBEDTLS_PLATFORM_C
#undef MBEDTLS_PLATFORM_MEMORY
#include "../platform_util.c"
#include "../md.c"
#include "../md_wrap.c"
#include "../hmac_drbg.c"

int main(void)
{
	int32_t ret;

	printf("Calling mbedtls_hmac_drbg_self_test \n");

	ret = mbedtls_hmac_drbg_self_test(1);

	printf("mbedtls_hmac_drbg_self_test returned %d\n", ret);

	return ret;
}
