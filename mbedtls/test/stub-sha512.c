
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MBEDTLS_SELF_TEST

#include <mbedtls/config.h>
#undef MBEDTLS_PLATFORM_C
#include <mbedtls/platform_util.h>
#include <mbedtls/sha512.h>
#include "../sha512.c"
