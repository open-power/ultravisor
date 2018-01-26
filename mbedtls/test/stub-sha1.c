
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MBEDTLS_SELF_TEST

#include <mbedtls/config.h>
#undef MBEDTLS_PLATFORM_C
#include <mbedtls/platform_util.h>
#define MBEDTLS_SHA1_C
#include <mbedtls/sha1.h>
#include "./sha1.c"
