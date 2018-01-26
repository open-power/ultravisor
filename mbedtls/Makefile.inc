# -*-Makefile-*-

MBEDTLS_DIR = mbedtls

SUBDIRS += $(MBEDTLS_DIR)

MBEDTLS_SRCS = aes.c cipher.c cipher_wrap.c gcm.c hmac_drbg.c platform.c
MBEDTLS_SRCS += platform_util.c md.c md_wrap.c pkcs5.c sha256.c sha512.c
MBEDTLS_OBJS = $(MBEDTLS_SRCS:%.c=%.o)
MBEDTLS = $(MBEDTLS_DIR)/built-in.a

CFLAGS_SKIP_mbedtls/md.o=-Wsuggest-attribute=const

$(MBEDTLS): $(MBEDTLS_OBJS:%=$(MBEDTLS_DIR)/%)
