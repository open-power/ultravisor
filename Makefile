# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# If you want to build in another directory copy this file there and
# fill in the following values

#
# Prefix of cross toolchain, if anything
# Example: CROSS= powerpc64-unknown-linux-gnu-
#
ARCH = $(shell uname -m)
ifdef CROSS_COMPILE
	CROSS ?= $(CROSS_COMPILE)
endif
ifneq ("$(ARCH)", "ppc64")
ifneq ("$(ARCH)", "ppc64le")
ifneq ($(shell which powerpc64-linux-gcc 2> /dev/null),)
	CROSS ?= powerpc64-linux-
endif
ifneq ($(shell which powerpc64-linux-gnu-gcc 2> /dev/null),)
	CROSS ?= powerpc64-linux-gnu-
endif
endif
endif

#
# Main debug switch
#
DEBUG ?= 0

# Run tests under valgrind?
USE_VALGRIND ?= 1

#
# Optional location of embedded linux kernel file
# This can be a raw vmlinux, stripped vmlinux or
# zImage.epapr
#
KERNEL ?=

#
# Optional build with advanced stack checking
#
STACK_CHECK ?= $(DEBUG)

#
# Experimental (unsupported) build options
#
# Little-endian does not yet build. Include it here to set ELF ABI.
LITTLE_ENDIAN ?= 0
# ELF v2 ABI is more efficient and compact
ELF_ABI_v2 ?= $(LITTLE_ENDIAN)
# Discard unreferenced code and data at link-time
DEAD_CODE_ELIMINATION ?= 0

#
# Where is the source directory, must be a full path (no ~)
# Example: SRC= /home/me/skiboot
#
SRC=$(CURDIR)

#
# Where to get information about this machine (subdir name)
#
#DEVSRC=hdata

#
# default config file, see include config_*.h for more specifics
#
CONFIG := config.h

#
# sfake 
#
TARGET = ultra

TARGET_DIRS = $(SRC)/asm $(SRC)/ccan $(SRC)/core $(SRC)/libc \
	$(SRC)/platforms $(SRC)/libfdt $(SRC)/svm \
	$(SRC)/lib $(SRC)/mbedtls $(SRC)/uv $(SRC)/tss $(SRC)/libstb

OBJS = $(ASM) $(CORE) $(PLATFORMS) $(LIBFDT) $(SVM)
OBJS += $(LIBC) $(CCAN) $(MAIN_MENU) $(LIBCRYPTO) $(LIB)
OBJS += $(MBEDTLS) $(UV) $(TSS)

CLEAN_FILES = *.lis

include $(SRC)/Makefile.main

doxygen:
	doxygen doc/doxygen.cfg

%.lst: %.elf
	$(call Q,OBJDUMP, $(OBJDUMP) -d -S $< > $@, $@)

