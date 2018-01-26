# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
# Copyright 2012-2019 IBM Corp
# -*-Makefile-*-

SUBDIRS += asm 
ASM_OBJS = head.o misc.o urmor.o
ASM=asm/built-in.a

$(ASM): $(ASM_OBJS:%=asm/%)

