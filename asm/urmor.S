// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2018 IBM Corp.
 */

#include <asm-utils.h>
#include <asm-offsets.h>
#include <processor.h>
#include <ppc-opcode.h>

	.section ".text","ax"
	.balign	0x10

/**
 * @brief Functions for updating URMOR.
 *
 * Functions to support the update sequence for URMOR based on steps described
 * in section 4.9.7 of the POWER9 User Manual.
 *
 */

/**
 * @brief Entry for primary thread.
 *
 * @param r3 Contains EA[0] value to bypass URMOR.
 * @param r4 Contains URMOR value.
 */
.global __urmor_update_pri
__urmor_update_pri:
	ld	%r3,0(%r3)
	LOAD_ADDR_FROM_TOC(%r12, __urmor_update_reg)
	or	%r3,%r3,%r12
	mtctr	%r3
	bctr

.global __urmor_update_reg
__urmor_update_reg:
        /* Set URMOR */
        mtspr   SPR_URMOR,%r4
	isync
	PPC_INVALIDATE_ERAT
	isync
	blr

/**
 * @brief Entry for secondary thread(s).
 *
 * @param r3 Contains EA[0] value to bypass URMOR
 */
.global __urmor_update_sec
__urmor_update_sec:
	ld	%r3,0(%r3)
	LOAD_ADDR_FROM_TOC(%r12, __urmor_update_sec_sync)
	or	%r3,%r3,%r12
	mtctr	%r3
	bctr

.global __urmor_update_sec_sync
__urmor_update_sec_sync:
	li	%r12,1
	stb     %r12,CPUTHREAD_URMOR_UP(%r13)
	sync
	LOAD_ADDR_FROM_TOC(%r12, cpu_urmor_updated)
1:	smt_lowest
	ld      %r11,0(%r12)
	cmpdi   %r11,0
	beq	1b

	smt_medium

	isync
	PPC_INVALIDATE_ERAT
	isync
	blr

