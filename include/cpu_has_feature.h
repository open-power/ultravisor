/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM Hosts
 *
 * Copyright 2018, IBM Corporation.
 *
 */
#ifndef CPU_HAS_FEATURE_H
#define CPU_HAS_FEATURE_H

#define LONG_ASM_CONST(x)	x
#define CPU_FTR_HVMODE		LONG_ASM_CONST(0x0000000100000000)
#define CPU_FTR_P9_TLBIE_BUG	LONG_ASM_CONST(0x0000400000000000)

static inline bool cpu_has_feature(u64 feature)
{
	if (CPU_FTR_HVMODE & feature)
		return true;

	return false;
}

#endif /* CPU_HAS_FEATURE_H */
