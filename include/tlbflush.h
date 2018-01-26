/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TLB FLUSH
 *
 * Copyright 2018, IBM Corporation.
 *
 */

#ifndef TLBFLUSH_H
#define TLBFLUSH_H

#include <svm_host.h>

#define RIC_FLUSH_TLB 0
#define RIC_FLUSH_PWC 1
#define RIC_FLUSH_ALL 2
void _tlbie_lpid_gpa(gpa_t gpa, unsigned long lpid,
			unsigned long psize, unsigned long ric);

struct tlb_flush {
	u64 lpid;
	gpa_t gpa;
};

#endif /* TLBFLUSH_H */
