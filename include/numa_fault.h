/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NUMA faults
 *
 * Copyright 2019, IBM Corporation.
 *
 */
#ifndef __NUMA_FAULT_H
#define __NUMA_FAULT_H

#ifdef NUMA_STATISTIC
#include <lock.h>
#include <cpu.h>
#include <timebase.h>

/*
 * When a SVM is starting we don't start to invalidate access to the page to
 * compute the NUMA statistics immediately. We let the SVM run a bit before
 * starting the job.
 * Set this initial delay to 60s.
 */
#define NUMA_FAULT_INITIAL_DELAY 60ULL

/*
 * Once the initial delay is expired, a set of secured pages are invalidated on
 * a periodic way.
 * Set this timer to 10s.
 */
#define NUMA_FAULT_DELAY 10ULL

extern int numa_fault(struct svm *svm, gpa_t gpa);

extern void numa_task(struct svm *svm);

static inline void numa_fault_init(struct svm *svm)
{
	init_lock(&svm->numa_fault.lock);
	svm->numa_fault.delay = secs_to_tb(NUMA_FAULT_INITIAL_DELAY);
	/* Initialise the last_tb field to the current timebase register */
	svm->numa_fault.last_tb = mftb();
}

#endif /* NUMA_STATISTIC */
#endif /* __NUMA_FAULT_H */
