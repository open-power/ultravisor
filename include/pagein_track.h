/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * PAGEIN TRACK
 *
 * Copyright 2020, IBM Corporation.
 *
 */

#ifndef PAGEIN_TRACK_H
#define PAGEIN_TRACK_H

extern int init_pagein_tracking(struct svm *svm);
extern void destroy_pagein_tracking(struct svm *svm);
#ifndef __TEST__
extern void *get_page_range(struct refl_state *rstate, gpa_t gpa, u64 len);
#else
static inline void *get_page_range(struct refl_state *r_state, gpa_t gpfdt,
			u64 UNUSED(len))
{
	return gpa_to_addr(&r_state->svm->mm, gpfdt, NULL);
}

#endif

#endif /* PAGEIN_TRACK_H */
