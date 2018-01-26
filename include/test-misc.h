/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2020 IBM Corp.  */

#include <assert.h>

#ifndef TEST_MISC_H
#define TEST_MISC_H


#define	plan_tests(x)
#define	ok1(x)		assert(x)
#define	ok(x, ...)	assert(x)
#define	fail(x, ...)	assert(0)
#define exit_status() (0)

#endif
