/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM Internal Support
 *
 * Copyright 2018, IBM Corporation.
 *
 */

#ifndef SVM_SVM_INTERNAL_H
#define SVM_SVM_INTERNAL_H

#include <device.h>
#include <context.h>
#include <uapi_uvcall.h>
#include <svm_host.h>
#include <svm/svm-fdt.h>

struct svm_ops {
	const char	*name;
	int64_t	(*fdt_upd_hdlr)(struct refl_state *r_state);
};

extern struct svm_ops __svm_ops_start;
extern struct svm_ops __svm_ops_end;

#define DECLARE_SVM_OPS(name)\
  static const struct svm_ops __used __section(".svm_ops") name ##_ops

#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

#endif /* SVM_SVM_INTERNAL_H */
