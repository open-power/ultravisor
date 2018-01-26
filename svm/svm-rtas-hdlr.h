/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SVM RTAS Handlers
 *
 * Copyright 2019, IBM Corporation.
 *
 */

#ifndef SVM_RTAS_HDLR_H
#define SVM_RTAS__HDLR_H

#include <svm_host.h>

typedef __be32 rtas_arg_t;

struct rtas_args {
	__be32 token;
	__be32 nargs;
	__be32 nret;
	rtas_arg_t args[16];
	rtas_arg_t *rets;
};

enum rtas_hdlr_ret {
	RTAS_HDLR_NONE = -2, /**< No token specific handler defined. */
	RTAS_HDLR_ERR, /**< Handler failed. */
	RTAS_HDLR_OK, /**< Handler completed successfully. */
};

enum rtas_hdlr_type {
	RTAS_HDLR_PRE = 1, /**< Pre handler. */
	RTAS_HDLR_POST, /**< Post handler. */
};

struct svm_rtas_hdlr {
	__be32 token;
	const char *service;
	enum rtas_hdlr_ret (*handler)(enum rtas_hdlr_type type,
				      struct svm *svm,
				      struct rtas_args *guest_args,
				      struct rtas_args *bb_args);
	bool optional;
};

extern struct svm_rtas_hdlr svm_rtas_hdlrs[];

#endif /* SVM_RTAS_HDLR_H */
