/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Ultravisor calls.
 *
 * Copyright 2018, IBM Corporation.
 *
 */
#ifndef UC_H
#define UC_H

/* internal error Values */
#define U_BUSY	-2
#define U_HARDWARE  -6
#define U_UNSUPPORTED -7
#define U_WRONG_STATE	-14
#define U_XSCOM_CHIPLET_OFF	U_WRONG_STATE
#define U_XSCOM_PARTIAL_GOOD -25
#define U_XSCOM_ADDR_ERROR -26
#define U_XSCOM_CLOCK_ERROR -27
#define U_XSCOM_PARITY_ERROR -28
#define U_XSCOM_TIMEOUT -29
#define U_XSCOM_BUSY U_BUSY

#include <uapi_uvcall.h>
#include <context.h>
#include <svm_host.h>

extern int syscall_ultracall(u64 function, struct stack_frame *stack);
extern int uv_e00_handle(struct stack_frame *stack, gpa_t gpa);

#endif /* #ifndef UC_H */
