// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __TRACE_H
#define __TRACE_H
#include <ccan/short_types/short_types.h>
#include <stddef.h>
#include <lock.h>
#include <trace_types.h>

#define TBUF_SZ (1024 * 1024)

struct cpu_thread;

struct trace_info {
	/* Lock for writers. */
	struct lock lock;
	/* Exposed to kernel. */
	struct tracebuf tb;
};

/* Allocate trace buffers once we know memory topology */
void init_trace_buffers(void);

/* This will fill in timestamp and cpu; you must do type and len. */
void trace_add(union trace *trace, u8 type, u16 len);

/* Put trace node into dt. */
void trace_add_node(void);
#endif /* __TRACE_H */
