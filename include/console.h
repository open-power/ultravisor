// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp.  */

#ifndef __CONSOLE_H
#define __CONSOLE_H

#include <unistd.h>
#include <stdint.h>
#include <lock.h>

/*
 * Our internal console uses the format of BML new-style in-memory
 * console and supports input for setups without a physical console
 * facility or FSP.
 *
 * (This is v3 of the format, the previous one sucked)
 */
struct memcons {
	uint64_t magic;
#define MEMCONS_MAGIC	0x6630696567726173LL
	uint64_t obuf_phys;
	uint64_t ibuf_phys;
	uint32_t obuf_size;
	uint32_t ibuf_size;
	uint32_t out_pos;
#define MEMCONS_OUT_POS_WRAP	0x80000000u
#define MEMCONS_OUT_POS_MASK	0x00ffffffu
	uint32_t in_prod;
	uint32_t in_cons;
};

extern struct memcons __memcons;

#define INMEM_CON_IN_LEN	16
#define INMEM_CON_OUT_LEN	(INMEM_CON_LEN - INMEM_CON_IN_LEN)

/* Console driver */
struct con_ops {
	size_t (*write)(const char *buf, size_t len);
	size_t (*read)(char *buf, size_t len);
	bool (*poll_read)(void);
};


extern bool flush_console(void);

extern void set_console(struct con_ops *driver);

extern void console_complete_flush(void);

extern size_t mambo_console_write(const char *buf, size_t count);
extern void enable_mambo_console(void);

ssize_t console_write(bool flush_to_drivers, const void *buf, size_t count);

extern void init_console(void *console);

void console_stoplog(void);

void mprintf(const char *fmt, ...);

#endif /* __CONSOLE_H */
