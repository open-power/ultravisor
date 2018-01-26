// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp.  */

/*
 * Console IO routine for use by libc
 *
 * fd is the classic posix 0,1,2 (stdin, stdout, stderr)
 */
#include <unistd.h>
#include <stdio.h>
#include <logging.h>
#include <ccan/str/str.h>
#include <console.h>
#include <device.h>
#include <processor.h>
#include <cpu.h>
#include <mem_region.h>

static char *con_buf;
static size_t con_in;
static size_t con_out;
static bool con_wrapped;

/* Internal console driver ops */
static struct con_ops *con_driver;

static struct lock con_lock = LOCK_UNLOCKED;

struct memcons *memcons;

static void clear_console(void)
{
	memset(con_buf, 0, memcons->obuf_size);
}

#define __va(x) ((void *)(u64)((u64)(x) | PPC_BIT(0)))

void init_console(void *console)
{
	memcons = (struct memcons *) console;

	memcons->obuf_phys = (u64) __va((u64)memcons->obuf_phys);
	memcons->ibuf_phys = (u64) __va((u64)memcons->ibuf_phys);

	con_buf = (char *) memcons->obuf_phys;

	clear_console();
}

/*
 * Flush the console buffer into the driver, returns true
 * if there is more to go.
 * Optionally can skip flushing to drivers, leaving messages
 * just in memory console.
 */
static bool __flush_console(bool flush_to_drivers)
{
	struct cpu_thread *cpu = this_cpu();
	size_t req, len = 0;
	static bool in_flush, more_flush;

	/* Is there anything to flush ? Bail out early if not */
	if (con_in == con_out || !con_driver)
		return false;

	/*
	 * Console flushing is suspended on this CPU, typically because
	 * some critical locks are held that would potentially cause a
	 * flush to deadlock
	 */
	if (cpu->con_suspend) {
		cpu->con_need_flush = true;
		return false;
	}
	cpu->con_need_flush = false;

	/*
	 * We must call the underlying driver with the console lock
	 * dropped otherwise we get some deadlocks if anything down
	 * that path tries to printf() something.
	 *
	 * So instead what we do is we keep a static in_flush flag
	 * set/released with the lock held, which is used to prevent
	 * concurrent attempts at flushing the same chunk of buffer
	 * by other processors.
	 */
	if (in_flush) {
		more_flush = true;
		return false;
	}
	in_flush = true;

	/*
	 * NB: this must appear after the in_flush check since it modifies
	 *     con_out.
	 */
	if (!flush_to_drivers) {
		con_out = con_in;
		in_flush = false;
		return false;
	}

	do {
		more_flush = false;

		if (con_out > con_in) {
			req = memcons->obuf_size - con_out;
			more_flush = true;
		} else
			req = con_in - con_out;

		unlock(&con_lock);
		len = con_driver->write(con_buf + con_out, req);
		lock(&con_lock);

		con_out = (con_out + len) % memcons->obuf_size;

		/* write error? */
		if (len < req)
			break;
	} while(more_flush);

	in_flush = false;
	return con_out != con_in;
}

bool flush_console(void)
{
	bool ret;

	lock(&con_lock);
	ret = __flush_console(true);
	unlock(&con_lock);

	return ret;
}

static void inmem_write(char c)
{
	uint32_t opos;

	if (!c)
		return;
	con_buf[con_in++] = c;
	if (con_in >= memcons->obuf_size) {
		con_in = 0;
		con_wrapped = true;
	}

	/*
	 * We must always re-generate memcons.out_pos because
	 * under some circumstances, the console script will
	 * use a broken putmemproc that does RMW on the full
	 * 8 bytes containing out_pos and in_prod, thus corrupting
	 * out_pos
	 */
	opos = con_in;
	if (con_wrapped)
		opos |= MEMCONS_OUT_POS_WRAP;
	lwsync();
	memcons->out_pos = opos;

	/* If head reaches tail, push tail around & drop chars */
	if (con_in == con_out)
		con_out = (con_in + 1) % memcons->obuf_size;
}

static size_t inmem_read(char *buf, size_t req)
{
	size_t read = 0;
	char *ibuf = (char *)memcons->ibuf_phys;

	while (req && memcons->in_prod != memcons->in_cons) {
		*(buf++) = ibuf[memcons->in_cons];
		lwsync();
		memcons->in_cons = (memcons->in_cons + 1) % memcons->obuf_size;
		req--;
		read++;
	}
	return read;
}

static void write_char(char c)
{
#ifdef MAMBO_DEBUG_CONSOLE
	mambo_console_write(&c, 1);
#endif
	inmem_write(c);
}

static bool log_blocked = false;

void console_stoplog(void)
{
	bool need_unlock = lock_recursive(&con_lock);

	log_blocked = true;
	__flush_console(true);

	if (need_unlock)
		unlock(&con_lock);
}

ssize_t console_write(bool flush_to_drivers, const void *buf, size_t count)
{
	/* We use recursive locking here as we can get called
	 * from fairly deep debug path
	 */
	bool need_unlock = lock_recursive(&con_lock);
	const char *cbuf = buf;

	if (log_blocked)
		goto out;

	while(count--) {
		char c = *(cbuf++);
		if (c == '\n')
			write_char('\r');
		write_char(c);
	}

	__flush_console(flush_to_drivers);

out:
	if (need_unlock)
		unlock(&con_lock);

	return count;
}

ssize_t write(int fd __unused, const void *buf, size_t count)
{
	return console_write(true, buf, count);
}

ssize_t read(int fd __unused, void *buf, size_t req_count)
{
	bool need_unlock = lock_recursive(&con_lock);
	size_t count = 0;

	if (con_driver && con_driver->read)
	count = con_driver->read(buf, req_count);
	if (!count)
	count = inmem_read(buf, req_count);
	if (need_unlock)
		unlock(&con_lock);
	return count;
}

/*
 * set_console()
 *
 * This sets the driver used internally by Skiboot. This is different to the
 * OPAL console driver.
 */
void set_console(struct con_ops *driver)
{
	con_driver = driver;
	if (driver)
		flush_console();
}

