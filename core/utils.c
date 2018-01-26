// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp.  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <logging.h>
#include <console.h>
#include <compiler.h>
#include <mem-map.h>
#include <mem_region.h>
#include <utils.h>
#include <lock.h>
#include <processor.h>
#include <cpu.h>
#include <stack.h>

void __noreturn assert_fail(const char *msg)
{
	/**
	 * @fwts-label FailedAssert
	 * @fwts-advice OPAL hit an assert(). During normal usage (even
	 * testing) we should never hit an assert. There are other code
	 * paths for controlled shutdown/panic in the event of catastrophic
	 * errors.
	 */
	prlog(PR_EMERG, "Assert fail: %s\n", msg);
	_abort(msg);
}

void __noreturn _abort(const char *msg)
{
	static bool in_abort = false;

	if (in_abort)
		for (;;) ;
	in_abort = true;

	prlog(PR_EMERG, "Aborting!\n");
	backtrace();
	console_stoplog();

	prlog(PR_EMERG, "Abort: %s\n", msg);

	for (;;) ;
}

char __attrconst tohex(uint8_t nibble)
{
	static const char __tohex[] = {'0','1','2','3','4','5','6','7','8','9',
				       'A','B','C','D','E','F'};
	if (nibble > 0xf)
		return '?';
	return __tohex[nibble];
}

static unsigned long get_symbol(unsigned long addr, char **sym, char **sym_end)
{
	unsigned long prev = 0, next;
	char *psym = NULL, *p = __sym_map_start;

	*sym = *sym_end = NULL;
	while(p < __sym_map_end) {
		next = strtoul(p, &p, 16) | ultra_base;
		if (next > addr && prev <= addr) {
			p = psym + 3;;
			if (p >= __sym_map_end)
				return 0;
			*sym = p;
			while(p < __sym_map_end && *p != 10)
				p++;
			*sym_end = p;
			return prev;
		}
		prev = next;
		psym = p;
		while(p < __sym_map_end && *p != 10)
			p++;
		p++;
	}
	return 0;
}

size_t snprintf_symbol(char *buf, size_t len, uint64_t addr)
{
	unsigned long saddr;
	char *sym, *sym_end;
	size_t l;

	saddr = get_symbol(addr, &sym, &sym_end);
	if (!saddr)
		return 0;

	if (len > sym_end - sym)
		l = sym_end - sym;
	else
		l = len - 1;
	memcpy(buf, sym, l);

	/*
	 * This snprintf will insert the terminating NUL even if the
	 * symbol has used up the entire buffer less 1.
	 */
	l += snprintf(buf + l, len - l, "+0x%llx", addr - saddr);

	return l;
}
