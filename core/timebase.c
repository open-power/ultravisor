// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp.  */

#include <timebase.h>
#include <cpu.h>
#include <chip.h>
#include <logging.h>

unsigned long tb_hz = 512000000;
bool tb_hz_set = false;

static void time_wait_poll(unsigned long duration)
{
	unsigned long now = mftb();
	unsigned long end = now + duration;
	unsigned long period = msecs_to_tb(5);

	if (this_cpu()->tb_invalid) {
		cpu_relax();
		return;
	}

	while (tb_compare(now, end) != TB_AAFTERB) {
		unsigned long remaining = end - now;

		/*
		 * Call pollers periodically but not continually to avoid
		 * bouncing cachelines due to lock contention.
		 */
		if (remaining >= period) {
			time_wait_nopoll(period);
			remaining -= period;
		} else
			time_wait_nopoll(remaining);

		now = mftb();
	}
}

void time_wait(unsigned long duration)
{
	struct cpu_thread *c = this_cpu();

	if (!list_empty(&this_cpu()->locks_held)) {
		time_wait_nopoll(duration);
		return;
	}

	if (c != boot_cpu)
		time_wait_nopoll(duration);
	else
		time_wait_poll(duration);
}

void time_wait_nopoll(unsigned long duration)
{
	if (this_cpu()->tb_invalid) {
		cpu_relax();
		return;
	}

	cpu_idle_delay(duration);
}

void time_wait_ms(unsigned long ms)
{
	time_wait(msecs_to_tb(ms));
}

void time_wait_ms_nopoll(unsigned long ms)
{
	time_wait_nopoll(msecs_to_tb(ms));
}

void time_wait_us(unsigned long us)
{
	time_wait(usecs_to_tb(us));
}

void time_wait_us_nopoll(unsigned long us)
{
	time_wait_nopoll(usecs_to_tb(us));
}

unsigned long timespec_to_tb(const struct timespec *ts)
{
	unsigned long ns;

	/* First convert to ns */
	ns = ts->tv_sec * 1000000000ul;
	ns += ts->tv_nsec;

	/*
	 * This is a very rough approximation, it works provided
	 * we never try to pass too long delays here and the TB
	 * frequency isn't significantly lower than 512Mhz.
	 *
	 * We could improve the precision by shifting less bits
	 * at the expense of capacity or do 128 bit math which
	 * I'm not eager to do :-)
	 */
	if (chip_quirk(QUIRK_SLOW_SIM))
		return (ns * (tb_hz >> 16)) / (1000000000ul >> 16);
	else
		return (ns * (tb_hz >> 24)) / (1000000000ul >> 24);
}

int nanosleep(const struct timespec *req, struct timespec *rem)
{
	time_wait(timespec_to_tb(req));

	if (rem) {
		rem->tv_sec = 0;
		rem->tv_nsec = 0;
	}
	return 0;
}

int nanosleep_nopoll(const struct timespec *req, struct timespec *rem)
{
	time_wait_nopoll(timespec_to_tb(req));

	if (rem) {
		rem->tv_sec = 0;
		rem->tv_nsec = 0;
	}
	return 0;
}

void set_tb_frequency(unsigned long frequency)
{
	if (!tb_hz_set) {
		tb_hz = frequency;
		tb_hz_set = true;
		pr_info("CPU: timebase-frequency=%lu\n", tb_hz);
		return;
	}

	if (frequency != tb_hz)
		pr_error("timebase-frequency discrepancy detected: %lu != %lu\n",
			 tb_hz, frequency);
}
