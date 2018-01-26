// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp.  */

#undef DEBUG
#define pr_fmt(fmt) "INIT: " fmt

#include <stdio.h>
#include <logging.h>
#include <stdlib.h>
#include <inttypes.h>
#include <version.h>
#include <numa.h>
#include <cpu.h>
#include <processor.h>
#include <io.h>
#include <device.h>
#include <chip.h>
#include <mem_region.h>
#include <console.h>
#include <libfdt/libfdt.h>
#include <mmu.h>
#include <urmor.h>
#include <xscom.h>
#include <utils.h>
#include <hvcall.h>
#include <opal-ultravisor-api.h>
#include <uv/uv-crypto.h>
#include <uv/uv-xscom-bwlist.h>
#include <sbe-chipops.h>

//#define DEBUG
#ifdef DEBUG
#define init_dprintf(fmt...)                                                   \
	do {                                                                   \
		printf(fmt);                                                   \
	} while (0)
#else
#define init_dprintf(fmt...)                                                   \
	do {                                                                   \
	} while (0)
#endif

enum proc_gen proc_gen;

struct debug_descriptor debug_descriptor = {
	.eye_catcher	= "OPALdbug",
	.version	= DEBUG_DESC_VERSION,
	.state_flags	= 0,
	.memcons_phys	= 0,
	.trace_mask	= 0, /* All traces disabled by default */
	/* console log level:
	 *   high 4 bits in memory, low 4 bits driver (e.g. uart). */
#ifdef DEBUG
	.console_log_levels = (PR_DEBUG << 4) | PR_DEBUG,
#else
	.console_log_levels = (PR_DEBUG << 4) | PR_INFO,
#endif
};


struct opal {
	uint64_t base;
	uint64_t entry;
} opal;

typedef void (*ctorcall_t)(void);

static void __nomcount do_ctors(void)
{
	extern ctorcall_t __ctors_start[], __ctors_end[];
	ctorcall_t *call;

	for (call = __ctors_start; call < __ctors_end; call++)
		(*call)();
}

static void per_thread_sanity_checks(void)
{
	struct cpu_thread *cpu = this_cpu();

	/**
	 * @fwts-label NonZeroHRMOR
	 * @fwts-advice The contents of the hypervisor real mode offset register
	 * (HRMOR) is bitwise orded with the address of any hypervisor real mode
	 * (i.e Skiboot) memory accesses. Skiboot does not support operating
	 * with a non-zero HRMOR and setting it will break some things (e.g
	 * XSCOMs) in hard-to-debug ways.
	 */
	assert(mfspr(SPR_HRMOR) == 0);

	/**
	 * @fwts-label UnknownSecondary
	 * @fwts-advice The boot CPU attampted to call in a secondary thread
	 * without initialising the corresponding cpu_thread structure. This may
	 * happen if the HDAT or devicetree reports too few threads or cores for
	 * this processor.
	 */
	assert(cpu->state != cpu_state_no_cpu);
}

/*
 * Generate a 32-bit random number (start-cpu RTAS call can only
 * take a 32-bit cookie).
 */
uint64_t generate_random_number(void)
{
	uint32_t i;
	uint64_t num;
	uint8_t buffer[64];

	uv_crypto_rand_bytes(buffer, sizeof(buffer));

	num = 0ULL;
	for (i = 0; i < 4; i++)
		num = (num << 8) | buffer[i];

	return num;
}

/* @todo: sync and remove multiple defined versions of __va */
#define __va(x) ((void *)(u64)((u64)(x) | PPC_BIT(0)))

/* Called from head.S, thus no prototype. */
int uv_main_cpu_entry(const struct uv_opal *opal_data);

int __nomcount uv_main_cpu_entry(const struct uv_opal *opal_data)
{
	int rc = 0;

	mem_region_early_init();

	/*
	 * The current cpu_thread() struct is not initialized
	 * either so we need to clear it out first thing first (without
	 * putting any other useful info in there jus yet) otherwise
	 * printf an locks are going to play funny games with "con_suspend"
	 */
	pre_init_boot_cpu();

	/*
	 * Before first printk, ensure console buffer is clear or
	 * reading tools might think it has wrapped
	 */
	init_console(__va((u64)opal_data->uv_mem));

	/* Call library constructors */
	do_ctors();

	pr_notice("ULTRA %s starting...\n", version);
	pr_debug("initial console log level: memory %d, driver %d\n",
		 (debug_descriptor.console_log_levels >> 4),
		 (debug_descriptor.console_log_levels & 0x0f));
	prlog(PR_TRACE, "You will not see this\n");

	/* Initialize boot cpu's cpu_thread struct */
	init_boot_cpu();
	/* Now locks can be used */
	init_locks();

	rc = uv_crypto_wrap_key_init((void *)opal_data->uv_fdt);
	/* Zero passed in fdt */
	memset((void *)opal_data->uv_fdt, 0,
	       fdt_totalsize((void *)opal_data->uv_fdt));
	if (rc)
		goto out;

	/* we are coming in with a flat device-tree, we expand it now. */
	dt_root = dt_new_root("");
	dt_expand((void *)opal_data->sys_fdt);

	/* Now that we have a full devicetree, verify that we aren't on fire. */
	per_thread_sanity_checks();

	init_chips();

	/* Init xscom */
	xscom_init();

	 /*
         * This should be done before mem_region_init, so the stack
         * region length can be set according to the maximum PIR.
         */
        init_cpu_max_pir();
        numa_find_min_common_depth();

	/*
	 * Now, we init our memory map from the device-tree, and immediately
	 * reserve areas which we know might contain data coming from
	 * HostBoot. We need to do these things before we start doing
	 * allocations outside of our heap, such as chip local allocs,
	 * otherwise we might clobber those data.
	 */
	mem_region_init();

	init_hcall_regs_map();

	/*
	 * Initialize the security Access Tables with data from the UVBWLIST
	 * reserved memory
	 */
	securityAccessTablesInit();

	/* Initialize the rest of the cpu thread structs */
	init_all_cpus();

	radix__early_init_mmu();

	cpu_bringup();

	uv_crypto_init();

	urmor_update();

	mtspr(SPR_USRR1, mfmsr() & ~MSR_S);

	sbe_init();

out:
	return rc;
}

static void __secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	/* Secondary CPU called in */
	cpu_callin(cpu);

	radix__early_init_mmu_secondary();

	mtspr(SPR_USRR1, mfmsr() & ~MSR_S);

	urmor_secondary_setup(cpu);
}

/* Called from head.S, thus no prototype. */
void secondary_cpu_entry(void);

void  secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	per_thread_sanity_checks();

	pr_debug("INIT: CPU PIR 0x%04x called in\n", cpu->pir);

	__secondary_cpu_entry();
}
