// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2018 IBM Corp.
 */

#define pr_fmt(fmt) "URMOR: " fmt

#include <chip.h>
#include <cpu.h>
#include <inttypes.h>
#include <logging.h>
#include <processor.h>
#include <stdlib.h>
#include <urmor.h>

uint64_t cpu_urmor_updated;

extern void __urmor_update_pri(uint64_t *ea, uint64_t urmor);
extern void __urmor_update_reg(void);

struct urmor_pri_data {
	uint64_t bypass_urmor;
	uint64_t urmor;
};

static void urmor_update_pri(void *data)
{
	struct urmor_pri_data *pri_data = (struct urmor_pri_data *)data;
	__urmor_update_pri(&pri_data->bypass_urmor, pri_data->urmor);
}

extern void __urmor_update_sec(uint64_t *ea);
extern void __urmor_update_sec_sync(void);

static void urmor_update_sec(void *data)
{
	uint64_t *bypass_urmor = (uint64_t *)data;
	__urmor_update_sec(bypass_urmor);
}

#define NIMBUS_URMOR_ADJ 0x7C800000UL

void urmor_update(void)
{
	struct cpu_thread *cpu;
	struct cpu_job **jobs;
	struct urmor_pri_data pri_data;
	uint64_t bypass_urmor = PPC_BIT(0);
	uint64_t urmor;
	int i = 0;
	int pvr;

	jobs = zalloc(sizeof(struct cpu_job *) * cpu_max_pir);

	pr_info("Updating URMOR\n");

	urmor = mfspr(SPRG_UVSCRATCH0);

	pvr = mfspr(SPR_PVR);

	if (PVR_TYPE(pvr) == PVR_TYPE_P9) {
		urmor = urmor - NIMBUS_URMOR_ADJ;
		pr_notice("Nimbus URMOR Adjustment applied\n");
	}

	pri_data.bypass_urmor = bypass_urmor;
	pri_data.urmor = urmor;

	for_each_available_cpu (cpu) {
		if (cpu_is_thread0(cpu))
			continue;

		jobs[i++] = cpu_queue_job(cpu, "urmor_update_sec",
					  urmor_update_sec, &bypass_urmor);
	}

	for_each_available_cpu (cpu) {
		if (cpu_is_thread0(cpu))
			continue;
		while (!cpu->in_urmor_update) {
			cpu_relax();
		}
		pr_info_once("PIR %d in_urmor_update\n", cpu->pir);
	}

	for_each_available_cpu (cpu) {
		if (!cpu_is_thread0(cpu))
			continue;
		if (cpu == this_cpu()) {
			urmor_update_pri(&pri_data);
			continue;
		}
		cpu_wait_job(cpu_queue_job(cpu, "urmor_update_pri",
					   urmor_update_pri, &pri_data),
			     true);
	}

	cpu_urmor_updated = 1;
	sync();

	while (i > 0) {
		cpu_wait_job(jobs[--i], true);
	}
	free(jobs);
}

void urmor_secondary_setup(struct cpu_thread *cpu)
{
	while (true) {
		if (cpu_check_jobs(cpu)) {
			cpu_process_jobs();
		}

		sync();
		if (cpu_urmor_updated) {
			break;
		}

		cpu_relax();
	}
}
