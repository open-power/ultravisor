/* Copyright 2013-2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: GPL-2.0
 * Copyright 2020 IBM Corp.
 */

#ifndef __CPU_H
#define __CPU_H

#include <processor.h>
#include <ccan/list/list.h>
#include <lock.h>
#include <device.h>
#include <stack.h>
/*
 * cpu_thread is our internal structure representing each
 * thread in the system
 */

enum cpu_thread_state {
	cpu_state_no_cpu	= 0,	/* Nothing there */
	cpu_state_unknown,		/* In PACA, not called in yet */
	cpu_state_unavailable,		/* Not available */
	cpu_state_present,		/* Assumed to spin in asm entry */
	cpu_state_active,		/* Secondary called in */
	cpu_state_os,			/* Under OS control */
	cpu_state_disabled,		/* Disabled by us due to error */
	cpu_state_rvwinkle,		/* Doing an rvwinkle cycle */
};

struct cpu_job;
struct xive_cpu_state;

struct vcpu {
	/*
	 * The SVM to which this vcpu belongs. It's not strictly necessary to
	 * store it here (a CPU can run only one SVM at a time), but we use it
	 * to verify that we're in a consistent state.
	 */
	uint32_t lpid;

	/* Set to UINT_MAX when not running any vcpu. */
	uint32_t vcpuid;
};

/*
 * Conveys that the hardware CPU isn't currently running on behalf of any guest
 * vcpu.
 */
static inline void invalidate_vcpuid(struct vcpu *vcpu)
{
	vcpu->vcpuid = vcpu->lpid = UINT_MAX;
}

struct cpu_thread {
	/*
	 * "stack_guard" must be at offset 0 to match the
	 * -mstack-protector-guard-offset=0 statement in the Makefile
	 */
	uint64_t			stack_guard;
	uint32_t			pir;
	uint32_t			server_no;
	uint32_t			chip_id;
	int32_t				numa_node_id;
	bool				is_secondary;
	struct cpu_thread		*primary;
	enum cpu_thread_state		state;
	struct dt_node			*node;
	struct trace_info		*trace;
	uint64_t			save_r1;
	uint64_t			save_r2;
	uint64_t			save_msr;
	uint32_t			con_suspend;
	struct list_head		locks_held;
	bool				con_need_flush;
	bool				in_mcount;
	bool				in_idle;
	bool				in_urmor_update;
	uint64_t			current_token;
#ifdef STACK_CHECK_ENABLED
	int64_t				stack_bot_mark;
	uint64_t			stack_bot_pc;
	uint64_t			stack_bot_tok;
#define CPU_BACKTRACE_SIZE	60
	struct bt_entry			stack_bot_bt[CPU_BACKTRACE_SIZE];
	unsigned int			stack_bot_bt_count;
#endif
	struct lock			job_lock;
	struct list_head		job_queue;
	uint32_t			job_count;
	bool				job_has_no_return;
	bool				tb_invalid;

	/* Which guest vcpu we are currently running. */
	struct vcpu			vcpu;

#ifdef DEBUG_LOCKS
	/* The lock requested by this cpu, used for deadlock detection */
	struct lock			*requested_lock;
#endif
};

/* This global is set to 1 to allow secondaries to callin,
 * typically set after the primary has allocated the cpu_thread
 * array and stacks
 */
extern unsigned long cpu_secondary_start;

/* Max PIR in the system */
extern unsigned int cpu_max_pir;

/* Max # of threads per core */
extern unsigned int cpu_thread_count;

/* bit position of secure bit in a Real Address */
extern int secure_ra_bit;

/* Boot CPU. */
extern struct cpu_thread *boot_cpu;

static inline void __nomcount cpu_relax(void)
{
	/* Relax a bit to give sibling threads some breathing space */
	smt_lowest();
	asm volatile("nop; nop; nop; nop;\n"
		     "nop; nop; nop; nop;\n"
		     "nop; nop; nop; nop;\n"
		     "nop; nop; nop; nop;\n");
	smt_medium();
	barrier();
}

/* Initialize CPUs */
void pre_init_boot_cpu(void);
void init_boot_cpu(void);
void init_cpu_max_pir(void);
void init_all_cpus(void);

/* This brings up our secondaries */
extern void cpu_bringup(void);

/* This is called by secondaries as they call in */
extern void cpu_callin(struct cpu_thread *cpu);

/* Find CPUs using different methods */
extern struct __nomcount cpu_thread *find_cpu_by_pir_nomcount(u32 pir);

/* Iterator */
extern struct cpu_thread *first_cpu(void);
extern struct cpu_thread *next_cpu(struct cpu_thread *cpu);

static inline bool cpu_is_available(struct cpu_thread *cpu)
{
	return cpu->state == cpu_state_active ||
		cpu->state == cpu_state_rvwinkle;
}

extern struct cpu_thread *first_available_cpu(void);
extern struct cpu_thread *next_available_cpu(struct cpu_thread *cpu);

#define for_each_cpu(cpu)	\
	for (cpu = first_cpu(); cpu; cpu = next_cpu(cpu))

#define for_each_available_cpu(cpu)	\
	for (cpu = first_available_cpu(); cpu; cpu = next_available_cpu(cpu))

/* Return the caller CPU (only after init_cpu_threads) */
register struct cpu_thread *__this_cpu asm("r13");
static inline __nomcount struct cpu_thread *this_cpu(void)
{
	return __this_cpu;
}

static inline bool cpu_is_thread0(struct cpu_thread *cpu)
{
	return cpu->primary == cpu;
}

/* Allocate & queue a job on target CPU */
extern struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				       const char *name,
				       void (*func)(void *data), void *data,
				       bool no_return);

static inline struct cpu_job *cpu_queue_job(struct cpu_thread *cpu,
					    const char *name,
					    void (*func)(void *data),
					    void *data)
{
	return __cpu_queue_job(cpu, name, func, data, false);
}

/* Synchronously wait for a job to complete, this will
 * continue handling the FSP mailbox if called from the
 * boot CPU. Set free_it to free it automatically.
 */
extern void cpu_wait_job(struct cpu_job *job, bool free_it);

/* Called by init to process jobs */
extern void cpu_process_jobs(void);
/* Check if there's any job pending */
bool cpu_check_jobs(struct cpu_thread *cpu);

extern unsigned long __attrconst cpu_stack_bottom(unsigned int pir);
extern unsigned long __attrconst cpu_stack_top(unsigned int pir);

extern void cpu_idle_delay(unsigned long delay);

#endif /* __CPU_H */
