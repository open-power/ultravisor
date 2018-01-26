// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp.  */

#include <logging.h>
#include <compiler.h>
#include <stdlib.h>
#include <mem_region-malloc.h>
#include <misc.h>
#include <cpu.h>
#include <device.h>
#include <mem_region.h>
#include <stack.h>
#include <chip.h>
#include <timebase.h>
#include <numa.h>
#include <ccan/str/str.h>
#include <ccan/container_of/container_of.h>

/* The cpu_threads array is static and indexed by PIR in
 * order to speed up lookup from asm entry points
 */
struct cpu_stack {
	union {
		uint8_t	stack[STACK_SIZE];
		struct cpu_thread cpu;
	};
} __align(STACK_SIZE);

static struct cpu_stack *cpu_stacks;
unsigned int cpu_thread_count;
int secure_ra_bit = -1;
unsigned int cpu_max_pir;
struct cpu_thread *boot_cpu;
static bool hile_supported;
static bool radix_supported;
static unsigned long hid0_hile;
static unsigned long hid0_attn;
static bool pm_enabled;

unsigned long cpu_secondary_start __force_data = 0;
unsigned long cpu_urmor_updated __force_data = 0;

struct cpu_job {
	struct list_node	link;
	void			(*func)(void *data);
	void			*data;
	const char		*name;
	bool			complete;
	bool		        no_return;
};

/* attribute const as cpu_stacks is constant. */
unsigned long __attrconst cpu_stack_bottom(unsigned int pir)
{
	return ((unsigned long)&cpu_stacks[pir]) +
		sizeof(struct cpu_thread) + STACK_SAFETY_GAP;
}

unsigned long __attrconst cpu_stack_top(unsigned int pir)
{
	/* This is the top of the MC stack which is above the normal
	 * stack, which means a SP between cpu_stack_bottom() and
	 * cpu_stack_top() can either be a normal stack pointer or
	 * a Machine Check stack pointer
	 */
	return ((unsigned long)&cpu_stacks[pir]) +
		NORMAL_STACK_SIZE - STACK_TOP_GAP;
}

static void cpu_wake(struct cpu_thread *cpu)
{
	/* Is it idle ? If not, no need to wake */
	sync();
	if (!cpu->in_idle)
		return;
}

static struct cpu_thread *cpu_find_job_target(void)
{
	struct cpu_thread *cpu, *best, *me = this_cpu();
	uint32_t best_count;

	/* We try to find a target to run a job. We need to avoid
	 * a CPU that has a "no return" job on its queue as it might
	 * never be able to process anything.
	 *
	 * Additionally we don't check the list but the job count
	 * on the target CPUs, since that is decremented *after*
	 * a job has been completed.
	 */


	/* First we scan all available primary threads
	 */
	for_each_available_cpu(cpu) {
		if (cpu == me || !cpu_is_thread0(cpu) || cpu->job_has_no_return)
			continue;
		if (cpu->job_count)
			continue;
		lock(&cpu->job_lock);
		if (!cpu->job_count)
			return cpu;
		unlock(&cpu->job_lock);
	}

	/* Now try again with secondary threads included and keep
	 * track of the one with the less jobs queued up. This is
	 * done in a racy way, but it's just an optimization in case
	 * we are overcommitted on jobs. Could also just pick
	 * a random one...
	 */
	best = NULL;
	best_count = -1u;
	for_each_available_cpu(cpu) {
		if (cpu == me || cpu->job_has_no_return)
			continue;
		if (!best || cpu->job_count < best_count) {
			best = cpu;
			best_count = cpu->job_count;
		}
		if (cpu->job_count)
			continue;
		lock(&cpu->job_lock);
		if (!cpu->job_count)
			return cpu;
		unlock(&cpu->job_lock);
	}

	/* We haven't found anybody, do we have a bestie ? */
	if (best) {
		lock(&best->job_lock);
		return best;
	}

	/* Go away */
	return NULL;
}
struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				const char *name,
				void (*func)(void *data), void *data,
				bool no_return)
{
	struct cpu_job *job;

#ifdef DEBUG_SERIALIZE_CPU_JOBS
	if (cpu == NULL)
		cpu = this_cpu();
#endif

	if (cpu && !cpu_is_available(cpu)) {
		pr_error("CPU: Tried to queue job on unavailable CPU 0x%04x\n",
			 cpu->pir);
		return NULL;
	}

	job = zalloc(sizeof(struct cpu_job));
	if (!job)
		return NULL;
	job->func = func;
	job->data = data;
	job->name = name;
	job->complete = false;
	job->no_return = no_return;

	/* Pick a candidate. Returns with target queue locked */
	if (cpu == NULL)
		cpu = cpu_find_job_target();
	else if (cpu != this_cpu())
		lock(&cpu->job_lock);
	else
		cpu = NULL;

	/* Can't be scheduled, run it now */
	if (cpu == NULL) {
		func(data);
		job->complete = true;
		return job;
	}

	/* That's bad, the job will never run */
	if (cpu->job_has_no_return) {
		pr_warn("WARNING ! Job %s scheduled on CPU 0x%x"
			" which has a no-return job on its queue !\n",
			job->name, cpu->pir);
		backtrace();
	}
	list_add_tail(&cpu->job_queue, &job->link);
	if (no_return)
		cpu->job_has_no_return = true;
	else
		cpu->job_count++;
	if (pm_enabled)
		cpu_wake(cpu);
	unlock(&cpu->job_lock);

	return job;
}

void cpu_wait_job(struct cpu_job *job, bool free_it)
{
	unsigned long time_waited = 0;

	if (!job)
		return;

	while (!job->complete) {
		/* This will call OPAL pollers for us */
		time_wait_ms(10);
		time_waited += 10;
		lwsync();
	}
	lwsync();

	if (time_waited > 1000)
		pr_debug("cpu_wait_job(%s) for %lums\n",
			 job->name, time_waited);

	if (free_it)
		free(job);
}

bool cpu_check_jobs(struct cpu_thread *cpu)
{
	return !list_empty_nocheck(&cpu->job_queue);
}

void cpu_process_jobs(void)
{
	struct cpu_thread *cpu = this_cpu();
	struct cpu_job *job = NULL;
	void (*func)(void *);
	void *data;

	sync();
	if (!cpu_check_jobs(cpu))
		return;

	lock(&cpu->job_lock);
	while (true) {
		bool no_return;

		job = list_pop(&cpu->job_queue, struct cpu_job, link);
		if (!job)
			break;

		func = job->func;
		data = job->data;
		no_return = job->no_return;
		unlock(&cpu->job_lock);
		prlog(PR_TRACE, "running job %s on %x\n", job->name, cpu->pir);
		if (no_return)
			free(job);
		func(data);
		if (!list_empty(&cpu->locks_held)) {
			pr_error("OPAL job %s returning with locks held\n",
				 job->name);
			drop_my_locks(true);
		}
		lock(&cpu->job_lock);
		if (!no_return) {
			cpu->job_count--;
			lwsync();
			job->complete = true;
		}
	}
	unlock(&cpu->job_lock);
}

enum cpu_wake_cause {
	cpu_wake_on_job,
	cpu_wake_on_dec,
};

/* idle pm is not yet supported. */
static void cpu_idle_pm(enum cpu_wake_cause UNUSED(wake_on))
{
	return ;
}

void cpu_idle_delay(unsigned long delay)
{
	unsigned long now = mftb();
	unsigned long end = now + delay;
	unsigned long min_pm = usecs_to_tb(10);

	if (pm_enabled && delay > min_pm) {
pm:
		for (;;) {
			if (delay >= 0x7fffffff)
				delay = 0x7fffffff;
			mtspr(SPR_DEC, delay);

			cpu_idle_pm(cpu_wake_on_dec);

			now = mftb();
			if (tb_compare(now, end) == TB_AAFTERB)
				break;
			delay = end - now;
			if (!(pm_enabled && delay > min_pm))
				goto no_pm;
		}
	} else {
no_pm:
		smt_lowest();
		for (;;) {
			now = mftb();
			if (tb_compare(now, end) == TB_AAFTERB)
				break;
			delay = end - now;
			if (pm_enabled && delay > min_pm) {
				smt_medium();
				goto pm;
			}
		}
		smt_medium();
	}
}

struct __nomcount cpu_thread *find_cpu_by_pir_nomcount(u32 pir)
{
        if (pir > cpu_max_pir)
                return NULL;
        return &cpu_stacks[pir].cpu;
}

struct cpu_thread *next_cpu(struct cpu_thread *cpu)
{
	struct cpu_stack *s = container_of(cpu, struct cpu_stack, cpu);
	unsigned int index;

	if (cpu == NULL)
		index = 0;
	else
		index = s - cpu_stacks + 1;
	for (; index <= cpu_max_pir; index++) {
		cpu = &cpu_stacks[index].cpu;
		if (cpu->state != cpu_state_no_cpu)
			return cpu;
	}
	return NULL;
}

struct cpu_thread *first_cpu(void)
{
	return next_cpu(NULL);
}

struct cpu_thread *next_available_cpu(struct cpu_thread *cpu)
{
	do {
		cpu = next_cpu(cpu);
	} while(cpu && !cpu_is_available(cpu));

	return cpu;
}

struct cpu_thread *first_available_cpu(void)
{
	return next_available_cpu(NULL);
}

static void init_cpu_thread(struct cpu_thread *t,
			    enum cpu_thread_state state,
			    unsigned int pir)
{
	memset(t, 0, sizeof(struct cpu_thread));
	init_lock(&t->job_lock);
	list_head_init(&t->job_queue);
	list_head_init(&t->locks_held);
	t->state = state;
	t->pir = pir;
	invalidate_vcpuid(&t->vcpu);
#ifdef STACK_CHECK_ENABLED
	t->stack_bot_mark = LONG_MAX;
#endif
	assert(pir == container_of(t, struct cpu_stack, cpu) - cpu_stacks);
}

static void enable_attn(void)
{
	unsigned long hid0;

	hid0 = mfspr(SPR_HID0);
	hid0 |= hid0_attn;
	set_hid0(hid0);
}

static void disable_attn(void)
{
	unsigned long hid0;

	hid0 = mfspr(SPR_HID0);
	hid0 &= ~hid0_attn;
	set_hid0(hid0);
}

extern void __trigger_attn(void);
void trigger_attn(void)
{
	enable_attn();
	__trigger_attn();
}

static void init_hid(void)
{
	/* attn is enabled even when HV=0, so make sure it's off */
	disable_attn();
}

void __nomcount pre_init_boot_cpu(void)
{
	struct cpu_thread *cpu = this_cpu();

	memset(cpu, 0, sizeof(struct cpu_thread));
}

void init_boot_cpu(void)
{
	unsigned int pir, pvr;

	pir = mfspr(SPR_PIR);
	pvr = mfspr(SPR_PVR);

	/* Get CPU family and other flags based on PVR */
	switch(PVR_TYPE(pvr)) {
	case PVR_TYPE_P7:
	case PVR_TYPE_P7P:
		proc_gen = proc_gen_p7;
		break;
	case PVR_TYPE_P8E:
	case PVR_TYPE_P8:
		proc_gen = proc_gen_p8;
		hile_supported = PVR_VERS_MAJ(mfspr(SPR_PVR)) >= 2;
		hid0_hile = SPR_HID0_POWER8_HILE;
		hid0_attn = SPR_HID0_POWER8_ENABLE_ATTN;
		break;
	case PVR_TYPE_P8NVL:
		proc_gen = proc_gen_p8;
		hile_supported = true;
		hid0_hile = SPR_HID0_POWER8_HILE;
		hid0_attn = SPR_HID0_POWER8_ENABLE_ATTN;
		break;
	case PVR_TYPE_P9:
		proc_gen = proc_gen_p9;
		hile_supported = true;
		radix_supported = true;
		secure_ra_bit = 15;
		hid0_hile = SPR_HID0_POWER9_HILE;
		hid0_attn = SPR_HID0_POWER9_ENABLE_ATTN;
		break;
	case PVR_TYPE_P9PRI:
		proc_gen = proc_gen_p9;
		hile_supported = true;
		radix_supported = true;
		secure_ra_bit = 15;
		hid0_hile = SPR_HID0_POWER9_HILE;
		hid0_attn = SPR_HID0_POWER9_ENABLE_ATTN;
		break;
	default:
		proc_gen = proc_gen_unknown;
	}

	/* Get a CPU thread count and an initial max PIR based on family */
	switch(proc_gen) {
	case proc_gen_p7:
		cpu_thread_count = 4;
		pr_info("CPU: P7 generation processor"
			" (max %d threads/core)\n", cpu_thread_count);
		break;
	case proc_gen_p8:
		cpu_thread_count = 8;
		pr_info("CPU: P8 generation processor"
			" (max %d threads/core)\n", cpu_thread_count);
		break;
	case proc_gen_p9:
		cpu_thread_count = 4;
		pr_info("CPU: P9 generation processor"
			" (max %d threads/core)\n", cpu_thread_count);
		break;
	default:
		pr_error("CPU: Unknown PVR, assuming 1 thread\n");
		cpu_thread_count = 1;
		cpu_max_pir = mfspr(SPR_PIR);
	}

	pr_debug("CPU: Boot CPU PIR is 0x%04x PVR is 0x%08x\n",
		 pir, pvr);
	pr_debug("CPU: Initial max PIR set to 0x%x\n", cpu_max_pir);

	cpu_stacks = (struct cpu_stack *)(ultra_base + ULTRA_SIZE);
	/*
	 * Adjust top of RAM to include CPU stacks. If we have less
	 * RAM than this, it's not possible to boot.
	 */
	cpu_max_pir = pir;
	top_of_ram += (cpu_max_pir + 1) * STACK_SIZE;

	/* Setup boot CPU state */
	boot_cpu = &cpu_stacks[pir].cpu;
	init_cpu_thread(boot_cpu, cpu_state_active, pir);
	assert(this_cpu() == boot_cpu);
	init_hid();
}

static void enable_large_dec(bool on)
{
	u64 lpcr = mfspr(SPR_LPCR);

	if (on)
		lpcr |= SPR_LPCR_P9_LD;
	else
		lpcr &= ~SPR_LPCR_P9_LD;

	mtspr(SPR_LPCR, lpcr);
}

#define HIGH_BIT (1ull << 63)

static int find_dec_bits(void)
{
	int bits = 65; /* we always decrement once */
	u64 mask = ~0ull;

	if (proc_gen < proc_gen_p9)
		return 32;

	/* The ISA doesn't specify the width of the decrementer register so we
	 * need to discover it. When in large mode (LPCR.LD = 1) reads from the
	 * DEC SPR are sign extended to 64 bits and writes are truncated to the
	 * physical register width. We can use this behaviour to detect the
	 * width by starting from an all 1s value and left shifting until we
	 * read a value from the DEC with it's high bit cleared.
	 */

	enable_large_dec(true);

	do {
		bits--;
		mask = mask >> 1;
		mtspr(SPR_DEC, mask);
	} while (mfspr(SPR_DEC) & HIGH_BIT);

	enable_large_dec(false);

	pr_debug("CPU: decrementer bits %d\n", bits);
	return bits;
}

void init_cpu_max_pir(void)
{
	struct dt_node *cpus, *cpu;

	cpus = dt_find_by_path(dt_root, "/cpus");
	assert(cpus);

	/* Iterate all CPUs in the device-tree */
	dt_for_each_child(cpus, cpu) {
		unsigned int pir, server_no;

		/* Skip cache nodes */
		if (strcmp(dt_prop_get(cpu, "device_type"), "cpu"))
			continue;

		server_no = dt_prop_get_u32(cpu, "reg");

		/*
		 * If PIR property is absent, assume it's the same as the
		 * server number
		 */
		pir = dt_prop_get_u32_def(cpu, "ibm,pir", server_no);

		if (cpu_max_pir < pir + cpu_thread_count - 1)
			cpu_max_pir = pir + cpu_thread_count - 1;
	}

	pr_debug("CPU: New max PIR set to 0x%x\n", cpu_max_pir);
}

void init_all_cpus(void)
{
	struct dt_node *cpus, *cpu;
	unsigned int thread;
	int UNUSED(dec_bits) = find_dec_bits();

	cpus = dt_find_by_path(dt_root, "/cpus");
	assert(cpus);

	/* Iterate all CPUs in the device-tree */
	dt_for_each_child(cpus, cpu) {
		unsigned int pir, server_no, chip_id;
		int numa_node_id;
		enum cpu_thread_state state;
		const struct dt_property *p;
		struct cpu_thread *t, *pt;
		unsigned int tb_freq;

		/* Skip cache nodes */
		if (strcmp(dt_prop_get(cpu, "device_type"), "cpu"))
			continue;

		server_no = dt_prop_get_u32(cpu, "reg");

		/*
		 * If PIR property is absent, assume it's the same as the
		 * server number
		 */
		pir = dt_prop_get_u32_def(cpu, "ibm,pir", server_no);

		/* Read the TB frequency. It must be the same on all CPUs */
		tb_freq = dt_prop_get_u32(cpu, "timebase-frequency");
		set_tb_frequency((unsigned long)tb_freq);

		/* We should always have an ibm,chip-id property */
		chip_id = dt_get_chip_id(cpu);
		numa_node_id = numa_associativity_to_nid(cpu);

		/* Only use operational CPUs */
		if (!strcmp(dt_prop_get(cpu, "status"), "okay"))
			state = cpu_state_present;
		else
			state = cpu_state_unavailable;

		pr_info("CPU: CPU from DT PIR=0x%04x Server#=0x%x"
			" Node#=%d State=%d\n", pir, server_no,
			numa_node_id, state);

		/* Setup thread 0 */
		t = pt = &cpu_stacks[pir].cpu;
		if (t != boot_cpu) {
			init_cpu_thread(t, state, pir);
			/* Each cpu gets its own later in init_trace_buffers */
			t->trace = boot_cpu->trace;
		}
		t->server_no = server_no;
		t->primary = t;
		t->node = cpu;
		t->chip_id = chip_id;
		t->numa_node_id = numa_node_id;
#ifdef DEBUG_LOCKS
		t->requested_lock = NULL;
#endif

		/* Iterate threads */
		p = dt_find_property(cpu, "ibm,ppc-interrupt-server#s");
		if (!p)
			continue;
		for (thread = 1; thread < (p->len / 4); thread++) {
			prlog(PR_TRACE, "CPU:   secondary thread %d found\n",
			      thread);
			t = &cpu_stacks[pir + thread].cpu;
			init_cpu_thread(t, state, pir + thread);
			t->trace = boot_cpu->trace;
			t->server_no = ((const u32 *)p->prop)[thread];
			t->is_secondary = true;
			t->primary = pt;
			t->node = cpu;
			t->chip_id = chip_id;
			t->numa_node_id = numa_node_id;
		}
		pr_info("CPU:  %d secondary threads\n", thread);
	}
}

void cpu_bringup(void)
{
	struct cpu_thread *t;
	uint32_t count = 0;

	pr_info("CPU: Setting up secondary CPU state\n");

	/* Tell everybody to chime in ! */
	pr_info("CPU: Calling in all processors...\n");
	cpu_secondary_start = 1;
	sync();

	for_each_cpu(t) {
		if (t->state != cpu_state_present &&
		    t->state != cpu_state_active)
			continue;

		/* Add a callin timeout ?  If so, call cpu_remove_node(t). */
		while (t->state != cpu_state_active) {
			smt_lowest();
			sync();
		}
		smt_medium();
		count++;
	}

	pr_notice("CPU: All %d processors called in...\n", count);
}

void cpu_callin(struct cpu_thread *cpu)
{
	sync();
	cpu->state = cpu_state_active;
	sync();

	cpu->job_has_no_return = false;

	init_hid();
}
