/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NUMA faults
 *
 * Copyright 2019, IBM Corporation.
 *
 */

#define NUMA_NO_NODE 	(-1)
#define LOCAL_DISTANCE	10

struct dt_node;

extern void numa_find_min_common_depth(void);
extern uint32_t numa_associativity_to_nid(struct dt_node *cpu);
extern int numa_node_distance(int a, int b);
