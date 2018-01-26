
// SPDX-License-Identifier: GPL-2.0
/*
 * NUMA Support
 *
 * Massively inspired by linux kernel file:
 * arch/powerpc/mm/numa.c
 * Copyright (C) 2002 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * Copyright 2019 IBM Corp.
 */
#include <logging.h>
#include <cpu.h>
#include <device.h>
#include <numa.h>

#define MAX_DISTANCE_REF_POINTS	4
#define MAX_NUMNODES		16

static int min_common_depth;
static int distance_ref_points_depth;
static int distance_ref_points[MAX_DISTANCE_REF_POINTS];
static int distance_lookup_table[MAX_NUMNODES][MAX_DISTANCE_REF_POINTS];

static inline uint32_t read_cell(const struct dt_property *p,
				 unsigned int index)
{
	/* Assuming 32 bit cells */
	unsigned int pos = index * sizeof(uint32_t);

	return *((uint32_t *) &(p->prop[pos]));
}

/**
 * find_min_common_depth - get the minimal common depth in DT
 *
 * We are assuming that we are running on top of OPAL so we are only supporting
 * the form 1 of the ibm,associativity-reference-points item.
 */
void numa_find_min_common_depth(void)
{
	struct dt_node *root;
	const struct dt_property *p;
	int i;

	root = dt_find_by_path(dt_root, "/ibm,opal");
	if (!root)
		return;

	p = dt_find_property(root, "ibm,associativity-reference-points");
	if (!p)
		return;

	distance_ref_points_depth = p->len / sizeof(uint32_t);
	if (distance_ref_points_depth > MAX_DISTANCE_REF_POINTS) {
		pr_warn("NUMA: distance depth is not capped at %d entries\n",
			MAX_DISTANCE_REF_POINTS);
		distance_ref_points_depth = MAX_DISTANCE_REF_POINTS;
		return;
	}

	for (i=0; i < distance_ref_points_depth; i++)
		distance_ref_points[i] = read_cell(p,i);

	min_common_depth = read_cell(p, 0);
	pr_debug("NUMA: distance_ref_points_depth=%d min_common_depth=%d\n",
		 distance_ref_points_depth, min_common_depth);
	for (i=0; i < distance_ref_points_depth; i++)
		pr_debug("   distance_ref_points[%d]=%d\n", i,
			 distance_ref_points[i]);
}

/**
 * associativity_to_nid - reads the associativity from DT and the node id
 *
 * @cpu : the CPU node in the device tree
 * Return the numa node id or NUMA_NO_NODE if something went wrong.
 */
uint32_t numa_associativity_to_nid(struct dt_node *cpu)
{
	const struct dt_property *p;
	int32_t nid = NUMA_NO_NODE;
	uint32_t length;

	p = dt_find_property(cpu, "ibm,associativity");
	if (!p)
		return nid;

	length = read_cell(p, 0);
	if (length >= min_common_depth)
		nid = read_cell(p, min_common_depth);

	if (nid > MAX_NUMNODES) {
		pr_warn("NUMA node id %d is too high.\n", nid);
		nid = NUMA_NO_NODE;
	}

	if (nid != NUMA_NO_NODE && length >= distance_ref_points_depth) {
		/*
		 * Initialize the distance lookup table for the node.
		 *
		 * Note: This is done multiple times for each node, but this
		 * should not impact so much.
		 */
		int i;
		for (i = 0; i < distance_ref_points_depth; i++)
			distance_lookup_table[nid][i] = read_cell(p, distance_ref_points[i]);
	}

	return nid;
}

/**
 * node_distance - compute the distance between 2 nodes.
 */
int numa_node_distance(int a, int b)
{
	int i;
	int distance = LOCAL_DISTANCE;

	for (i = 0; i < distance_ref_points_depth; i++) {
		if (distance_lookup_table[a][i] == distance_lookup_table[b][i])
			break;

		/* Double the distance for each NUMA level */
		distance *= 2;
	}

	return distance;
}
