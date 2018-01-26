// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp.  */

/*
 *
 * All functions in charge of generating the associativity/affinity
 * properties in the device-tree
 */

#ifndef __AFFINITY_H
#define __AFFINITY_H

struct dt_node;
struct cpu_thread;

extern void add_associativity_ref_point(void);

extern void add_chip_dev_associativity(struct dt_node *dev);

#endif /* __AFFINITY_H */
