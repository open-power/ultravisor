// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * URMOR Update.
 *
 * Copyright 2018, IBM Corporation.
 *
 */

/**
 * @brief Function for updating URMOR.
 *
 * Functions to support the update sequence for URMOR based on steps described
 * in section 4.9.7 of the POWER9 User Manual.
 *
 */
extern void urmor_update(void);
extern void urmor_secondary_setup(struct cpu_thread *cpu);
