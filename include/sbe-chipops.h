// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2020 IBM Corp.
 */

#include <stdint.h>

void sbe_init(void);
int send_sbe_command(uint64_t chip_id, uint64_t opcode, uint64_t input,
		     uint64_t *output);
