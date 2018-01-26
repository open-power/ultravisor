// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __MEM_MAP_H
#define __MEM_MAP_H

/* Stack size set to 16K, some of it will be used for
 * machine check (see stack.h)
 */
#define PADDING 		0x0
#define STACK_SHIFT		14
#define STACK_SIZE		(1 << STACK_SHIFT)
#define TEXT_AND_BSS_OFFSET   0x0
#define TEXT_AND_BSS_SIZE     0x00400000


/* We keep a gap of 2M for ultra text & bss for now. We will
 * then we have our heap which goes up to base + 14M (so 12M for
 * now, though we can certainly reduce that a lot).
 *
 * Ideally, we should fix the heap end and use _end to basically
 * initialize our heap so that it covers anything from _end to
 * that heap end, avoiding wasted space.
 */
#define HEAP_OFFSET		TEXT_AND_BSS_SIZE+PADDING
#define HEAP_SIZE		0x00c00000

/* UV Non-Dumpable storage area */
#define UV_STOR_OFFSET		HEAP_OFFSET+HEAP_SIZE+PADDING
#define UV_STOR_SIZE		0x00010000

/* Total size of the above area
 *
 * (Ensure this has at least a 64k alignment)
 */
#define ULTRA_SIZE            UV_STOR_OFFSET+UV_STOR_SIZE+PADDING

/* We start laying out the CPU stacks from here, indexed by PIR
 * each stack is STACK_SIZE in size (naturally aligned power of
 * two) and the bottom of the stack contains the cpu thread
 * structure for the processor, so it can be obtained by a simple
 * bit mask from the stack pointer.
 *
 * The size of this array is dynamically determined at boot time
 */

/* Size allocated to build the device-tree */
#define	DEVICE_TREE_MAX_SIZE	0x80000

#endif /* __MEM_MAP_H */
