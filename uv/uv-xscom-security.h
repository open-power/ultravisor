// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#ifndef __UV_XSCOM_SECURITY_H
#define __UV_XSCOM_SECURITY_H

/* WHITELIST */

/*
 * Table 1:
 *
 *     keys   = 2byte - (start , end) of
 *              the ranges in bit 0-7 of the 32-bit address
 *     values = running count of the paths to table 2
 *
 * for example - if ranges are 0x20-0x37, 0x01-0x01, 0x10-0x17 and has
 *               1, 2 and 3 paths respectively to table 2
 * then table 1 will have {0x20,0x37} = 01, {0x01,0x01} = 3, {0x10,0x17} = 7
 *
 * 1 byte for running count - we are good with uint8_t till the total paths are
 * less than 256
 */
_t1_t wl_t1[] = {
	// length of the table = 2
	{ 0x00, 0x00, 0x02 },
	{ 0x05, 0x05, 0x03 }
};

/*
 * Table 2:
 *     keys   = unique 1 byte numbers having same prefix for each
 *              range in table 1 key - bit 8-15 from a 32-bit address
 *     values = running count of paths from each of the keys
 *
 *  for example - if element a has 1 path, b has 0 and c has 3 paths
 *  then table 1 will have a = 1, b = 1, c = 4
 *
 *  1 byte for key
 *  2 byte for number of paths
 *  We are good with uint16_t,
 *  till the number of paths to table 3 from each key is less than 65536
 */
_t2_t wl_t2[] = {
	// length of the table = 3
	{ 0x06, 0x02 },
	{ 0x0a, 0x16 },
	{ 0x01, 0x17 }
};

/*
 * Table 3:
 *     values = 2 byte value bit 16-31 of the 32-bit address
 */
// length of the table = 23
// _t3_t wl_t3[] = {
uint16_t wl_t3[] = { 0xc081, 0xc082, 0x0004, 0x0005, 0x0007, 0x0009,
		     0x000a, 0x1004, 0x1005, 0x1007, 0x1009, 0x100a,
		     0x2004, 0x2005, 0x2007, 0x2009, 0x200a, 0x3004,
		     0x3005, 0x3007, 0x3009, 0x300a, 0x2c4b };

_t1_table_t wl_table1 = { sizeof(wl_t1) / sizeof(_t1_t), 0xFF000000, wl_t1 };
_t2_table_t wl_table2 = { sizeof(wl_t2) / sizeof(_t2_t), 0x00FF0000, wl_t2 };
_t3_table_t wl_table3 = { sizeof(wl_t3) / sizeof(_t3_t), 0x0000FFFF,
			  (_t3_t *)wl_t3 };

/* BLACKLIST */

/*
 *  Table 1:
 *     keys   = 2byte - (start , end) of
 *              the ranges in bit 0-7 of the 32-bit address
 *     values = running count of the paths to table2
 *
 *  for example - if ranges are 0x20-0x37, 0x01-0x01, 0x10-0x17 and has
 *                1, 2 and 3 paths respectively to table 2
 *  then table 1 will have {0x20,0x37} = 01, {0x01,0x01} = 3, {0x10,0x17} = 7
 *
 *  1 byte for running count - we are good with uint8_t till the
 *  total paths are less than 256
 */
_t1_t bl_t1[] = {
	// length of the table = 0
};

/*
 *  Table 2:
 *     keys   = unique 1 byte numbers having same prefix for each
 *              range in table 1 key - bit 8-15 from a 32-bit address
 *     values = running count of paths from each of the keys
 *
 *  for example - if element a has 1 path, b has 0 and c has 3 paths
 *  then table 1 will have a = 1, b = 1, c = 4
 *
 *  1 byte for key
 *  2 byte for number of paths
 *  We are good with uint16_t,
 *  till the number of paths to table 3 from each key is less than 65536
 */
_t2_t bl_t2[] = {
	// length of the table = 0
};

/*
 * Table 3:
 *     values = 2 byte value bit 16-31 of the 32-bit address
 */
_t3_t bl_t3[] = {
	// length of the table = 0
};

_t1_table_t bl_table1 = { sizeof(bl_t1) / sizeof(_t1_t), 0xFF000000, bl_t1 };
_t2_table_t bl_table2 = { sizeof(bl_t2) / sizeof(_t2_t), 0x00FF0000, bl_t2 };
_t3_table_t bl_table3 = { sizeof(bl_t3) / sizeof(_t3_t), 0x0000FFFF, bl_t3 };

/* GREYLIST */

/*
 * Table 1:
 *     Address   = 4 byte
 *     Mask      = 8 byte
 */
_gl_t1_t gl_t1[] = {
	// length of the table = 0
};

_gl_t1_table_t gl_table1 = { sizeof(gl_t1) / sizeof(_gl_t1_t), 0xFFFFFFFF,
			     gl_t1 };

#endif //__UV_XSCOM_SECURITY_H
