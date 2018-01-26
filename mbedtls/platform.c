/*
 *  Platform abstraction layer
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * Reduced platform.c only for defines needed for subset of files used.
 */


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_MEMORY)

#include <stdlib.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_CALLOC_MACRO)
void *platform_calloc( size_t n, size_t size )
{
	void *ptr = malloc(n * size);
	if (ptr)
		memset(ptr, 0, n * size);
	return ptr;
}
#endif /* MBEDTLS_PLATFORM_CALLOC_MACRO */

#endif /* MBEDTLS_PLATFORM_MEMORY */

#endif /* MBEDTLS_PLATFORM_C */
