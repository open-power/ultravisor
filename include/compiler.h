// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp.  */

#ifndef __COMPILER_H
#define __COMPILER_H

#ifndef __ASSEMBLY__

#include <stddef.h>
#include <stdbool.h>
#include <ccan/short_types/short_types.h>

/* Macros for various compiler bits and pieces */
#define __packed		__attribute__((packed))
#define __align(x)		__attribute__((__aligned__(x)))
#define __unused		__attribute__((unused))
#define __used			__attribute__((used))
#define __section(x)		__attribute__((__section__(x)))
#define __noreturn		__attribute__((noreturn))
/* not __const as this has a different meaning (const) */
#define __attrconst		__attribute__((const))
#define __warn_unused_result	__attribute__((warn_unused_result))

/* Kernel uses __force to silence sparse? Ignore for Ultra */
#define __force

#define __nomcount		__attribute__((no_instrument_function))

/* Compiler barrier */
static inline void barrier(void)
{
	asm volatile("" : : : "memory");
}

#endif /* __ASSEMBLY__ */

#ifndef read_barrier_depends
#define read_barrier_depends()          do { } while (0)
#endif

#ifndef __smp_read_barrier_depends
#define __smp_read_barrier_depends()    read_barrier_depends()
#endif

#ifndef smp_read_barrier_depends
#define smp_read_barrier_depends()      __smp_read_barrier_depends()
#endif

/* Stringification macro */
#define __tostr(x)	#x
#define tostr(x)	__tostr(x)

#ifdef __GNUC__
#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#define UNUSED(x) UNUSED_ ## x
#endif

#define __force_data		__section(".force.data")

#ifndef __TESTING__
/* Readonly section start and end. */
extern char __rodata_start[], __rodata_end[];

static inline bool is_rodata(const void *p)
{
	return ((const char *)p >= __rodata_start &&
		(const char *)p < __rodata_end);
}
#else
static inline bool is_rodata(const void *p)
{
	return false;
}
#endif

#define __READ_ONCE_SIZE                                                \
({                                                                      \
        switch (size) {                                                 \
        case 1: *(u8 *)res = *(volatile u8 *)p; break;                  \
        case 2: *(u16 *)res = *(volatile u16 *)p; break;                \
        case 4: *(u32 *)res = *(volatile u32 *)p; break;                \
        case 8: *(u64 *)res = *(volatile u64 *)p; break;                \
        default:                                                        \
                barrier();                                              \
                __builtin_memcpy((void *)res, (const void *)p, size);   \
                barrier();                                              \
        }                                                               \
})

static inline void __read_once_size(const volatile void *p, void *res, int size)
{
        __READ_ONCE_SIZE;
}

#define __READ_ONCE(x, check)                                           \
({                                                                      \
        union { typeof(x) __val; char __c[1]; } __u;                    \
        if (check)                                                      \
                __read_once_size(&(x), __u.__c, sizeof(x));             \
        else                                                            \
                __read_once_size_nocheck(&(x), __u.__c, sizeof(x));     \
        smp_read_barrier_depends(); /* Enforce dependency ordering from x */ \
        __u.__val;                                                      \
})
#define READ_ONCE(x) __READ_ONCE(x, 1)

static inline
void __read_once_size_nocheck(const volatile void *p, void *res, int size)
{
        __READ_ONCE_SIZE;
}

static inline void __write_once_size(volatile void *p, void *res, int size)
{
        switch (size) {
        case 1: *(volatile u8 *)p = *(u8 *)res; break;
        case 2: *(volatile u16 *)p = *(u16 *)res; break;
        case 4: *(volatile u32 *)p = *(u32 *)res; break;
        case 8: *(volatile u64 *)p = *(u64 *)res; break;
        default:
                barrier();
                __builtin_memcpy((void *)p, (const void *)res, size);
                barrier();
        }
}

#define WRITE_ONCE(x, val) \
({                                                      \
        union { typeof(x) __val; char __c[1]; } __u =   \
                { .__val = (__force typeof(x)) (val) }; \
        __write_once_size(&(x), __u.__c, sizeof(x));    \
        __u.__val;                                      \
})

#endif /* __COMPILER_H */
