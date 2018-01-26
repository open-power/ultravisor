/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Based on Ealier Work: arch/powerpc/include/asm/atomic.h
 *  Obtained from:
 *  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
 */


#ifndef ATOMIC_H
#define ATOMIC_H

typedef struct {
	int counter;
} atomic_t;

static __inline__ int atomic_read(const atomic_t *v)
{
	int t;

	__asm__ __volatile__("lwz%U1%X1 %0,%1" : "=r"(t) : "m"(v->counter));
	return t;
}

static __inline__ void atomic_set(atomic_t *v, int i)
{
	__asm__ __volatile__("stw%U0%X0 %1,%0" : "=m"(v->counter) : "r"(i));
}

static __inline__ int atomic_add_return_relaxed(int a, atomic_t *v)
{
	int t;

	__asm__ __volatile__(
	"1:     lwarx   %0,0,%3         # atomic_add_return_relaxed\n"
	"add %0,%2,%0\n"
	"       stwcx.  %0,0,%3\n"
	"       bne-    1b\n"
	: "=&r" (t), "+m" (v->counter)
	: "r" (a), "r" (&v->counter)
	: "cc");
	return t;
}

static __inline__ int atomic_sub_return_relaxed(int a, atomic_t *v)
{
	int t;

	__asm__ __volatile__(
	"1:     lwarx   %0,0,%3         # atomic_subf_return_relaxed\n"
	"subf %0,%2,%0\n"
	"       stwcx.  %0,0,%3\n"
	"       bne-    1b\n"
	: "=&r" (t), "+m" (v->counter)
	: "r" (a), "r" (&v->counter)
	: "cc");
	return t;
}
#endif /* ATOMIC_H */
