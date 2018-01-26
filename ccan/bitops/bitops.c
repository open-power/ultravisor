/* CC0 license (public domain) - see LICENSE file for details */
#include <ccan/str/str.h>
#include <stdlib.h>
#include <ccan/bitops/bitops.h>

/* We do naive replacement versions: good for testing, and really your
 * compiler should do better. */
#ifdef BITOPS_NEED_FFS
int __attribute__ ((const)) bitops_ffs32(uint32_t u)
{
	int i;
	for (i = 0; i < 32; i++)
		if (u & ((uint32_t)1 << i))
			return i + 1;
	return 0;
}

int __attribute__ ((const)) bitops_ffs64(uint64_t u)
{
	int i;
	for (i = 0; i < 64; i++)
		if (u & ((uint64_t)1 << i))
			return i + 1;
	return 0;
}
#endif

#ifdef BITOPS_NEED_CLZ
int bitops_clz32(uint32_t u)
{
	int i;
	for (i = 0; i < 32; i++)
		if (u & ((uint32_t)1 << (31 - i)))
			return i;
	abort();
}

int bitops_clz64(uint64_t u)
{
	int i;
	for (i = 0; i < 64; i++)
		if (u & ((uint64_t)1 << (63 - i)))
			return i;
	abort();
}
#endif

#ifdef BITOPS_NEED_CTZ
int __attribute__ ((const)) bitops_ctz32(uint32_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return bitops_ffs32(u) - 1;
}

int __attribute__ ((const)) bitops_ctz64(uint64_t u)
{
	BITOPS_ASSERT_NONZERO(u);
	return bitops_ffs64(u) - 1;
}
#endif

#ifdef BITOPS_NEED_WEIGHT
int __attribute__ ((const)) bitops_weight32(uint32_t u)
{
	int i, num = 0;
	for (i = 0; i < 32; i++)
		if (u & ((uint32_t)1 << i))
			num++;
	return num;
}

int __attribute__ ((const)) bitops_weight64(uint64_t u)
{
	int i, num = 0;
	for (i = 0; i < 64; i++)
		if (u & ((uint64_t)1 << i))
			num++;
	return num;
}
#endif
