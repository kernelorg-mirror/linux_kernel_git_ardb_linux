// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RAID-6 syndrome calculation using x86 Galois Field New Instructions
 *
 * See gfni-asm.S for a description of the algorithm.
 */

#include <linux/array_size.h>
#include <linux/bits.h>
#include <linux/cache.h>
#include <linux/linkage.h>
#include <asm/fpu/api.h>
#include "algos.h"
#include "pq_arch.h"

/*
 * GF2P8AFFINEQB bit matrices that multiply each byte by g^n in the RAID-6
 * Galois field.  Byte 7 - i of each matrix selects the input bits that are
 * XORed together to produce output bit i.
 */
static u64 raid6_gfni_gexp[256] __ro_after_init;

void __init raid6_gfni_init(void)
{
	for (unsigned int n = 0; n < ARRAY_SIZE(raid6_gfni_gexp); n++) {
		const u8 *mul = raid6_gfmul[raid6_gfexp[n]];
		u64 m = 0;

		/* Column j is the product of g^n and {01} << j */
		for (int j = 0; j < 8; j++)
			for (int i = 0; i < 8; i++)
				if (mul[BIT(j)] & BIT(i))
					m |= BIT_ULL(8 * (7 - i) + j);
		raid6_gfni_gexp[n] = m;
	}
}

#define DEFINE_RAID6_GFNI(isa, n)					\
asmlinkage void raid6_gfni_##isa##_gen_x##n(void **ptrs,		\
		unsigned long nr, size_t bytes, const u64 mats[],	\
		u8 *p, u8 *q);						\
asmlinkage void raid6_gfni_##isa##_xor_x##n(void **ptrs,		\
		unsigned long nr, size_t bytes, const u64 mats[],	\
		u8 *p, u8 *q);						\
									\
static void raid6_gfni_##isa##x##n##_gen_syndrome(int disks,		\
		size_t bytes, void **ptrs)				\
{									\
	/* g and g^2 */							\
	const u64 *mats = &raid6_gfni_gexp[1];				\
									\
	kernel_fpu_begin();						\
	raid6_gfni_##isa##_gen_x##n(ptrs, disks - 3, bytes, mats,	\
			ptrs[disks - 2], ptrs[disks - 1]);		\
	kernel_fpu_end();						\
}									\
									\
static void raid6_gfni_##isa##x##n##_xor_syndrome(int disks,		\
		int start, int stop, size_t bytes, void **ptrs)		\
{									\
	const u64 mats[] = {						\
		raid6_gfni_gexp[1], raid6_gfni_gexp[2],			\
		raid6_gfni_gexp[start],					\
	};								\
									\
	kernel_fpu_begin();						\
	raid6_gfni_##isa##_xor_x##n(ptrs + start, stop - start, bytes,	\
			mats, ptrs[disks - 2], ptrs[disks - 1]);	\
	kernel_fpu_end();						\
}									\
									\
const struct raid6_calls raid6_gfni_##isa##x##n = {			\
	.gen_syndrome	= raid6_gfni_##isa##x##n##_gen_syndrome,	\
	.xor_syndrome	= raid6_gfni_##isa##x##n##_xor_syndrome,	\
	.name		= "gfni_" #isa "x" #n,				\
}

DEFINE_RAID6_GFNI(avx2, 2);
DEFINE_RAID6_GFNI(avx2, 4);
DEFINE_RAID6_GFNI(avx512, 2);
DEFINE_RAID6_GFNI(avx512, 4);
