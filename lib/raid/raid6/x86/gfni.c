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
#include <linux/mm.h>
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

/* Return the GF2P8AFFINEQB matrix that multiplies by c, which must be non-zero */
static u64 raid6_gfni_mul(u8 c)
{
	return raid6_gfni_gexp[raid6_gflog[c]];
}

typedef void (*raid6_gfni_gen_fn)(void **ptrs, unsigned long nr, size_t bytes,
				  const u64 mats[], u8 *p, u8 *q);
typedef void (*raid6_gfni_recov_fn)(size_t bytes, u8 *p, u8 *q, u8 *dp, u8 *dq,
				    const u64 mats[2]);

#define DECLARE_RAID6_GFNI_RECOV(isa)					\
asmlinkage void raid6_gfni_##isa##_gen_cached_x4(void **ptrs,		\
		unsigned long nr, size_t bytes, const u64 mats[],	\
		u8 *p, u8 *q);						\
asmlinkage void raid6_gfni_##isa##_recov_2data(size_t bytes, u8 *p,	\
		u8 *q, u8 *dp, u8 *dq, const u64 mats[2]);		\
asmlinkage void raid6_gfni_##isa##_recov_datap(size_t bytes, u8 *p,	\
		u8 *q, u8 *dp, u8 *dq, const u64 mats[2])

DECLARE_RAID6_GFNI_RECOV(avx2);
DECLARE_RAID6_GFNI_RECOV(avx512);

static __always_inline void raid6_gfni_2data_recov(int disks, size_t bytes,
		int faila, int failb, void **ptrs, raid6_gfni_gen_fn gen,
		raid6_gfni_recov_fn recov)
{
	u8 *p = ptrs[disks - 2], *q = ptrs[disks - 1];
	u8 *dp = ptrs[faila], *dq = ptrs[failb];
	const u64 mats[2] = {
		raid6_gfni_mul(raid6_gfexi[failb - faila]),
		raid6_gfni_mul(raid6_gfinv[raid6_gfexp[faila] ^
					   raid6_gfexp[failb]]),
	};

	/*
	 * Compute the syndromes with zeroes for the missing data pages, using
	 * the dead data pages as temporary storage for delta P and delta Q.
	 * Use ordinary stores for this, given that the deltas are consumed
	 * right away.
	 */
	ptrs[faila] = page_address(ZERO_PAGE(0));
	ptrs[failb] = page_address(ZERO_PAGE(0));

	kernel_fpu_begin();
	gen(ptrs, disks - 3, bytes, &raid6_gfni_gexp[1], dp, dq);
	recov(bytes, p, q, dp, dq, mats);
	kernel_fpu_end();

	ptrs[faila] = dp;
	ptrs[failb] = dq;
}

static __always_inline void raid6_gfni_datap_recov(int disks, size_t bytes,
		int faila, void **ptrs, raid6_gfni_gen_fn gen,
		raid6_gfni_recov_fn recov)
{
	u8 *p = ptrs[disks - 2], *q = ptrs[disks - 1];
	u8 *dq = ptrs[faila];
	const u64 mats[2] = {
		0, raid6_gfni_mul(raid6_gfinv[raid6_gfexp[faila]]),
	};

	/*
	 * Compute the syndromes with zeroes for the missing data page, using
	 * the dead data page as temporary storage for delta Q.  Use ordinary
	 * stores for this, given that P and delta Q are consumed right away.
	 */
	ptrs[faila] = page_address(ZERO_PAGE(0));

	kernel_fpu_begin();
	gen(ptrs, disks - 3, bytes, &raid6_gfni_gexp[1], p, dq);
	recov(bytes, p, q, NULL, dq, mats);
	kernel_fpu_end();

	ptrs[faila] = dq;
}

static void raid6_gfni_avx2_2data_recov(int disks, size_t bytes, int faila,
		int failb, void **ptrs)
{
	raid6_gfni_2data_recov(disks, bytes, faila, failb, ptrs,
			       raid6_gfni_avx2_gen_cached_x4,
			       raid6_gfni_avx2_recov_2data);
}

static void raid6_gfni_avx2_datap_recov(int disks, size_t bytes, int faila,
		void **ptrs)
{
	raid6_gfni_datap_recov(disks, bytes, faila, ptrs,
			       raid6_gfni_avx2_gen_cached_x4,
			       raid6_gfni_avx2_recov_datap);
}

static void raid6_gfni_avx512_2data_recov(int disks, size_t bytes, int faila,
		int failb, void **ptrs)
{
	raid6_gfni_2data_recov(disks, bytes, faila, failb, ptrs,
			       raid6_gfni_avx512_gen_cached_x4,
			       raid6_gfni_avx512_recov_2data);
}

static void raid6_gfni_avx512_datap_recov(int disks, size_t bytes, int faila,
		void **ptrs)
{
	raid6_gfni_datap_recov(disks, bytes, faila, ptrs,
			       raid6_gfni_avx512_gen_cached_x4,
			       raid6_gfni_avx512_recov_datap);
}

const struct raid6_recov_calls raid6_recov_gfni_avx2 = {
	.data2		= raid6_gfni_avx2_2data_recov,
	.datap		= raid6_gfni_avx2_datap_recov,
	.name		= "gfni_avx2",
};

const struct raid6_recov_calls raid6_recov_gfni_avx512 = {
	.data2		= raid6_gfni_avx512_2data_recov,
	.datap		= raid6_gfni_avx512_datap_recov,
	.name		= "gfni_avx512",
};
