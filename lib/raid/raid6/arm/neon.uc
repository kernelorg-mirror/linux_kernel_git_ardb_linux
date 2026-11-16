/* -----------------------------------------------------------------------
 *
 *   neon.uc - RAID-6 syndrome calculation using ARM NEON instructions
 *
 *   Copyright (C) 2012 Rob Herring
 *   Copyright (C) 2015 Linaro Ltd. <ard.biesheuvel@linaro.org>
 *
 *   Based on altivec.uc:
 *     Copyright 2002-2004 H. Peter Anvin - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 53 Temple Place Ste 330,
 *   Boston MA 02111-1307, USA; either version 2 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

/*
 * neon$#.c
 *
 * $#-way unrolled NEON intrinsics math RAID-6 instruction set
 *
 * This file is postprocessed using unroll.awk
 *
 * The Q syndrome is evaluated using Horner's rule, but four data disks at a
 * time, i.e.,
 *
 *   Q' = x^4 * Q + x^3 * D[z+3] + x^2 * D[z+2] + x * D[z+1] + D[z]
 *
 * Multiplying by x^n amounts to shifting each byte left by n bits, and
 * reducing the n bits that are shifted out modulo the RAID-6 polynomial.
 * Since this reduction is linear, the bits shifted out of all terms can be
 * XORed together first, and reduced using a single polynomial multiplication
 * by 0x1d, which is exact as long as no more than 4 bits are shifted out.
 */

#include <arm_neon.h>
#include "arm/neon.h"
#include "arm/neon_compat.h"

typedef uint8x16_t unative_t;

#define NSIZE	sizeof(unative_t)

#define RAID6_NEON_FN(n, fn)	raid6_neon ## n ## _ ## fn

/*
 * The SHLBYTE() operation shifts each byte left by 1, *not*
 * rolling over into the next byte
 */
static inline unative_t SHLBYTE(unative_t v)
{
	return vshlq_n_u8(v, 1);
}

/*
 * The MASK() operation returns 0xFF in any byte for which the high
 * bit is 1, 0x00 for any byte for which the high bit is 0.
 */
static inline unative_t MASK(unative_t v)
{
	return (unative_t)vshrq_n_s8((int8x16_t)v, 7);
}

static inline unative_t PMUL(unative_t v, unative_t u)
{
	return (unative_t)vmulq_p8((poly8x16_t)v, (poly8x16_t)u);
}

/* Q * x + D */
static inline unative_t HORNER1(unative_t q, unative_t d, unative_t x1d)
{
	return SHLBYTE(q) ^ (MASK(q) & x1d) ^ d;
}

/* Q * x^2 + D1 * x + D0 */
static inline unative_t HORNER2(unative_t q, unative_t d1, unative_t d0,
				unative_t x1d)
{
	unative_t lo = vshlq_n_u8(q, 2) ^ vshlq_n_u8(d1, 1) ^ d0;
	unative_t hi = vshrq_n_u8(q, 6) ^ vshrq_n_u8(d1, 7);

	return lo ^ PMUL(hi, x1d);
}

/* Q * x^4 + D3 * x^3 + D2 * x^2 + D1 * x + D0 */
static inline unative_t HORNER4(unative_t q, unative_t d3, unative_t d2,
				unative_t d1, unative_t d0, unative_t x1d)
{
	unative_t lo = vshlq_n_u8(q, 4) ^ vshlq_n_u8(d3, 3) ^
		       vshlq_n_u8(d2, 2) ^ vshlq_n_u8(d1, 1) ^ d0;
	unative_t hi = vshrq_n_u8(q, 4) ^ vshrq_n_u8(d3, 5) ^
		       vshrq_n_u8(d2, 6) ^ vshrq_n_u8(d1, 7);

	return lo ^ PMUL(hi, x1d);
}

/*
 * Perform a Horner step for a single lane.  Each step is a single statement
 * so that unroll.awk keeps the code for each lane together, which avoids
 * running out of registers with the wider unrolls.
 */
static inline void STEP1(unative_t *wp, unative_t *wq, const uint8_t *s,
			 unative_t x1d)
{
	unative_t d = vld1q_u8(s);

	*wp ^= d;
	*wq = HORNER1(*wq, d, x1d);
}

static inline void STEP2(unative_t *wp, unative_t *wq, const uint8_t *s1,
			 const uint8_t *s0, unative_t x1d)
{
	unative_t d1 = vld1q_u8(s1);
	unative_t d0 = vld1q_u8(s0);

	*wp ^= d1 ^ d0;
	*wq = HORNER2(*wq, d1, d0, x1d);
}

static inline void STEP4(unative_t *wp, unative_t *wq, const uint8_t *s3,
			 const uint8_t *s2, const uint8_t *s1,
			 const uint8_t *s0, unative_t x1d)
{
	unative_t d3 = vld1q_u8(s3);
	unative_t d2 = vld1q_u8(s2);
	unative_t d1 = vld1q_u8(s1);
	unative_t d0 = vld1q_u8(s0);

	*wp ^= d3 ^ d2 ^ d1 ^ d0;
	*wq = HORNER4(*wq, d3, d2, d1, d0, x1d);
}

/* Multiply by the constant described by the nibble tables in m0 and m1 */
static inline unative_t GFMUL(unative_t v, unative_t m0, unative_t m1)
{
	return vqtbl1q_u8(m0, v & 0x0f) ^ vqtbl1q_u8(m1, vshrq_n_u8(v, 4));
}

void RAID6_NEON_FN($#, gen_syndrome_real)(int disks, unsigned long bytes,
					 void **ptrs)
{
	uint8_t **dptr = (uint8_t **)ptrs;
	uint8_t *p, *q;
	int d, z, z0;

	unative_t wq$$, wp$$;
	const unative_t x1d = vdupq_n_u8(0x1d);

	z0 = disks - 3;		/* Highest data disk */
	p = dptr[z0+1];		/* XOR parity */
	q = dptr[z0+2];		/* RS syndrome */

	for ( d = 0 ; d < bytes ; d += NSIZE*$# ) {
		wq$$ = wp$$ = vld1q_u8(&dptr[z0][d+$$*NSIZE]);
		z = z0 - 1;

		/* Process 1 and/or 2 disks so that a multiple of 4 remains */
		if (z0 & 1) {
			STEP1(&wp$$, &wq$$, &dptr[z][d+$$*NSIZE], x1d);
			z--;
		}
		if (z0 & 2) {
			STEP2(&wp$$, &wq$$, &dptr[z][d+$$*NSIZE], &dptr[z-1][d+$$*NSIZE], x1d);
			z -= 2;
		}
		for ( ; z >= 0 ; z -= 4 ) {
			STEP4(&wp$$, &wq$$, &dptr[z][d+$$*NSIZE], &dptr[z-1][d+$$*NSIZE], &dptr[z-2][d+$$*NSIZE], &dptr[z-3][d+$$*NSIZE], x1d);
		}
		vst1q_u8(&p[d+NSIZE*$$], wp$$);
		vst1q_u8(&q[d+NSIZE*$$], wq$$);
	}
}

/*
 * @gmul points to the 32 byte nibble table (see raid6_vgfmul[]) that
 * multiplies by g^start.
 */
void RAID6_NEON_FN($#, xor_syndrome_real)(int disks, int start, int stop,
					 unsigned long bytes, void **ptrs,
					 const uint8_t *gmul)
{
	uint8_t **dptr = (uint8_t **)ptrs;
	uint8_t *p, *q;
	int d, z, z0;

	unative_t wq$$, wp$$;
	const unative_t x1d = vdupq_n_u8(0x1d);
	const unative_t gm0 = vld1q_u8(gmul);
	const unative_t gm1 = vld1q_u8(gmul + 16);

	z0 = stop;		/* P/Q right side optimization */
	p = dptr[disks-2];	/* XOR parity */
	q = dptr[disks-1];	/* RS syndrome */

	for ( d = 0 ; d < bytes ; d += NSIZE*$# ) {
		wq$$ = vld1q_u8(&dptr[z0][d+$$*NSIZE]);
		wp$$ = vld1q_u8(&p[d+$$*NSIZE]) ^ wq$$;
		z = z0 - 1;

		/* P/Q data pages */
		if ((z0 - start) & 1) {
			STEP1(&wp$$, &wq$$, &dptr[z][d+$$*NSIZE], x1d);
			z--;
		}
		if ((z0 - start) & 2) {
			STEP2(&wp$$, &wq$$, &dptr[z][d+$$*NSIZE], &dptr[z-1][d+$$*NSIZE], x1d);
			z -= 2;
		}
		for ( ; z >= start ; z -= 4 ) {
			STEP4(&wp$$, &wq$$, &dptr[z][d+$$*NSIZE], &dptr[z-1][d+$$*NSIZE], &dptr[z-2][d+$$*NSIZE], &dptr[z-3][d+$$*NSIZE], x1d);
		}

		/* P/Q left side optimization: multiply by g^start */
		if (start) {
			wq$$ = GFMUL(wq$$, gm0, gm1);
		}

		wq$$ ^= vld1q_u8(&q[d+NSIZE*$$]);
		vst1q_u8(&p[d+NSIZE*$$], wp$$);
		vst1q_u8(&q[d+NSIZE*$$], wq$$);
	}
}
