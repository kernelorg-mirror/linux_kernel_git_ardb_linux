/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Accelerated CRC32(C) using AArch64 CRC and PMULL instructions
 *
 * Copyright (C) 2016 - 2018 Linaro Ltd.
 * Copyright (C) 2024 Google LLC
 *
 * Author: Ard Biesheuvel <ardb@kernel.org>
 */

#include <linux/linkage.h>
#include <asm/alternative.h>
#include <asm/assembler.h>

	.cpu		generic+crc+crypto

	.macro		bitle, reg
	.endm

	.macro		bitbe, reg
	rbit		\reg, \reg
	.endm

	.macro		bytele, reg
	.endm

	.macro		bytebe, reg
	rbit		\reg, \reg
	lsr		\reg, \reg, #24
	.endm

	.macro		hwordle, reg
CPU_BE(	rev16		\reg, \reg	)
	.endm

	.macro		hwordbe, reg
CPU_LE(	rev		\reg, \reg	)
	rbit		\reg, \reg
CPU_BE(	lsr		\reg, \reg, #16	)
	.endm

	.macro		le, regs:vararg
	.irp		r, \regs
CPU_BE(	rev		\r, \r		)
	.endr
	.endm

	.macro		be, regs:vararg
	.irp		r, \regs
CPU_LE(	rev		\r, \r		)
	.endr
	.irp		r, \regs
	rbit		\r, \r
	.endr
	.endm

	.macro		__crc32, c, order=le
	bit\order	w0
	cmp		x2, #16
	b.lt		8f			// less than 16 bytes

	and		x7, x2, #0x1f
	and		x2, x2, #~0x1f
	cbz		x7, 32f			// multiple of 32 bytes

	and		x8, x7, #0xf
	ldp		x3, x4, [x1]
	add		x8, x8, x1
	add		x1, x1, x7
	ldp		x5, x6, [x8]
	\order		x3, x4, x5, x6

	tst		x7, #8
	crc32\c\()x	w8, w0, x3
	csel		x3, x3, x4, eq
	csel		w0, w0, w8, eq
	tst		x7, #4
	lsr		x4, x3, #32
	crc32\c\()w	w8, w0, w3
	csel		x3, x3, x4, eq
	csel		w0, w0, w8, eq
	tst		x7, #2
	lsr		w4, w3, #16
	crc32\c\()h	w8, w0, w3
	csel		w3, w3, w4, eq
	csel		w0, w0, w8, eq
	tst		x7, #1
	crc32\c\()b	w8, w0, w3
	csel		w0, w0, w8, eq
	tst		x7, #16
	crc32\c\()x	w8, w0, x5
	crc32\c\()x	w8, w8, x6
	csel		w0, w0, w8, eq
	cbz		x2, 0f

32:	ldp		x3, x4, [x1], #32
	sub		x2, x2, #32
	ldp		x5, x6, [x1, #-16]
	\order		x3, x4, x5, x6
	crc32\c\()x	w0, w0, x3
	crc32\c\()x	w0, w0, x4
	crc32\c\()x	w0, w0, x5
	crc32\c\()x	w0, w0, x6
	cbnz		x2, 32b
0:	bit\order	w0
	ret

8:	tbz		x2, #3, 4f
	ldr		x3, [x1], #8
	\order		x3
	crc32\c\()x	w0, w0, x3
4:	tbz		x2, #2, 2f
	ldr		w3, [x1], #4
	\order		w3
	crc32\c\()w	w0, w0, w3
2:	tbz		x2, #1, 1f
	ldrh		w3, [x1], #2
	hword\order	w3
	crc32\c\()h	w0, w0, w3
1:	tbz		x2, #0, 0f
	ldrb		w3, [x1]
	byte\order	w3
	crc32\c\()b	w0, w0, w3
0:	bit\order	w0
	ret
	.endm

	.align		5
SYM_FUNC_START(crc32_le_arm64)
	__crc32
SYM_FUNC_END(crc32_le_arm64)

	.align		5
SYM_FUNC_START(crc32c_le_arm64)
	__crc32		c
SYM_FUNC_END(crc32c_le_arm64)

	.align		5
SYM_FUNC_START(crc32_be_arm64)
	__crc32		order=be
SYM_FUNC_END(crc32_be_arm64)

	in		.req	x1
	len		.req	x2

	.macro		do_pmull32_3x, a0, a1, a2, b0, b1, b2
alternative_if_not ARM64_HAS_PMULL
	b		.La\@
alternative_else_nop_endif
	mov		v3.d[0], \a0
	mov		v4.d[0], \a1
	mov		v5.d[0], \a2
	pmull		\b0\().1q, \b0\().1d, v3.1d
	pmull		\b1\().1q, \b1\().1d, v4.1d
	pmull		\b2\().1q, \b2\().1d, v5.1d
.Lb\@:	eor		\b0\().8b, \b0\().8b, \b1\().8b
	eor		\b0\().8b, \b0\().8b, \b2\().8b
	mov		\a0, \b0\().d[0]

	.subsection	1
.La\@:	dup		v3.2s, w\a0
	dup		v4.2s, w\a1
	dup		v5.2s, w\a2

	ror		w\a0, w\a0, #8
	ror		w\a1, w\a1, #8
	ror		w\a2, w\a2, #8

	dup		\b0\().2s, \b0\().s[0]
	dup		\b1\().2s, \b1\().s[0]
	dup		\b2\().2s, \b2\().s[0]

	mov		v3.s[0], w\a0
	mov		v4.s[0], w\a1
	mov		v5.s[0], w\a2

	ext		v6.8b, \b0\().8b, \b0\().8b, #2
	ext		v7.8b, \b1\().8b, \b1\().8b, #2
	ext		v8.8b, \b2\().8b, \b2\().8b, #2

	/*
	 * The polynomial multiplication of two 32-bit values x and y can be
	 * decomposed as follows, where xN denotes the Nth least significant
	 * byte of x and (*) denotes 8x8->16 bit long polynomial multiplication
	 *
	 * rank:
	 *   0                                            (x0 (*) y0)        ^
	 *   1                             ((x1 (*) y0) ^ (x0 (*) y1)) <<  8 ^
	 *   2               ((x2 (*) y0) ^ (x1 (*) y1) ^ (x0 (*) y2)) << 16 ^
	 *   3 ((x3 (*) y0) ^ (x2 (*) y1) ^ (x1 (*) y2) ^ (x0 (*) y3)) << 24 ^
	 *   4               ((x3 (*) y1) ^ (x2 (*) y2) ^ (x1 (*) y3)) << 32 ^
	 *   5                             ((x3 (*) y2) ^ (x2 (*) y3)) << 40 ^
	 *   6                                            (x3 (*) y3)  << 48
	 *
	 * After reorganizing the input vectors into
	 *
	 *  { x1, x2, x3, x0 }, { x0, x1, x2, x3 }
	 *  { y0, y1, y2, y3 }, { y0, y1, y2, y3 }
	 *  { y2, y3, y0, y1 }, { y2, y3, y0, y1 }
	 *
	 * all 16 terms can be obtained by performing 8x8 -> 16 multiplication
	 * of the first vector with each of the subsequent ones, resulting in
	 *
	 *   a := { x1*y0, x2*y1, x3*y2, x0*y3 }, { x0*y0, x1*y1, x2*y2, x3*y3 }
	 *   b := { x1*y2, x2*y3, x3*y0, x0*y1 }, { x0*y2, x1*y3, x2*y0, x3*y1 }
	 *
	 * where each vector element is 16 bits wide.  Only minor manipulation
	 * is required to move the terms of each rank into the correct column:
	 *
	 * - the upper half of result 'a' has all ranks in the right place,
	 *   given that the elements are 16 bits wide
	 *
	 * - the lower half of result 'b' can be rotated left by 16 bits and
	 *   combined with the lower half of result 'a', to produce
	 *
	 *     { x1*y0 ^ x0*y1, x2*y1 ^ x1*y2, x3*y2 ^ x2*y3, x0*y3 ^ x3*y0 }
	 *
	 * - the preceding result has the rank 3 term 'x0*y3 ^ x3*y0' appearing
	 *   out of order, and it needs to be xor'ed with the following to
	 *   combine it with the other rank 3 term in the vector instead
	 *
	 *     { 0, x0*y3 ^ x3*y0, 0, x0*y3 ^ x3*y0 }
	 *
	 *   which can be constructed from the preceding result using dup and
	 *   zip2. The combined result contains elements of ranks 1, 3 and 5,
	 *   and so it needs to be shifted left by 8 bits.
	 *
	 * - ushll2 (long shift left) by 16 bits on the second vector produces
	 *
	 *     { 0, x0*y2, x1*y3, 0 }, { 0, x2*y0, x3*y1, 0 }
	 *
	 *   each of which has its elements of ranks 2 and 4 appearing in the
	 *   correct column.
	 *
	 * These manipulations are distributive over XOR, so they can be
	 * applied after combining the partial results of the three interleaved
	 * multiplications below.
	 */

	pmull		v6.8h, v6.8b, v3.8b
	pmull		v7.8h, v7.8b, v4.8b
	pmull		v8.8h, v8.8b, v5.8b
	eor		v6.16b, v6.16b, v7.16b
	pmull		v3.8h, \b0\().8b, v3.8b
	eor		v6.16b, v6.16b, v8.16b
	pmull		v4.8h, \b1\().8b, v4.8b
	pmull		v5.8h, \b2\().8b, v5.8b
	eor		v3.16b, v3.16b, v4.16b
	ushll2		\b0\().2d, v6.4s, #16
	eor		v3.16b, v3.16b, v5.16b
	ext		v6.8b, v6.8b, v6.8b, #6
	eor		v6.8b, v6.8b, v3.8b
	dup		v5.8h, v6.h[3]
	zip2		v5.8h, v6.8h, v5.8h
	eor		v3.16b, v3.16b, \b0\().16b
	eor		v6.8b, v6.8b, v5.8b
	ext		\b1\().16b, v3.16b, v3.16b, #8
	shl		\b2\().2d, v6.2d, #8
	b		.Lb\@
	.previous
	.endm

	/*
	 * w0: input CRC at entry, output CRC at exit
	 * x1: pointer to input buffer
	 * x2: length of input in bytes
	 */
	.macro		crc4way, insn, table, order=le
	bit\order	w0
	lsr		len, len, #6		// len := # of 64-byte blocks

	/* Process up to 64 blocks of 64 bytes at a time */
.La\@:	mov		x3, #64
	cmp		len, #64
	csel		x3, x3, len, hi		// x3 := min(len, 64)
	sub		len, len, x3

	/* Divide the input into 4 contiguous blocks */
	add		x4, x3, x3, lsl #1	// x4 :=  3 * x3
	add		x7, in, x3, lsl #4	// x7 := in + 16 * x3
	add		x8, in, x3, lsl #5	// x8 := in + 32 * x3
	add		x9, in, x4, lsl #4	// x9 := in + 16 * x4

	/* Load the folding coefficients from the lookup table */
	adr_l		x5, \table - 12		// entry 0 omitted
	add		x5, x5, x4, lsl #2	// x5 += 12 * x3
	ldp		s0, s1, [x5]
	ldr		s2, [x5, #8]

	/* Zero init partial CRCs for this iteration */
	mov		w4, wzr
	mov		w5, wzr
	mov		w6, wzr
	mov		x17, xzr

.Lb\@:	sub		x3, x3, #1
	\insn		w6, w6, x17
	ldp		x10, x11, [in], #16
	ldp		x12, x13, [x7], #16
	ldp		x14, x15, [x8], #16
	ldp		x16, x17, [x9], #16

	\order		x10, x11, x12, x13, x14, x15, x16, x17

	/* Apply the CRC transform to 4 16-byte blocks in parallel */
	\insn		w0, w0, x10
	\insn		w4, w4, x12
	\insn		w5, w5, x14
	\insn		w6, w6, x16
	\insn		w0, w0, x11
	\insn		w4, w4, x13
	\insn		w5, w5, x15
	cbnz		x3, .Lb\@

	/* Combine the 4 partial results into w0 */
	do_pmull32_3x	x0, x4, x5, v0, v1, v2
	eor		x0, x0, x17
	\insn		w0, w6, x0

	mov		in, x9
	cbnz		len, .La\@

	bit\order	w0
	ret
	.endm

	.align		5
SYM_FUNC_START(crc32c_le_arm64_4way)
	crc4way		crc32cx, .L0
SYM_FUNC_END(crc32c_le_arm64_4way)

	.align		5
SYM_FUNC_START(crc32_le_arm64_4way)
	crc4way		crc32x, .L1
SYM_FUNC_END(crc32_le_arm64_4way)

	.align		5
SYM_FUNC_START(crc32_be_arm64_4way)
	crc4way		crc32x, .L1, be
SYM_FUNC_END(crc32_be_arm64_4way)

	.section	.rodata, "a", %progbits
	.align		6
.L0:	.long		0xddc0152b, 0xba4fc28e, 0x493c7d27
	.long		0x0715ce53, 0x9e4addf8, 0xba4fc28e
	.long		0xc96cfdc0, 0x0715ce53, 0xddc0152b
	.long		0xab7aff2a, 0x0d3b6092, 0x9e4addf8
	.long		0x299847d5, 0x878a92a7, 0x39d3b296
	.long		0xb6dd949b, 0xab7aff2a, 0x0715ce53
	.long		0xa60ce07b, 0x83348832, 0x47db8317
	.long		0xd270f1a2, 0xb9e02b86, 0x0d3b6092
	.long		0x65863b64, 0xb6dd949b, 0xc96cfdc0
	.long		0xb3e32c28, 0xbac2fd7b, 0x878a92a7
	.long		0xf285651c, 0xce7f39f4, 0xdaece73e
	.long		0x271d9844, 0xd270f1a2, 0xab7aff2a
	.long		0x6cb08e5c, 0x2b3cac5d, 0x2162d385
	.long		0xcec3662e, 0x1b03397f, 0x83348832
	.long		0x8227bb8a, 0xb3e32c28, 0x299847d5
	.long		0xd7a4825c, 0xdd7e3b0c, 0xb9e02b86
	.long		0xf6076544, 0x10746f3c, 0x18b33a4e
	.long		0x98d8d9cb, 0x271d9844, 0xb6dd949b
	.long		0x57a3d037, 0x93a5f730, 0x78d9ccb7
	.long		0x3771e98f, 0x6b749fb2, 0xbac2fd7b
	.long		0xe0ac139e, 0xcec3662e, 0xa60ce07b
	.long		0x6f345e45, 0xe6fc4e6a, 0xce7f39f4
	.long		0xa2b73df1, 0xb0cd4768, 0x61d82e56
	.long		0x86d8e4d2, 0xd7a4825c, 0xd270f1a2
	.long		0xa90fd27a, 0x0167d312, 0xc619809d
	.long		0xca6ef3ac, 0x26f6a60a, 0x2b3cac5d
	.long		0x4597456a, 0x98d8d9cb, 0x65863b64
	.long		0xc9c8b782, 0x68bce87a, 0x1b03397f
	.long		0x62ec6c6d, 0x6956fc3b, 0xebb883bd
	.long		0x2342001e, 0x3771e98f, 0xb3e32c28
	.long		0xe8b6368b, 0x2178513a, 0x064f7f26
	.long		0x9ef68d35, 0x170076fa, 0xdd7e3b0c
	.long		0x0b0bf8ca, 0x6f345e45, 0xf285651c
	.long		0x02ee03b2, 0xff0dba97, 0x10746f3c
	.long		0x135c83fd, 0xf872e54c, 0xc7a68855
	.long		0x00bcf5f6, 0x86d8e4d2, 0x271d9844
	.long		0x58ca5f00, 0x5bb8f1bc, 0x8e766a0c
	.long		0xded288f8, 0xb3af077a, 0x93a5f730
	.long		0x37170390, 0xca6ef3ac, 0x6cb08e5c
	.long		0xf48642e9, 0xdd66cbbb, 0x6b749fb2
	.long		0xb25b29f2, 0xe9e28eb4, 0x1393e203
	.long		0x45cddf4e, 0xc9c8b782, 0xcec3662e
	.long		0xdfd94fb2, 0x93e106a4, 0x96c515bb
	.long		0x021ac5ef, 0xd813b325, 0xe6fc4e6a
	.long		0x8e1450f7, 0x2342001e, 0x8227bb8a
	.long		0xe0cdcf86, 0x6d9a4957, 0xb0cd4768
	.long		0x613eee91, 0xd2c3ed1a, 0x39c7ff35
	.long		0xbedc6ba1, 0x9ef68d35, 0xd7a4825c
	.long		0x0cd1526a, 0xf2271e60, 0x0ab3844b
	.long		0xd6c3a807, 0x2664fd8b, 0x0167d312
	.long		0x1d31175f, 0x02ee03b2, 0xf6076544
	.long		0x4be7fd90, 0x363bd6b3, 0x26f6a60a
	.long		0x6eeed1c9, 0x5fabe670, 0xa741c1bf
	.long		0xb3a6da94, 0x00bcf5f6, 0x98d8d9cb
	.long		0x2e7d11a7, 0x17f27698, 0x49c3cc9c
	.long		0x889774e1, 0xaa7c7ad5, 0x68bce87a
	.long		0x8a074012, 0xded288f8, 0x57a3d037
	.long		0xbd0bb25f, 0x6d390dec, 0x6956fc3b
	.long		0x3be3c09b, 0x6353c1cc, 0x42d98888
	.long		0x465a4eee, 0xf48642e9, 0x3771e98f
	.long		0x2e5f3c8c, 0xdd35bc8d, 0xb42ae3d9
	.long		0xa52f58ec, 0x9a5ede41, 0x2178513a
	.long		0x47972100, 0x45cddf4e, 0xe0ac139e
	.long		0x359674f7, 0xa51b6135, 0x170076fa

.L1:	.long		0xaf449247, 0x81256527, 0xccaa009e
	.long		0x57c54819, 0x1d9513d7, 0x81256527
	.long		0x3f41287a, 0x57c54819, 0xaf449247
	.long		0xf5e48c85, 0x910eeec1, 0x1d9513d7
	.long		0x1f0c2cdd, 0x9026d5b1, 0xae0b5394
	.long		0x71d54a59, 0xf5e48c85, 0x57c54819
	.long		0x1c63267b, 0xfe807bbd, 0x0cbec0ed
	.long		0xd31343ea, 0xe95c1271, 0x910eeec1
	.long		0xf9d9c7ee, 0x71d54a59, 0x3f41287a
	.long		0x9ee62949, 0xcec97417, 0x9026d5b1
	.long		0xa55d1514, 0xf183c71b, 0xd1df2327
	.long		0x21aa2b26, 0xd31343ea, 0xf5e48c85
	.long		0x9d842b80, 0xeea395c4, 0x3c656ced
	.long		0xd8110ff1, 0xcd669a40, 0xfe807bbd
	.long		0x3f9e9356, 0x9ee62949, 0x1f0c2cdd
	.long		0x1d6708a0, 0x0c30f51d, 0xe95c1271
	.long		0xef82aa68, 0xdb3935ea, 0xb918a347
	.long		0xd14bcc9b, 0x21aa2b26, 0x71d54a59
	.long		0x99cce860, 0x356d209f, 0xff6f2fc2
	.long		0xd8af8e46, 0xc352f6de, 0xcec97417
	.long		0xf1996890, 0xd8110ff1, 0x1c63267b
	.long		0x631bc508, 0xe95c7216, 0xf183c71b
	.long		0x8511c306, 0x8e031a19, 0x9b9bdbd0
	.long		0xdb3839f3, 0x1d6708a0, 0xd31343ea
	.long		0x7a92fffb, 0xf7003835, 0x4470ac44
	.long		0x6ce68f2a, 0x00eba0c8, 0xeea395c4
	.long		0x4caaa263, 0xd14bcc9b, 0xf9d9c7ee
	.long		0xb46f7cff, 0x9a1b53c8, 0xcd669a40
	.long		0x60290934, 0x81b6f443, 0x6d40f445
	.long		0x8e976a7d, 0xd8af8e46, 0x9ee62949
	.long		0xdcf5088a, 0x9dbdc100, 0x145575d5
	.long		0x1753ab84, 0xbbf2f6d6, 0x0c30f51d
	.long		0x255b139e, 0x631bc508, 0xa55d1514
	.long		0xd784eaa8, 0xce26786c, 0xdb3935ea
	.long		0x6d2c864a, 0x8068c345, 0x2586d334
	.long		0x02072e24, 0xdb3839f3, 0x21aa2b26
	.long		0x06689b0a, 0x5efd72f5, 0xe0575528
	.long		0x1e52f5ea, 0x4117915b, 0x356d209f
	.long		0x1d3d1db6, 0x6ce68f2a, 0x9d842b80
	.long		0x3796455c, 0xb8e0e4a8, 0xc352f6de
	.long		0xdf3a4eb3, 0xc55a2330, 0xb84ffa9c
	.long		0x28ae0976, 0xb46f7cff, 0xd8110ff1
	.long		0x9764bc8d, 0xd7e7a22c, 0x712510f0
	.long		0x13a13e18, 0x3e9a43cd, 0xe95c7216
	.long		0xb8ee242e, 0x8e976a7d, 0x3f9e9356
	.long		0x0c540e7b, 0x753c81ff, 0x8e031a19
	.long		0x9924c781, 0xb9220208, 0x3edcde65
	.long		0x3954de39, 0x1753ab84, 0x1d6708a0
	.long		0xf32238b5, 0xbec81497, 0x9e70b943
	.long		0xbbd2cd2c, 0x0925d861, 0xf7003835
	.long		0xcc401304, 0xd784eaa8, 0xef82aa68
	.long		0x4987e684, 0x6044fbb0, 0x00eba0c8
	.long		0x3aa11427, 0x18fe3b4a, 0x87441142
	.long		0x297aad60, 0x02072e24, 0xd14bcc9b
	.long		0xf60c5e51, 0x6ef6f487, 0x5b7fdd0a
	.long		0x632d78c5, 0x3fc33de4, 0x9a1b53c8
	.long		0x25b8822a, 0x1e52f5ea, 0x99cce860
	.long		0xd4fc84bc, 0x1af62fb8, 0x81b6f443
	.long		0x5690aa32, 0xa91fdefb, 0x688a110e
	.long		0x1357a093, 0x3796455c, 0xd8af8e46
	.long		0x798fdd33, 0xaaa18a37, 0x357b9517
	.long		0xc2815395, 0x54d42691, 0x9dbdc100
	.long		0x21cfc0f7, 0x28ae0976, 0xf1996890
	.long		0xa0decef3, 0x7b4aa8b7, 0xbbf2f6d6
