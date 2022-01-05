/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * BLAKE2s digest algorithm, ARM scalar implementation
 *
 * Copyright 2020-2022 Google LLC
 *
 * Author: Eric Biggers <ebiggers@google.com>
 * Ported to arm64 by Ard Biesheuvel <ardb@kernel.org>
 */

#include <linux/linkage.h>
#include <asm/assembler.h>

	// Registers used to hold message words temporarily.  There aren't
	// enough ARM registers to hold the whole message block, so we have to
	// load the words on-demand.
	M_0		.req	w23
	M_1		.req	w24
	M_2		.req	w25
	M_3		.req	w26
	T_0		.req	w16
	T_1		.req	w17
	T_2		.req	w27
	T_3		.req	w28

// The BLAKE2s initialization vector
.Lblake2s_IV:
	.word	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
	.word	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19

.macro _blake2s_load_words	s0, s1, s2, s3
	ldr		M_0, [x20, #4 * \s0]
	ldr		M_1, [x20, #4 * \s1]
	ldr		M_2, [x20, #4 * \s2]
	ldr		M_3, [x20, #4 * \s3]

CPU_BE(	rev		M_0, M_0	)
CPU_BE(	rev		M_1, M_1	)
CPU_BE(	rev		M_2, M_2	)
CPU_BE(	rev		M_3, M_3	)
.endm

// Execute a quarter-round of BLAKE2s by mixing two columns or two diagonals.
// (a0, b0, c0, d0) and (a1, b1, c1, d1) give the registers containing the two
// columns/diagonals.  s0-s1 are the word offsets to the message words the first
// column/diagonal needs, and likewise s2-s3 for the second column/diagonal.
//
// Note that to save instructions, the rotations don't happen when the
// pseudocode says they should, but rather they are delayed until the values are
// used.  See the comment above _blake2s_round().
.macro _blake2s_halfround  a0, b0, c0, d0,  a1, b1, c1, d1, \
			   a2, b2, c2, d2,  a3, b3, c3, d3, \
			   s0, s1, s2, s3, s4, s5, s6, s7

	_blake2s_load_words	\s0, \s2, \s4, \s6

	// a += b + m[blake2s_sigma[r][2*i + 0]];
	.if		brot != 0
	ror		T_0, \b0, #brot
	ror		T_1, \b1, #brot
	ror		T_2, \b2, #brot
	ror		T_3, \b3, #brot
	add		\a0, \a0, T_0
	add		\a1, \a1, T_1
	add		\a2, \a2, T_2
	add		\a3, \a3, T_3
	.else
	add		\a0, \a0, \b0
	add		\a1, \a1, \b1
	add		\a2, \a2, \b2
	add		\a3, \a3, \b3
	.endif
	add		\a0, \a0, M_0
	add		\a1, \a1, M_1
	add		\a2, \a2, M_2
	add		\a3, \a3, M_3

	_blake2s_load_words	\s1, \s3, \s5, \s7

	// d = ror32(d ^ a, 16);
	eor		\d0, \a0, \d0, ror #drot
	eor		\d1, \a1, \d1, ror #drot
	eor		\d2, \a2, \d2, ror #drot
	eor		\d3, \a3, \d3, ror #drot

	// c += d;
	ror		T_0, \d0, #16
	ror		T_1, \d1, #16
	ror		T_2, \d2, #16
	ror		T_3, \d3, #16
	add		\c0, \c0, T_0
	add		\c1, \c1, T_1
	add		\c2, \c2, T_2
	add		\c3, \c3, T_3

	// b = ror32(b ^ c, 12);
	eor		\b0, \c0, \b0, ror #brot
	eor		\b1, \c1, \b1, ror #brot
	eor		\b2, \c2, \b2, ror #brot
	eor		\b3, \c3, \b3, ror #brot

	// a += b + m[blake2s_sigma[r][2*i + 1]];
	ror		T_0, \b0, #12
	ror		T_1, \b1, #12
	ror		T_2, \b2, #12
	ror		T_3, \b3, #12
	add		\a0, \a0, T_0
	add		\a1, \a1, T_1
	add		\a2, \a2, T_2
	add		\a3, \a3, T_3
	add		\a0, \a0, M_0
	add		\a1, \a1, M_1
	add		\a2, \a2, M_2
	add		\a3, \a3, M_3

	// d = ror32(d ^ a, 8);
	eor		\d0, \a0, \d0, ror#16
	eor		\d1, \a1, \d1, ror#16
	eor		\d2, \a2, \d2, ror#16
	eor		\d3, \a3, \d3, ror#16

	// c += d;
	ror		T_0, \d0, #8
	ror		T_1, \d1, #8
	ror		T_2, \d2, #8
	ror		T_3, \d3, #8
	add		\c0, \c0, T_0
	add		\c1, \c1, T_1
	add		\c2, \c2, T_2
	add		\c3, \c3, T_3

	// b = ror32(b ^ c, 7);
	eor		\b0, \c0, \b0, ror#12
	eor		\b1, \c1, \b1, ror#12
	eor		\b2, \c2, \b2, ror#12
	eor		\b3, \c3, \b3, ror#12
.endm

// Execute one round of BLAKE2s by updating the state matrix v[0..15].  The
// macro arguments s0-s15 give the order in which the message words are used in
// this round.
//
// All rotates are performed using the implicit rotate operand accepted by the
// 'add' and 'eor' instructions.  This is faster than using explicit rotate
// instructions.  To make this work, we allow the values in the second and last
// rows of the BLAKE2s state matrix (rows 'b' and 'd') to temporarily have the
// wrong rotation amount.  The rotation amount is then fixed up just in time
// when the values are used.  'brot' is the number of bits the values in row 'b'
// need to be rotated right to arrive at the correct values, and 'drot'
// similarly for row 'd'.  (brot, drot) start out as (0, 0) but we make it such
// that they end up as (7, 8) after every round.
.macro	_blake2s_round	s0, s1, s2, s3, s4, s5, s6, s7, \
			s8, s9, s10, s11, s12, s13, s14, s15

	// Mix columns:
	// (v[0], v[4], v[8], v[12]) and (v[1], v[5], v[9], v[13]).
	// (v[2], v[6], v[10], v[14]) and (v[3], v[7], v[11], v[15]).
	_blake2s_halfround	w0, w4, w8, w12,  w1, w5, w9, w13, \
				w2, w6, w10, w14,  w3, w7, w11, w15, \
				\s0, \s1, \s2, \s3, \s4, \s5, \s6, \s7

	.set brot, 7
	.set drot, 8

	// Mix diagonals:
	// (v[0], v[5], v[10], v[15]) and (v[1], v[6], v[11], v[12]).
	// (v[2], v[7], v[8], v[13]) and (v[3], v[4], v[9], v[14]).
	_blake2s_halfround	w0, w5, w10, w15,  w1, w6, w11, w12, \
				w2, w7, w8, w13,  w3, w4, w9, w14, \
				\s8, \s9, \s10, \s11, \s12, \s13, \s14, \s15
.endm

//
// void blake2s_compress(struct blake2s_state *state,
//			 const u8 *block, size_t nblocks, u32 inc);
//
// Only the first three fields of struct blake2s_state are used:
//	u32 h[8];	(inout)
//	u32 t[2];	(inout)
//	u32 f[2];	(in)
//
	.align		5
SYM_FUNC_START(blake2s_compress_arch)
	frame_push	10

	mov		x19, x0			// x19 is 'state'
	mov		x20, x1			// x20 is 'block'
	mov		x21, x2			// x21 is 'nblocks'
	mov		w22, w3			// w22 is 'inc'

.Lnext_block:
	// Load and increment the counter t[0..1].
	ldp		w16, w17, [x19, #32]
	adds		w16, w16, w22
	adc		w17, w17, wzr
	stp		w16, w17, [x19, #32]

	// Calculate v[8..15].
	adr		x15, .Lblake2s_IV
	ldp		w8, w9, [x15], #8	// load IV[0..1]
	ldp		w10, w11, [x15], #8	// load IV[2..3]
	ldp		w12, w13, [x15], #8	// load IV[4..5]
	ldp		w14, w15, [x15]		// load IV[6..7]
	ldp		w0, w1, [x19, #40]	// load f[0..1]
	eor		w12, w12, w16		// v[12] = IV[4] ^ t[0]
	eor		w13, w13, w17		// v[13] = IV[5] ^ t[1]
	eor		w14, w14, w0		// v[14] = IV[6] ^ f[0]
	eor		w15, w15, w1		// v[15] = IV[7] ^ f[1]

	// Load h[0..7] == v[0..7].
	ldp		w0, w1, [x19]
	ldp		w2, w3, [x19, #8]
	ldp		w4, w5, [x19, #16]
	ldp		w6, w7, [x19, #24]

	// Execute the rounds.  Each round is provided the order in which it
	// needs to use the message words.
	.set brot, 0
	.set drot, 0
	_blake2s_round	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
	_blake2s_round	14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
	_blake2s_round	11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4
	_blake2s_round	7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8
	_blake2s_round	9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13
	_blake2s_round	2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9
	_blake2s_round	12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11
	_blake2s_round	13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10
	_blake2s_round	6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5
	_blake2s_round	10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0

	// Fold the final state matrix into the hash chaining value:
	//
	//	for (i = 0; i < 8; i++)
	//		h[i] ^= v[i] ^ v[i + 8];
	//
	eor		w0, w0, w8
	eor		w1, w1, w9
	ldp		w8, w9, [x19]		// load h[0..1]
	eor		w2, w2, w10
	eor		w3, w3, w11
	ldp		w10, w11, [x19, #8] 	// load h[2..3]
	eor		w0, w0, w8
	eor		w1, w1, w9
	eor		w2, w2, w10
	eor		w3, w3, w11
	stp		w0, w1, [x19]		// store new h[0..1]
	stp		w2, w3, [x19, #8]	// store new h[0..3]
	ldp		w0, w1, [x19, #16]	// load old h[4..5]
	ldp		w2, w3, [x19, #24]	// load old h[6..7]
	eor		w0, w0, w4, ror #brot
	eor		w1, w1, w5, ror #brot
	eor		w2, w2, w6, ror #brot
	eor		w3, w3, w7, ror #brot
	eor		w0, w0, w12, ror #drot
	eor		w1, w1, w13, ror #drot
	eor		w2, w2, w14, ror #drot
	eor		w3, w3, w15, ror #drot
	stp		w0, w1, [x19, #16]
	stp		w2, w3, [x19, #24]

	// Advance to the next block, if there is one.
	subs		x21, x21, #1		// nblocks--
	add		x20, x20, #64
	b.ne		.Lnext_block		// nblocks != 0?

	frame_pop
	ret
SYM_FUNC_END(blake2s_compress_arch)
