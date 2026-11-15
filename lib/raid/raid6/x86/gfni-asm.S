/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * RAID-6 P/Q syndrome generation using x86 Galois Field New Instructions
 *
 * The Q syndrome is computed as Q = sum(g^z * D[z]) over GF(2^8) using the
 * reducing polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d) and g = {02}.  This
 * rules out GF2P8MULB, which hardcodes the AES polynomial 0x11b.  However,
 * multiplication by a constant is a linear map over GF(2) in any
 * representation of GF(2^8), and so it can be expressed as an 8x8 bit matrix
 * that GF2P8AFFINEQB applies to each byte of a vector in a single instruction.
 * This replaces the 4-5 instruction compare/add/and/xor sequence that is used
 * by the plain AVX2 and AVX-512 code to multiply by {02}.
 *
 * Q is evaluated using Horner's rule, but two data disks at a time, i.e.,
 *
 *   Q' = g^2 * Q + g * D[z+1] + D[z]
 *
 * which halves the length of the multiply/add dependency chain through Q.  On
 * AVX-512, it also allows the additions to be folded into three-way XORs
 * using VPTERNLOGQ.  Note that GF2P8AFFINEQB only takes the matrix operand
 * from memory, so D[z+1] is loaded into a register explicitly.  D[z] only
 * needs to be added to P and Q, which is done using memory operands.
 *
 * The caller passes a pointer to an array of matrices that multiply by
 *
 *   [0] g, [1] g^2, [2] g^start (xor_syndrome only)
 *
 * The latter is used to apply the 'left side' scaling in xor_syndrome() using
 * a single instruction, rather than multiplying by g repeatedly.
 */

#include <linux/linkage.h>

/* Arguments shared by all routines */
#define PTRS	%rdi		/* array of data disk pointers, rebased to 'start' */
#define N	%rsi		/* index of highest data disk in PTRS[] */
#define BYTES	%rdx		/* number of bytes per disk */
#define MATS	%rcx		/* pointer to the matrices, see above */
#define P	%r8		/* pointer to P syndrome */
#define Q	%r9		/* pointer to Q syndrome */

#define OFF	%rax		/* byte offset into each data disk */
#define Z	%rcx		/* disk index - aliases MATS which is dead by then */
#define PZ1	%r10		/* pointer into data disk Z - 1 */
#define PZ2	%r11		/* pointer into data disk Z - 2 */

/*
 * Vector register allocation: lane i in [0, 4) keeps its P and Q accumulators
 * in register i and i + 4, respectively.  The temporaries are shared between
 * lanes: register renaming takes care of the false dependencies.
 */
#define T0	8
#define T1	9
#define A1	13		/* multiplication by g */
#define A2	14		/* multiplication by g^2 */
#define AS	15		/* multiplication by g^start */

.macro	_vmov	v, src, dst
.ifc \v, z
	vmovdqa64	\src, \dst
.else
	vmovdqa		\src, \dst
.endif
.endm

.macro	_vxor	v, src2, src1, dst
.ifc \v, z
	vpxorq		\src2, \src1, \dst
.else
	vpxor		\src2, \src1, \dst
.endif
.endm

/* Invoke \m for each of the \n lanes */
.macro	_for_each_lane	n, v, m, args:vararg
	\m	\v, \args, 0, %\v\()mm0, %\v\()mm4
	\m	\v, \args, 1, %\v\()mm1, %\v\()mm5
.if \n > 2
	\m	\v, \args, 2, %\v\()mm2, %\v\()mm6
	\m	\v, \args, 3, %\v\()mm3, %\v\()mm7
.endif
.endm

/* Q = D[N], P = D[N] (gen) or P = P ^ D[N] (xor) */
.macro	_lane_init	v, op, vl, i, p, q
	_vmov		\v, \i*\vl(PZ1), \q
.ifc \op, gen
	_vmov		\v, \q, \p
.else
	_vxor		\v, \i*\vl(P), \q, \p
.endif
.endm

/* Q = g * Q + D[Z - 1], P = P + D[Z - 1] */
.macro	_lane_step1	v, vl, i, p, q
	vgf2p8affineqb	$0, %\v\()mm\()A1, \q, \q
	_vmov		\v, \i*\vl(PZ1), %\v\()mm\()T0
	_vxor		\v, %\v\()mm\()T0, \q, \q
	_vxor		\v, %\v\()mm\()T0, \p, \p
.endm

/* Q = g^2 * Q + g * D[Z - 1] + D[Z - 2], P = P + D[Z - 1] + D[Z - 2] */
.macro	_lane_step2	v, vl, i, p, q
	_vmov		\v, \i*\vl(PZ1), %\v\()mm\()T0
	vgf2p8affineqb	$0, %\v\()mm\()A1, %\v\()mm\()T0, %\v\()mm\()T1
	vgf2p8affineqb	$0, %\v\()mm\()A2, \q, \q
.ifc \v, z
	vpternlogq	$0x96, \i*\vl(PZ2), %zmm\()T1, \q
	vpternlogq	$0x96, \i*\vl(PZ2), %zmm\()T0, \p
.else
	vpxor		\i*\vl(PZ2), %ymm\()T1, %ymm\()T1
	vpxor		\i*\vl(PZ2), %ymm\()T0, %ymm\()T0
	vpxor		%ymm\()T1, \q, \q
	vpxor		%ymm\()T0, \p, \p
.endif
.endm

/* Store P and Q using non-temporal stores */
.macro	_lane_store_gen	v, vl, i, p, q
	vmovntdq	\p, \i*\vl(P)
	vmovntdq	\q, \i*\vl(Q)
.endm

/* Q = Q + g^start * Q', and store P and Q */
.macro	_lane_store_xor	v, vl, i, p, q
	vgf2p8affineqb	$0, %\v\()mm\()AS, \q, \q
	_vxor		\v, \i*\vl(Q), \q, \q
	_vmov		\v, \p, \i*\vl(P)
	_vmov		\v, \q, \i*\vl(Q)
.endm

/*
 * void raid6_gfni_<isa>_<op>_x<n>(void **ptrs, unsigned long n, size_t bytes,
 *				   const u64 mats[], u8 *p, u8 *q);
 *
 * \op:	'gen' to generate P and Q from ptrs[0..n], or 'xor' to update P and Q
 *	in place with the contribution of ptrs[0..n] (which the caller has
 *	rebased to point to the 'start' disk).
 * \v:	'y' for AVX2 (32 byte vectors) or 'z' for AVX-512 (64 byte vectors)
 * \n:	the number of vectors to process in parallel
 */
.macro	_raid6_gfni	op, v, n
.ifc \v, z
	.set		VL, 64
.else
	.set		VL, 32
.endif
	vpbroadcastq	0(MATS), %\v\()mm\()A1
	vpbroadcastq	8(MATS), %\v\()mm\()A2
.ifc \op, xor
	vpbroadcastq	16(MATS), %\v\()mm\()AS
.endif
	xor		%eax, %eax

.Lblock\@:
	mov		(PTRS, N, 8), PZ1
	add		OFF, PZ1
	_for_each_lane	\n, \v, _lane_init, \op, VL
	mov		N, Z

	/* Process a single disk if the number of remaining disks is odd */
	test		$1, Z
	jz		0f
	mov		-8(PTRS, Z, 8), PZ1
	add		OFF, PZ1
	dec		Z
	_for_each_lane	\n, \v, _lane_step1, VL
0:
	test		Z, Z
	jz		2f

	/* Process the remaining disks in pairs */
1:	mov		-8(PTRS, Z, 8), PZ1
	mov		-16(PTRS, Z, 8), PZ2
	add		OFF, PZ1
	add		OFF, PZ2
	_for_each_lane	\n, \v, _lane_step2, VL
	sub		$2, Z
	jnz		1b
2:
	_for_each_lane	\n, \v, _lane_store_\op, VL

	add		$(\n * VL), OFF
	add		$(\n * VL), P
	add		$(\n * VL), Q
	cmp		BYTES, OFF
	jb		.Lblock\@

.ifc \op, gen
	sfence
.endif
	vzeroupper
	RET
.endm

SYM_FUNC_START(raid6_gfni_avx2_gen_x2)
	_raid6_gfni	gen, y, 2
SYM_FUNC_END(raid6_gfni_avx2_gen_x2)

SYM_FUNC_START(raid6_gfni_avx2_xor_x2)
	_raid6_gfni	xor, y, 2
SYM_FUNC_END(raid6_gfni_avx2_xor_x2)

SYM_FUNC_START(raid6_gfni_avx2_gen_x4)
	_raid6_gfni	gen, y, 4
SYM_FUNC_END(raid6_gfni_avx2_gen_x4)

SYM_FUNC_START(raid6_gfni_avx2_xor_x4)
	_raid6_gfni	xor, y, 4
SYM_FUNC_END(raid6_gfni_avx2_xor_x4)

SYM_FUNC_START(raid6_gfni_avx512_gen_x2)
	_raid6_gfni	gen, z, 2
SYM_FUNC_END(raid6_gfni_avx512_gen_x2)

SYM_FUNC_START(raid6_gfni_avx512_xor_x2)
	_raid6_gfni	xor, z, 2
SYM_FUNC_END(raid6_gfni_avx512_xor_x2)

SYM_FUNC_START(raid6_gfni_avx512_gen_x4)
	_raid6_gfni	gen, z, 4
SYM_FUNC_END(raid6_gfni_avx512_gen_x4)

SYM_FUNC_START(raid6_gfni_avx512_xor_x4)
	_raid6_gfni	xor, z, 4
SYM_FUNC_END(raid6_gfni_avx512_xor_x4)
