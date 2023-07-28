/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Scalar AES core transform using RISC-V Zkned extensions
 *
 * Copyright (C) 2023 Google, LLC.
 * Author: Ard Biesheuvel <ardb@kernel.org>
 */

#include <linux/linkage.h>
#include <asm/insn-def.h>

#ifdef CONFIG_AS_HAS_OPTION_ARCH
	.option	arch, +zkn
#else
	// Zkn RV64 opcodes
	.macro	aes64es, rd, rs1, rs2
	insn_r	0x33, 0, 0x19, \rd, \rs1, \rs2
	.endm

	.macro	aes64esm, rd, rs1, rs2
	insn_r	0x33, 0, 0x1b, \rd, \rs1, \rs2
	.endm

	.macro	aes64ds, rd, rs1, rs2
	insn_r	0x33, 0, 0x1d, \rd, \rs1, \rs2
	.endm

	.macro	aes64dsm, rd, rs1, rs2
	insn_r	0x33, 0, 0x1f, \rd, \rs1, \rs2
	.endm

	.macro	aes64im, rd, rs1
	insn_i	0x13, 0x1, \rd, \rs1, 0x300
	.endm

	.macro	aes64ks1i, rd, rs1, rnum
	insn_i	0x13, 0x1, \rd, \rs1, (0x310 | \rnum)
	.endm

	.macro	aes64ks2, rd, rs1, rs2
	insn_r	0x33, 0, 0x3f, \rd, \rs1, \rs2
	.endm
#endif

	// One AES round
	.macro		round, ed, rkp, st0, st1, in0, in1, tt, op=sm
	ld		\tt, 0(\rkp)		// Load next round key
	add		\rkp, \rkp, 16		// Advance round key pointer
	aes64\ed\op	\st0, \in0, \in1
	aes64\ed\op	\st1, \in1, \in0
	ld		\in0, -8(\rkp)
	xor		\st0, \st0, \tt
	xor		\st1, \st1, \in0
	.endm

	.macro		crypt, ed
	ld		t0, 0(a3)		// Load input block
	ld		t1, 8(a3)
	ld		t2, 0(a0)		// Load first round key
	ld		t3, 8(a0)
	add		t4, a0, 16
	add		t5, a1, -2

	xor		t0, t0, t2
	xor		t1, t1, t3
.La\@:	round		\ed, t4, t2, t1, t0, t1, t3
	beqz		t5, .Lb\@
	round		\ed, t4, t0, t1, t2, t1, t3
	add		t5, t5, -2
	j		.La\@
.Lb\@:	round		\ed, t4, t0, t1, t2, t1, t3, s

	sd		t0, 0(a2)		// Store output block
	sd		t1, 8(a2)
	ret
	.endm

SYM_FUNC_START(__aes_riscv_scalar_encrypt)
	crypt	e
SYM_FUNC_END(__aes_riscv_scalar_encrypt)

SYM_FUNC_START(__aes_riscv_scalar_decrypt)
	crypt	d
SYM_FUNC_END(__aes_riscv_scalar_decrypt)

/* __aes_riscv_scalar_expand_key(u32 *enc_key, u32 *dec_key, int keylen) */
SYM_FUNC_START(__aes_riscv_scalar_expand_key)
	ld		t0, 0(a0)
	ld		t1, 8(a0)
	add		a3, a0, a2		// Advance key pointer by keylen
	ld		t2, -16(a3)		// Loads overlap for AES 128/192
	ld		t3, -8(a3)
	add		a4, a2, -24		// Subtract keylen of AES-192

	// Encryption key schedule
	.irpc		r, 0123456789		// Up to 10 iterations
	aes64ks1i	t4, t3, \r
	.if		\r < 8
	  bltz		a4, 0f			// Skip forward for AES-128
	  aes64ks2	t0, t4, t0
	  sd		t0, 0(a3)
	  mv		t4, t0
	  .if		\r < 7
	    beqz	a4, 0f			// Skip forward for AES-192
	    aes64ks2	t1, t0, t1
	    sd		t1, 8(a3)
	    .if		\r == 6			// Final iteration for AES-256
	      j		3f			// Last round key present in t0/t1
	    .endif
	    aes64ks1i	t4, t1, 10
	  .endif
	.endif
0:	add		a3, a3, a2		// Advance key pointer by keylen
	aes64ks2	t2, t4, t2
	sd		t2, -16(a3)
	.if		\r == 7			// Final iteration for AES-192
	  beqz		a4, 1f			// Last round key present in t0/t2
	.endif
	aes64ks2	t3, t2, t3
	sd		t3, -8(a3)
	.endr

	// Decryption key schedule
	mv		t0, t2			// Move last round key into t0/t1
	mv		t2, t3
1:	mv		t1, t2
	sub		a3, a3, a2		// Point enc_key pointer to last entry
	j		3f
2:	  aes64im	t0, t0
	  aes64im	t1, t1
3:	  add		a3, a3, -16
	  sd		t0, 0(a1)		// Store next decryption key
	  sd		t1, 8(a1)
	  add		a1, a1, 16
	  ld		t0, 0(a3)		// Load previous encryption key
	  ld		t1, 8(a3)
	bne		a0, a3, 2b
	sd		t0, 0(a1)		// Store last decryption key
	sd		t1, 8(a1)
	ret
SYM_FUNC_END(__aes_riscv_scalar_expand_key)
