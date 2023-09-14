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
