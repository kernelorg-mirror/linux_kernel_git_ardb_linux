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
	// Zkn RV32 opcodes
	.macro	aes32esi, rd, rs1, rs2, bs
	insn_r	0x33, 0, (0x11 | ((\bs) << 5)), \rd, \rs1, \rs2
	.endm

	.macro	aes32esmi, rd, rs1, rs2, bs
	insn_r	0x33, 0, (0x13 | ((\bs) << 5)), \rd, \rs1, \rs2
	.endm

	.macro	aes32dsi, rd, rs1, rs2, bs
	insn_r	0x33, 0, (0x15 | ((\bs) << 5)), \rd, \rs1, \rs2
	.endm

	.macro	aes32dsmi, rd, rs1, rs2, bs
	insn_r	0x33, 0, (0x17 | ((\bs) << 5)), \rd, \rs1, \rs2
	.endm
#endif

	// Load next round key and advance round key pointer
	.macro		next_rk, rkp, rk0, rk1, rk2, rk3
	lw		\rk0,  0(\rkp)
	lw		\rk1,  4(\rkp)
	lw		\rk2,  8(\rkp)
	lw		\rk3, 12(\rkp)
	add		\rkp, \rkp, 16
	.endm

	// AES quarter round
	.macro		qround, op, o0, o1, o2, o3, i0, i1, i2, i3, bs
	aes32\op	\o0, \o0, \i0, \bs
	aes32\op	\o1, \o1, \i1, \bs
	aes32\op	\o2, \o2, \i2, \bs
	aes32\op	\o3, \o3, \i3, \bs
	.endm

	.set		.Lshe, 0
	.set		.Lshd, 2

	// One AES round
	.macro		round, ed, o0, o1, o2, o3, i0, i1, i2, i3, op=smi
	qround		\ed\op, \o0, \o1, \o2, \o3, \i0, \i1, \i2, \i3, 0
	qround		\ed\op, \o0, \o1, \o2, \o3, \i1, \i2, \i3, \i0, 1 ^ .Lsh\ed
	qround		\ed\op, \o0, \o1, \o2, \o3, \i2, \i3, \i0, \i1, 2
	qround		\ed\op, \o0, \o1, \o2, \o3, \i3, \i0, \i1, \i2, 3 ^ .Lsh\ed
	.endm

	.macro		crypt, ed
	lw		t0,  0(a3)
	lw		t1,  4(a3)
	lw		t2,  8(a3)
	lw		t3, 12(a3)

	next_rk		a0, a3, t4, t5, t6
	xor		t0, t0, a3
	xor		t1, t1, t4
	xor		t2, t2, t5
	xor		t3, t3, t6

0:	next_rk		a0, a3, t4, t5, t6
	add		a1, a1, -2
	round		\ed, a3, t4, t5, t6, t0, t1, t2, t3
	next_rk		a0, t0, t1, t2, t3
	beqz		a1, 1f
	round		\ed, t0, t1, t2, t3, a3, t4, t5, t6
	j		0b
1:	round		\ed, t0, t1, t2, t3, a3, t4, t5, t6, si

	sw		t0,  0(a2)
	sw		t1,  4(a2)
	sw		t2,  8(a2)
	sw		t3, 12(a2)
	ret
	.endm

SYM_FUNC_START(__aes_riscv_scalar_encrypt)
	crypt	e
SYM_FUNC_END(__aes_riscv_scalar_encrypt)

SYM_FUNC_START(__aes_riscv_scalar_decrypt)
	crypt	d
SYM_FUNC_END(__aes_riscv_scalar_decrypt)
