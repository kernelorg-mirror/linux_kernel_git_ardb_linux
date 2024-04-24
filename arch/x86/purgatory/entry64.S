/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2003,2004  Eric Biederman (ebiederm@xmission.com)
 * Copyright (C) 2014  Red Hat Inc.

 * Author(s): Vivek Goyal <vgoyal@redhat.com>
 *
 * This code has been taken from kexec-tools.
 */

#include <linux/linkage.h>

	.text
	.balign 16
	.code64

SYM_CODE_START(entry64)
	/* Setup a gdt that should be preserved */
	leaq	gdt(%rip), %rax
	pushq	%rax
	pushw	$gdt_end - gdt - 1
	lgdt	(%rsp)
	addq	$10, %rsp

	/* load the data segments */
	xorl    %eax, %eax     /* data segment */
	movl    %eax, %ds
	movl    %eax, %es
	movl    %eax, %ss
	movl    %eax, %fs
	movl    %eax, %gs

	pushq   $0x8 /* CS */
	leaq    new_cs_exit(%rip), %rax
	pushq   %rax
	lretq
new_cs_exit:

	/* Load the registers */
	leaq	entry64_regs(%rip), %r15
	movq	0x00(%r15), %rax
	movq	0x08(%r15), %rcx
	movq	0x10(%r15), %rdx
	movq	0x18(%r15), %rbx
	movq	0x20(%r15), %rbp
	movq	0x28(%r15), %rsi
	movq	0x30(%r15), %rdi
	movq	0x38(%r15), %r8
	movq	0x40(%r15), %r9
	movq	0x48(%r15), %r10
	movq	0x50(%r15), %r11
	movq	0x58(%r15), %r12
	movq	0x60(%r15), %r13
	movq	0x68(%r15), %r14
	movq	0x70(%r15), %r15

	/* Jump to the new code... */
	jmpq	*.Lrip(%rip)
SYM_CODE_END(entry64)

	.section ".rodata"
	.balign	8
SYM_DATA_START(entry64_regs)
.Lrax:	.quad	0x0
.Lrcx:	.quad	0x0
.Lrdx:	.quad	0x0
.Lrbx:	.quad	0x0
.Lrbp:	.quad	0x0
.Lrsi:	.quad	0x0
.Lrdi:	.quad	0x0
.Lr8:	.quad	0x0
.Lr9:	.quad	0x0
.Lr10:	.quad	0x0
.Lr11:	.quad	0x0
.Lr12:	.quad	0x0
.Lr13:	.quad	0x0
.Lr14:	.quad	0x0
.Lr15:	.quad	0x0
.Lrip:	.quad	0x0
SYM_DATA_END(entry64_regs)

	/* GDT */
	.section ".rodata"
	.balign 16
SYM_DATA_START_LOCAL(gdt)
	/*
	 * 0x00 unusable segment
	 */
	.quad 0

	/* 0x8 4GB flat code segment */
	.word 0xFFFF, 0x0000, 0x9A00, 0x00AF
SYM_DATA_END_LABEL(gdt, SYM_L_LOCAL, gdt_end)
