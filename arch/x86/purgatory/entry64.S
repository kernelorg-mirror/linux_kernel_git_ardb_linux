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
	movq	rax(%rip), %rax
	movq	rbx(%rip), %rbx
	movq	rcx(%rip), %rcx
	movq	rdx(%rip), %rdx
	movq	rsi(%rip), %rsi
	movq	rdi(%rip), %rdi
	movq	rbp(%rip), %rbp
	movq	r8(%rip), %r8
	movq	r9(%rip), %r9
	movq	r10(%rip), %r10
	movq	r11(%rip), %r11
	movq	r12(%rip), %r12
	movq	r13(%rip), %r13
	movq	r14(%rip), %r14
	movq	r15(%rip), %r15

	/* Jump to the new code... */
	jmpq	*rip(%rip)
SYM_CODE_END(entry64)

	.section ".rodata"
	.balign 4
SYM_DATA_START(entry64_regs)
rax:	.quad 0x0
rcx:	.quad 0x0
rdx:	.quad 0x0
rbx:	.quad 0x0
rbp:	.quad 0x0
rsi:	.quad 0x0
rdi:	.quad 0x0
r8:	.quad 0x0
r9:	.quad 0x0
r10:	.quad 0x0
r11:	.quad 0x0
r12:	.quad 0x0
r13:	.quad 0x0
r14:	.quad 0x0
r15:	.quad 0x0
rip:	.quad 0x0
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
