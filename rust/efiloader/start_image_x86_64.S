// SPDX-License-Identifier: GPL-2.0
// Copyright 2022-2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

	.section ".text", "ax", %progbits
	.globl	exit_image
exit_image:
	mov	rax, rdi
	mov	rsp, rsi
	jmp	0f

	.globl	start_image
start_image:
	push	r15
	push	r14
	push	r13
	push	r12
	push	rbp
	push	rbx

	mov	rbp, rdx
	mov	rbx, rcx
	mov	[rbx], rsp	// store current SP in loadedimage protocol

	mov	rcx, rdi	// pass args using MS abi
	mov	rdx, rsi
	test	r8, r8		// stay on the current stack if no stack was provided
	jz	1f
	mov	rsp, r8
1:	and	rsp, -16
	sub	rsp, 0x20	// shadow space for the MS abi
	call	rbp
	mov	rsp, [rbx]	// switch back to our own stack

	xor	ecx, ecx
	mov	[rbx], rcx 	// wipe recorded SP value

0:	pop	rbx
	pop	rbp
	pop	r12
	pop	r13
	pop	r14
	pop	r15
	ret
