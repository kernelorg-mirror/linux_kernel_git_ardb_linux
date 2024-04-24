/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * purgatory:  setup code
 *
 * Copyright (C) 2003,2004  Eric Biederman (ebiederm@xmission.com)
 * Copyright (C) 2014 Red Hat Inc.
 *
 * This code has been taken from kexec-tools.
 */
#include <linux/linkage.h>
#include <asm/purgatory.h>

	.text
	.balign 16
	.code64

SYM_CODE_START(purgatory_start)
	/* Setup a stack */
	leaq	lstack_end(%rip), %rsp

	/* Call the C code */
	call purgatory
	jmp	entry64
SYM_CODE_END(purgatory_start)

	.bss
	.balign 16
SYM_DATA_START_LOCAL(lstack)
	.skip 4096
SYM_DATA_END_LABEL(lstack, SYM_L_LOCAL, lstack_end)
