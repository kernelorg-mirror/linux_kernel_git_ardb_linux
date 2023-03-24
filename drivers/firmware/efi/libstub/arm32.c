// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Google LLC
 */

#include <linux/compiler.h>
#include <linux/efi.h>
#include <linux/linkage.h>

#include <asm/efi.h>

#include "efistub.h"

asmlinkage void __div0(void)
{
	for (;;);
}

void efi_cache_sync_image(unsigned long image_base,
			  unsigned long alloc_size)
{
	u32 ctr, lsize;

	asm("mrc p15, 0, %0, c0, c0, 1" : "=r"(ctr));

	lsize = 4 << ((ctr >> 16) & 0xf);

	alloc_size = ALIGN(alloc_size, lsize);

	do {
		// Dcache clean by VA
		asm("mcr p15, 0, %0, c7, c10, 1" :: "r"(image_base));
		image_base += lsize;
		alloc_size -= lsize;
	} while (alloc_size >= lsize);
}

static void __naked __noreturn jump_to_kernel(u32 arg0, u32 arg1, u32 arg2,
					      u32 entrypoint)
{
	asm("	adr	ip, 1f						\n\t"
	    "	mcr	p15, 0, ip, c7, c10, 1	@ DC clean by VA	\n\t"
	    "	mcr	p15, 0, r2, c7, c10, 1	@ clean FDT magic	\n\t"
	    "	mcr	p15, 0, ip, c7, c10, 4	@ DSB			\n\t"
	    "	mcr	p15, 0, ip, c7, c5, 4	@ ISB			\n\t"
	    "	mcr	p15, 0, ip, c7, c5, 0	@ invalidate I+BTB	\n\t"
	    "	mcr	p15, 0, ip, c7, c5, 4	@ ISB			\n\t"
	    "	mrs	ip, CPSR					\n\t"
	    "	and	ip, %[mode_mask]				\n\t"
	    "	cmp	ip, %[hyp_mode]					\n\t"
	    "	mrc	p15, 0, ip, c1, c0, 0	@ SCTLR			\n\t"
	    "	bne	0f						\n\t"
	    "	mrc	p15, 4, ip, c1, c0, 0	@ HSCTLR		\n\t"
	    "0:	bic	ip, ip, #1		@ clear M bit		\n\t"
	    "	bne	2f						\n\t"
	    "	.align	4						\n\t"
	    "1:	mcr	p15, 4, ip, c1, c0, 0	@ HSCTLR		\n\t"
	    "2:	mcrne 	p15, 0, ip, c1, c0, 0	@ SCTLR			\n\t"
	    "	mcr	p15, 0, ip, c7, c5, 4	@ ISB			\n\t"
	    "	bx	r3						\n\t"
	    :
	    :	[mode_mask]"I"(MODE_MASK), [hyp_mode]"I"(HYP_MODE)
	    :	"ip", "cc");
}

void __noreturn efi_enter_kernel(unsigned long entrypoint,
				 unsigned long fdt_addr,
				 unsigned long fdt_size)
{
	jump_to_kernel(0, -1, fdt_addr, entrypoint + TEXT_OFFSET % SZ_2M);
}
